package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *stepClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newLimitedServer(t *testing.T, lim ratelimit.Limit, clk *stepClock) (*httptest.Server, *metrics.Registry) {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	m := metrics.New()
	var now func() time.Time
	if clk != nil {
		now = clk.Now
	}
	s, err := New(Config{Store: st, Tokens: tok, APIKeys: []string{apiKey, secondKey}, Metrics: m,
		KeyLimit: lim, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return srv, m
}

func getWith(t *testing.T, url, key string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// GRANTD's per-key limit: each API key has its own bucket, a refused
// request gets 429 with Retry-After and the stable error code, and requests
// that never authenticate, or need no key, are not counted.
func TestKeyRateLimit(t *testing.T) {
	clk := &stepClock{t: time.Unix(1000, 0)}
	srv, m := newLimitedServer(t, ratelimit.Limit{Rate: 0.5, Burst: 2}, clk)
	for range 5 {
		if r := getWith(t, srv.URL+"/v1/schema", "wrong-key-0123456789"); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad key: %d", r.StatusCode)
		}
		if r := getWith(t, srv.URL+"/healthz", ""); r.StatusCode != http.StatusOK {
			t.Fatalf("healthz: %d", r.StatusCode)
		}
	}
	for i := range 2 {
		if r := getWith(t, srv.URL+"/v1/schema", apiKey); r.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d within the burst refused", i)
		}
	}
	r := getWith(t, srv.URL+"/v1/schema", apiKey)
	if r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d", r.StatusCode)
	}
	if got := r.Header.Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After %q, want 2", got)
	}
	if r.Header.Get("X-Request-Id") == "" {
		t.Fatal("refused request has no request ID")
	}
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Error.Code != "resource_exhausted" {
		t.Fatalf("body: %+v %v", body, err)
	}
	if r := getWith(t, srv.URL+"/v1/schema", secondKey); r.StatusCode == http.StatusTooManyRequests {
		t.Fatal("keys share a bucket")
	}
	if got := m.Counter("grantd_rate_limited_total", "", "").Value(); got != 1 {
		t.Fatalf("grantd_rate_limited_total = %d", got)
	}
	clk.Add(1500 * time.Millisecond)
	if r := getWith(t, srv.URL+"/v1/schema", apiKey); r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "1" {
		t.Fatalf("half a second short: %d %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
	clk.Add(500 * time.Millisecond)
	if r := getWith(t, srv.URL+"/v1/schema", apiKey); r.StatusCode == http.StatusTooManyRequests {
		t.Fatal("refilled token refused")
	}
	if got := m.Counter("grantd_http_requests_total", `route="/v1/schema",code="429"`, "").Value(); got != 2 {
		t.Fatalf("429s counted %d", got)
	}
}

func TestKeyRateLimitOffByDefault(t *testing.T) {
	srv, m := newLimitedServer(t, ratelimit.Limit{}, nil)
	for range 200 {
		if r := getWith(t, srv.URL+"/v1/schema", apiKey); r.StatusCode == http.StatusTooManyRequests {
			t.Fatal("limited without a KeyLimit")
		}
	}
	if got := m.Counter("grantd_rate_limited_total", "", "").Value(); got != 0 {
		t.Fatalf("grantd_rate_limited_total = %d", got)
	}
}
