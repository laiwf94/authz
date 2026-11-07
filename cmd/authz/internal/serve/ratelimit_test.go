package serve

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

func TestKeyLimitConfig(t *testing.T) {
	base := func(kv ...string) map[string]string {
		e := map[string]string{"GRANTD_API_KEYS": "integration-key-0123"}
		for i := 0; i < len(kv); i += 2 {
			e[kv[i]] = kv[i+1]
		}
		return e
	}
	for _, c := range []struct {
		env  map[string]string
		want ratelimit.Limit
	}{
		{base(), ratelimit.Limit{}},
		{base("GRANTD_KEY_RATE", "0"), ratelimit.Limit{}},
		{base("GRANTD_KEY_RATE", "2.5"), ratelimit.Limit{Rate: 2.5, Burst: 3}},
		{base("GRANTD_KEY_RATE", "0.1"), ratelimit.Limit{Rate: 0.1, Burst: 1}},
		{base("GRANTD_KEY_RATE", "100", "GRANTD_KEY_BURST", "500"), ratelimit.Limit{Rate: 100, Burst: 500}},
	} {
		cfg, err := loadConfig(env(c.env))
		if err != nil || cfg.keyLimit != c.want {
			t.Errorf("%v: %+v %v, want %+v", c.env, cfg.keyLimit, err, c.want)
		}
	}
	for want, e := range map[string]map[string]string{
		"GRANTD_KEY_RATE must be":     base("GRANTD_KEY_RATE", "fast"),
		"GRANTD_KEY_RATE must be a":   base("GRANTD_KEY_RATE", "-1"),
		"GRANTD_KEY_RATE must be a n": base("GRANTD_KEY_RATE", "Inf"),
		"GRANTD_KEY_RATE must":        base("GRANTD_KEY_RATE", "NaN"),
		"GRANTD_KEY_BURST must be":    base("GRANTD_KEY_RATE", "1", "GRANTD_KEY_BURST", "0"),
		"GRANTD_KEY_BURST must":       base("GRANTD_KEY_RATE", "1", "GRANTD_KEY_BURST", "x"),
		"GRANTD_KEY_BURST needs":      base("GRANTD_KEY_BURST", "5"),
	} {
		if _, err := loadConfig(env(e)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: err = %v, want %q", e, err, want)
		}
		if errs := Check(env(e)); len(errs) != 1 || !strings.Contains(errs[0].Error(), want) {
			t.Errorf("Check %v: %v", e, errs)
		}
	}
}

// TestRunKeyRateLimit: with GRANTD_KEY_RATE set, authz serve answers 429
// once a key has used its burst.
func TestRunKeyRateLimit(t *testing.T) {
	const apiKey = "integration-key-0123"
	e := map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": apiKey,
		"GRANTD_KEY_RATE": "0.001", "GRANTD_KEY_BURST": "3"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, env(e), &bytes.Buffer{}, func(a string) { addrs <- a }) }()
	var addr string
	select {
	case addr = <-addrs:
	case err := <-done:
		t.Fatal(err)
	}
	var codes []int
	for range 5 {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/schema", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	for i, c := range codes {
		if limited := c == http.StatusTooManyRequests; limited != (i >= 3) {
			t.Fatalf("status codes %v: want the 4th and 5th refused", codes)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
