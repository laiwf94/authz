package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

const thirdKey = "third-key-0123456789"

func TestSetAPIKeys(t *testing.T) {
	clk := &stepClock{t: time.Unix(1000, 0)}
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	s, err := New(Config{Store: st, Tokens: tok, APIKeys: []string{apiKey, secondKey},
		KeyLimit: ratelimit.Limit{Rate: 0.5, Burst: 2}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	status := func(key string) int { return getWith(t, srv.URL+"/v1/schema", key).StatusCode }

	// Spend apiKey's burst before the change.
	for range 2 {
		if c := status(apiKey); c == http.StatusUnauthorized || c == http.StatusTooManyRequests {
			t.Fatalf("apiKey before the change: %d", c)
		}
	}
	if c := status(thirdKey); c != http.StatusUnauthorized {
		t.Fatalf("thirdKey before it was added: %d", c)
	}

	// Refused lists leave the keys in place.
	if err := s.SetAPIKeys(nil); err == nil {
		t.Fatal("an empty key list was accepted")
	}
	if err := s.SetAPIKeys([]string{thirdKey, "short"}); err == nil {
		t.Fatal("a short key was accepted")
	}
	if c := status(secondKey); c == http.StatusUnauthorized {
		t.Fatal("a refused SetAPIKeys removed secondKey")
	}
	if c := status(thirdKey); c != http.StatusUnauthorized {
		t.Fatal("a refused SetAPIKeys added thirdKey")
	}

	if err := s.SetAPIKeys([]string{thirdKey, apiKey}); err != nil {
		t.Fatal(err)
	}
	if c := status(secondKey); c != http.StatusUnauthorized {
		t.Fatalf("removed key: %d", c)
	}
	if c := status(thirdKey); c == http.StatusUnauthorized || c == http.StatusTooManyRequests {
		t.Fatalf("added key: %d", c)
	}
	// A key kept across the change keeps its bucket: apiKey is still
	// over its limit.
	if c := status(apiKey); c != http.StatusTooManyRequests {
		t.Fatalf("kept key lost its bucket: %d", c)
	}
}

// Keys replaced while requests run: a request carrying a key that is in
// both the old and the new list never fails, and a key that was removed
// stops working.
func TestSetAPIKeysUnderLoad(t *testing.T) {
	srv, _ := newLimitedServer(t, ratelimit.Limit{}, nil)
	s := srv.Config.Handler.(*Server)

	var stop atomic.Bool
	var failures, requests atomic.Int64
	var wg sync.WaitGroup
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 8}}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/schema", nil)
				req.Header.Set("Authorization", "Bearer "+apiKey)
				resp, err := client.Do(req)
				requests.Add(1)
				if err != nil || resp.StatusCode == http.StatusUnauthorized {
					failures.Add(1)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	for i := range 200 {
		keys := []string{apiKey, secondKey}
		if i%2 == 1 {
			keys = []string{thirdKey, apiKey}
		}
		if err := s.SetAPIKeys(keys); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if failures.Load() != 0 || requests.Load() == 0 {
		t.Fatalf("%d of %d requests failed", failures.Load(), requests.Load())
	}
	if c := getWith(t, srv.URL+"/v1/schema", secondKey).StatusCode; c != http.StatusUnauthorized {
		t.Fatalf("secondKey after it was removed: %d", c)
	}
}
