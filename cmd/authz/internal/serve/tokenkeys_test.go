package serve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	keyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestTokenKeyList(t *testing.T) {
	c, err := loadConfig(env(map[string]string{"GRANTD_API_KEYS": "k", "GRANTD_TOKEN_KEY": keyB + ", " + keyA}))
	if err != nil {
		t.Fatal(err)
	}
	if c.tokenKey[0] != 0xbb || len(c.oldTokens) != 1 || c.oldTokens[0][0] != 0xaa {
		t.Fatalf("token keys: %x %x", c.tokenKey, c.oldTokens)
	}
	for v, want := range map[string]string{
		keyA + ",abc":                  "entry 2 is not",
		keyA + ",":                     "entry 2 is not",
		"abc," + keyA:                  "entry 1 is not",
		keyA + "," + keyA:              "entry 2 repeats an earlier key",
		keyB + "," + keyA + "," + keyB: "entry 3 repeats an earlier key",
	} {
		if _, err := loadConfig(env(map[string]string{"GRANTD_API_KEYS": "k", "GRANTD_TOKEN_KEY": v})); err == nil ||
			!strings.Contains(err.Error(), want) || !strings.HasPrefix(err.Error(), "GRANTD_TOKEN_KEY") {
			t.Errorf("%q: %v, want %q", v, err, want)
		}
	}
}

// Rotating GRANTD_TOKEN_KEY across restarts: a token issued under key A
// still reads after the restart that makes B current, and is refused once
// A leaves the list.
func TestTokenKeyRotationAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	serve := func(tokenKeys string, f func(do func(method, path, body string) (int, map[string]any))) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		addrc := make(chan string, 1)
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, env(map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
				"GRANTD_DATA_DIR": dir, "GRANTD_TOKEN_KEY": tokenKeys}), io.Discard, func(a string) { addrc <- a })
		}()
		var addr string
		select {
		case addr = <-addrc:
		case err := <-done:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("server did not start")
		}
		f(func(method, path, body string) (int, map[string]any) {
			req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer integration-key-0123")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var out map[string]any
			json.NewDecoder(resp.Body).Decode(&out)
			return resp.StatusCode, out
		})
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	readAt := func(tok string) string {
		return `{"filter":{"resource_type":"doc"},"consistency":{"mode":"at_least_as_fresh","token":"` + tok + `"}}`
	}

	var tokA string
	serve(keyA, func(do func(string, string, string) (int, map[string]any)) {
		code, out := do("PUT", "/v1/schema", `{"schema":"definition user {}\ndefinition doc { relation viewer: user }"}`)
		if code != 200 {
			t.Fatalf("schema write: %d %v", code, out)
		}
		tokA, _ = out["written_at"].(string)
	})
	var tokB string
	serve(keyB+","+keyA, func(do func(string, string, string) (int, map[string]any)) {
		code, out := do("POST", "/v1/relationships/read", readAt(tokA))
		if code != 200 {
			t.Fatalf("token from the previous key after rotation: %d %v", code, out)
		}
		tokB, _ = out["read_at"].(string)
		if tokB == tokA {
			t.Fatal("new tokens are still signed with the old key")
		}
	})
	serve(keyB, func(do func(string, string, string) (int, map[string]any)) {
		if code, out := do("POST", "/v1/relationships/read", readAt(tokB)); code != 200 {
			t.Fatalf("token from the current key: %d %v", code, out)
		}
		if code, out := do("POST", "/v1/relationships/read", readAt(tokA)); code != 400 {
			t.Fatalf("token from a removed key: %d %v", code, out)
		}
	})
}
