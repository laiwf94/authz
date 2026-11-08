package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/httpserver/httpservertest"
)

// TestRunTLSAndDrain: with GRANTD_TLS_* the API serves HTTPS; on shutdown
// /readyz turns 503 for GRANTD_DRAIN_DELAY while requests are still served,
// and a watch poll in flight is answered before run returns.
func TestRunTLSAndDrain(t *testing.T) {
	tf := httpservertest.Write(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrc := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- run(ctx, env(map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
			"GRANTD_TLS_CERT": tf.CertFile, "GRANTD_TLS_KEY": tf.KeyFile, "GRANTD_DRAIN_DELAY": "500ms",
			"GRANTD_DRAIN_TIMEOUT": "10s"}), &logs, func(a string) { addrc <- a })
	}()
	var base string
	select {
	case a := <-addrc:
		base = "https://" + a
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer integration-key-0123")
		req.Header.Set("Content-Type", "application/json")
		resp, err := tf.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, ready := do("GET", "/readyz", "")
	if code != 200 {
		t.Fatalf("readyz over TLS: %d %s", code, ready)
	}
	if resp, err := http.Get(strings.Replace(base, "https", "http", 1) + "/readyz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plain HTTP answered on a TLS listener")
		}
	}
	_, w := do("POST", "/v1/watch", `{}`)
	var head struct{ Next string }
	if err := json.Unmarshal([]byte(w), &head); err != nil || head.Next == "" {
		t.Fatalf("watch head: %s", w)
	}

	polled := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("POST", base+"/v1/watch", strings.NewReader(`{"after":"`+head.Next+`","wait_seconds":2}`))
		req.Header.Set("Authorization", "Bearer integration-key-0123")
		req.Header.Set("Content-Type", "application/json")
		resp, err := tf.Client.Do(req)
		if err != nil {
			polled <- -1
			return
		}
		resp.Body.Close()
		polled <- resp.StatusCode
	}()
	time.Sleep(200 * time.Millisecond) // the poll is waiting
	start := time.Now()
	cancel()
	// During the delay: not ready, still serving.
	deadline := time.Now().Add(400 * time.Millisecond)
	sawDraining := false
	for time.Now().Before(deadline) && !sawDraining {
		code, body := do("GET", "/readyz", "")
		sawDraining = code == 503 && strings.Contains(body, "draining")
		if !sawDraining && code != 200 {
			t.Fatalf("readyz while stopping: %d %s", code, body)
		}
	}
	if !sawDraining {
		t.Fatal("readyz did not turn 503 after shutdown began")
	}
	// No schema is written: 424 is the API's answer, not the drain's.
	if code, _ := do("GET", "/v1/schema", ""); code != http.StatusFailedDependency {
		t.Errorf("request during the drain delay: %d", code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
	if code := <-polled; code != 200 {
		t.Errorf("watch poll in flight at shutdown: %d", code)
	}
	if d := time.Since(start); d < 1500*time.Millisecond {
		t.Errorf("run returned after %s, before the poll in flight finished", d)
	}
	if !strings.Contains(logs.String(), `"msg":"shutting down"`) {
		t.Errorf("logs: %s", logs.String())
	}
}

func TestDrainAndTLSConfig(t *testing.T) {
	base := map[string]string{"GRANTD_API_KEYS": "integration-key-0123"}
	with := func(kv ...string) func(string) string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return env(m)
	}
	if _, err := loadConfig(with("GRANTD_TLS_CERT", "c")); err == nil || !strings.Contains(err.Error(), "GRANTD_TLS_KEY") {
		t.Errorf("cert alone: %v", err)
	}
	if _, err := loadConfig(with("GRANTD_DRAIN_TIMEOUT", "forever")); err == nil || !strings.Contains(err.Error(), "GRANTD_DRAIN_TIMEOUT") {
		t.Errorf("bad drain timeout: %v", err)
	}
	errs := Check(with("GRANTD_TLS_CERT", "/does/not/exist", "GRANTD_TLS_KEY", "/does/not/exist"))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "GRANTD_TLS_CERT") {
		t.Errorf("Check with missing TLS files: %v", errs)
	}
	tf := httpservertest.Write(t)
	if errs := Check(with("GRANTD_TLS_CERT", tf.CertFile, "GRANTD_TLS_KEY", tf.KeyFile)); len(errs) != 0 {
		t.Errorf("Check with good TLS files: %v", errs)
	}
}
