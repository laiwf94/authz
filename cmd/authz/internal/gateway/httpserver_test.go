package gateway

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/httpserver/httpservertest"
)

// TestRunTLSAndDrain: WICKET_TLS_* serve both listeners over TLS, the admin
// listener answers /readyz, and on shutdown it turns 503 for
// WICKET_DRAIN_DELAY while both listeners still answer.
func TestRunTLSAndDrain(t *testing.T) {
	dir := t.TempDir()
	tf := httpservertest.Write(t)
	var keyOut bytes.Buffer
	subcommand("gensigningkey", &keyOut)
	os.WriteFile(filepath.Join(dir, "sign.pem"), keyOut.Bytes(), 0o600)
	e := map[string]string{"WICKET_CONFIG": writeConfig(t, dir), "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0", "WICKET_SIGNING_KEYS": filepath.Join(dir, "sign.pem"),
		"WICKET_TLS_CERT": tf.CertFile, "WICKET_TLS_KEY": tf.KeyFile, "WICKET_DRAIN_DELAY": "1s"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs := make(chan [2]string, 1)
	logs := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, env(e), logs, nil, func(p, a string) { addrs <- [2]string{p, a} }) }()
	var a [2]string
	select {
	case a = <-addrs:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not start")
	}
	get := func(u string) (int, string) {
		t.Helper()
		resp, err := tf.Client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, _ := get("https://" + a[0] + "/healthz"); code != 200 {
		t.Fatalf("public health over TLS: %d", code)
	}
	if code, body := get("https://" + a[1] + "/readyz"); code != 200 || body != `{"status":"ready"}`+"\n" {
		t.Fatalf("admin readyz: %d %q", code, body)
	}
	start := time.Now()
	cancel()
	draining := false
	for !draining && time.Since(start) < 800*time.Millisecond {
		code, _ := get("https://" + a[1] + "/readyz")
		draining = code == 503
	}
	if !draining {
		t.Fatal("admin readyz did not turn 503")
	}
	if code, _ := get("https://" + a[0] + "/healthz"); code != 200 {
		t.Errorf("public listener during the drain delay: %d", code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not stop")
	}
	if d := time.Since(start); d < time.Second {
		t.Errorf("stopped after %s, inside the 1s drain delay", d)
	}
	if !strings.Contains(logs.String(), `"msg":"shutting down"`) {
		t.Errorf("logs: %s", logs.String())
	}
}

func TestLoadSettingsHTTP(t *testing.T) {
	e := map[string]string{"WICKET_CONFIG": "c", "WICKET_COOKIE_KEYS": cookieKey}
	s, err := loadSettings(env(e))
	if err != nil || s.http.TLS != nil || s.http.DrainTimeout != 20*time.Second {
		t.Fatalf("defaults: %+v %v", s.http, err)
	}
	e["WICKET_TLS_CLIENT_CA"] = "ca.pem"
	if _, err := loadSettings(env(e)); err == nil || !strings.Contains(err.Error(), "WICKET_TLS_CLIENT_CA needs") {
		t.Fatalf("client CA alone: %v", err)
	}
}
