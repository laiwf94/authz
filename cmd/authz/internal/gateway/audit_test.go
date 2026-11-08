package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging/logtest"
)

const reloadTrace = "4bf92f3577b34da6a3ce929d0e0e4736"

// TestRunAuditLog: WICKET_AUDIT_LOG gives the gateway a hash-chained audit
// log that verifies against the platform schemas and survives a restart.
func TestRunAuditLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	e := map[string]string{"WICKET_CONFIG": writeConfig(t, dir), "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0", "WICKET_AUDIT_LOG": path}
	// Neither the logs nor the audit records may carry the cookie key.
	scan := logtest.Check(t).Known(cookieKey)
	scan.File(path)
	if s, err := loadSettings(env(e)); err != nil || s.auditLog != path {
		t.Fatalf("settings: %+v %v", s, err)
	}
	logged := &syncBuf{}
	for i := 0; i < 2; i++ { // the second run appends to the first one's chain
		ctx, cancel := context.WithCancel(context.Background())
		addrs := make(chan [2]string, 1)
		done := make(chan error, 1)
		logs := scan.Writer(io.MultiWriter(logged, &syncBuf{}))
		go func() { done <- run(ctx, env(e), logs, nil, func(p, a string) { addrs <- [2]string{p, a} }) }()
		var a [2]string
		select {
		case a = <-addrs:
		case err := <-done:
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", "http://"+a[1]+"/admin/reload", nil)
		req.Header.Set("X-Request-Id", "reload-1")
		req.Header.Set("Traceparent", "00-"+reloadTrace+"-00f067aa0ba902b7-01")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("reload: %v %v", resp, err)
		}
		resp.Body.Close()
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.VerifyWith(bytes.NewReader(raw), audit.Default())
	if err != nil {
		t.Fatal(err)
	}
	// Each run: the load at start and the reload, under the reload's trace
	// ID, which its request line carries too.
	if res.Records != 4 || strings.Count(string(raw), `"event":"authn.config_loaded"`) != 4 ||
		strings.Count(string(raw), `"correlation_id":"`+reloadTrace+`"`) != 2 {
		t.Fatalf("%d records:\n%s", res.Records, raw)
	}
	if n := strings.Count(logged.String(), `"msg":"request","correlation_id":"`+reloadTrace+`","request_id":"reload-1"`); n != 2 {
		t.Fatalf("%d reload request lines with the trace ID:\n%s", n, logged.String())
	}
}

func TestRunAuditLogFailure(t *testing.T) {
	dir := t.TempDir()
	e := map[string]string{"WICKET_CONFIG": writeConfig(t, dir), "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0",
		"WICKET_AUDIT_LOG": filepath.Join(dir, "no", "such", "dir", "audit.log")}
	err := run(context.Background(), env(e), &syncBuf{}, nil, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "WICKET_AUDIT_LOG: ") {
		t.Fatalf("missing directory: %v", err)
	}
	// A log whose chain is broken is refused rather than extended.
	bad := filepath.Join(dir, "bad.log")
	os.WriteFile(bad, []byte("{\"seq\":1}\n"), 0o600)
	e["WICKET_AUDIT_LOG"] = bad
	if err := run(context.Background(), env(e), &syncBuf{}, nil, nil); err == nil || !strings.Contains(err.Error(), "WICKET_AUDIT_LOG") {
		t.Fatalf("broken log: %v", err)
	}
}
