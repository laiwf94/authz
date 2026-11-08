package serve

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging/logtest"
)

// TestRunAuditLog: GRANTD_AUDIT_LOG gives authz serve a hash-chained audit
// log of schema changes and relationship writes.
func TestRunAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	const apiKey = "integration-key-0123"
	// Neither the log nor the audit records may carry the key.
	scan := logtest.Check(t).Known(apiKey)
	scan.File(path)
	e := map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": apiKey, "GRANTD_AUDIT_LOG": path}
	if c, err := loadConfig(env(e)); err != nil || c.auditLog != path {
		t.Fatalf("config: %+v %v", c, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs := make(chan string, 1)
	done := make(chan error, 1)
	logs := scan.Writer(&bytes.Buffer{})
	go func() { done <- run(ctx, env(e), logs, func(a string) { addrs <- a }) }()
	var addr string
	select {
	case addr = <-addrs:
	case err := <-done:
		t.Fatal(err)
	}
	post := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("X-Request-Id", "corr-"+method)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s %s: %v %v", method, path, resp, err)
		}
		resp.Body.Close()
	}
	post("PUT", "/v1/schema", `{"schema":"definition user {}\ndefinition doc { relation viewer: user }"}`)
	post("POST", "/v1/relationships/write", `{"updates":[{"op":"touch","relationship":"doc:a#viewer@user:alice"}]}`)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.VerifyWith(bytes.NewReader(raw), audit.Default())
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if res.Records != 2 || !strings.Contains(s, `"event":"authz.schema_written","actor":"`+api.KeyID(apiKey)+`","action":"schema.write","correlation_id":"corr-PUT"`) ||
		!strings.Contains(s, `"event":"authz.relationships_written"`) || !strings.Contains(s, `"correlation_id":"corr-POST"`) ||
		strings.Contains(s, apiKey) {
		t.Fatalf("audit log:\n%s", s)
	}
}

func TestRunAuditLogFailure(t *testing.T) {
	e := map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
		"GRANTD_AUDIT_LOG": filepath.Join(t.TempDir(), "no", "such", "audit.log")}
	if err := run(context.Background(), env(e), &bytes.Buffer{}, nil); err == nil || !strings.HasPrefix(err.Error(), "GRANTD_AUDIT_LOG: ") {
		t.Fatalf("missing directory: %v", err)
	}
}
