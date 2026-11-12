package gateway

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
)

func TestAdminAuditCheckpoint(t *testing.T) {
	e := newEnv(t)
	// The test log has no signing key.
	if r := e.admin("GET", "/admin/audit/checkpoint", ""); r.status != 404 || !strings.Contains(r.raw, "AUTHZ_AUDIT_SIGNING_KEY") {
		t.Fatalf("without a key: %d %s", r.status, r.raw)
	}

	skey, vkey, err := audit.GenerateKey(rand.Reader, "audit.test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.ParseSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := audit.ParseVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.dir, "signed.jsonl")
	al, err := audit.OpenWith(path, audit.Options{Now: e.clk.now, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	o := e.gw.opt
	o.Audit = al
	gw, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	gwTS := httptest.NewServer(gw.Handler())
	t.Cleanup(gwTS.Close)
	adminTS := httptest.NewServer(gw.AdminHandler(adminToken))
	t.Cleanup(adminTS.Close)
	e.gwURL, e.adminURL = gwTS.URL+"/mcp", adminTS.URL

	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.status != 200 {
		t.Fatalf("call: %d %s", r.status, r.raw)
	}
	r := e.admin("GET", "/admin/audit/checkpoint", "")
	if r.status != 200 || r.header.Get("Content-Type") != "text/plain; charset=utf-8" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("checkpoint: %d %v %s", r.status, r.header, r.raw)
	}
	c, err := audit.OpenCheckpoint([]byte(r.raw), verifier)
	if err != nil {
		t.Fatalf("served checkpoint does not open: %v\n%s", err, r.raw)
	}
	n, head := al.Head()
	if c.Size != n || c.Head != head || n < 2 {
		t.Fatalf("checkpoint %+v, log head %d %s", c, n, head)
	}
	cr, err := audit.VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.Covers(c); err != nil {
		t.Fatal(err)
	}

	// The admin token is needed, as for every other route.
	req, _ := http.NewRequest("GET", e.adminURL+"/admin/audit/checkpoint", nil)
	if r := e.do(req); r.status != 401 {
		t.Fatalf("without the admin token: %d", r.status)
	}
	// A broken log answers 500 without a checkpoint.
	al.Close()
	if r := e.admin("GET", "/admin/audit/checkpoint", ""); r.status != 500 {
		t.Fatalf("closed log: %d %s", r.status, r.raw)
	}
}
