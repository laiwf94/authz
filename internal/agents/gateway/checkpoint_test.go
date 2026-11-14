package gateway

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

func TestAdminAuditCheckpoint(t *testing.T) {
	e := newEnv(t)
	// The test log has no signing key.
	if r := e.admin("GET", "/admin/audit/checkpoint", ""); r.status != 404 || !strings.Contains(r.raw, "AUTHZ_AUDIT_SIGNING_KEY") {
		t.Fatalf("without a key: %d %s", r.status, r.raw)
	}

	al, path, verifier := e.signedLog()

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

// signedLog points the test gateway at a new audit log signing checkpoints
// with a fresh key, returning it, its path and the public key.
func (e *env) signedLog() (*audit.Log, string, *audit.Verifier) {
	t := e.t
	t.Helper()
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

	return al, path, verifier
}

func TestAdminAuditProof(t *testing.T) {
	e := newEnv(t)
	if r := e.admin("GET", "/admin/audit/proof?record=1", ""); r.status != 404 || !strings.Contains(r.raw, "AUTHZ_AUDIT_SIGNING_KEY") {
		t.Fatalf("without a key: %d %s", r.status, r.raw)
	}
	al, _, verifier := e.signedLog()
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.status != 200 {
		t.Fatalf("call: %d %s", r.status, r.raw)
	}
	r := e.admin("GET", "/admin/audit/checkpoint", "")
	old, err := audit.OpenCheckpoint([]byte(r.raw), verifier)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		e.clk.add(2 * time.Second) // past the tool's rate limit
		if r := e.call(aliceKey, "fake.echo", map[string]any{"text": strings.Repeat("x", i)}); r.status != 200 {
			t.Fatalf("call: %d %s", r.status, r.raw)
		}
	}
	n, _ := al.Head()
	proof := func(query string) audit.Proof {
		t.Helper()
		r := e.admin("GET", "/admin/audit/proof?"+query, "")
		if r.status != 200 || r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", query, r.status, r.raw)
		}
		var p audit.Proof
		if err := json.Unmarshal([]byte(r.raw), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for rec := uint64(1); rec <= n; rec++ {
		p := proof(fmt.Sprintf("record=%d", rec))
		cp, err := audit.OpenCheckpoint([]byte(p.Checkpoint), verifier)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Check(cp, nil); err != nil {
			t.Fatalf("record %d: %v", rec, err)
		}
		if cp.Size != n {
			t.Fatalf("record %d proved against %d records, not %d", rec, cp.Size, n)
		}
	}
	// A tool call's record, by its event.
	var sawCall bool
	for rec := uint64(1); rec <= n; rec++ {
		var rd audit.Record
		if err := json.Unmarshal([]byte(proof(fmt.Sprintf("record=%d", rec)).Entry), &rd); err != nil {
			t.Fatal(err)
		}
		sawCall = sawCall || rd.Event == "tool_call"
	}
	if !sawCall {
		t.Error("no tool_call record was proved")
	}
	p := proof(fmt.Sprintf("from=%d", old.Size))
	cp, err := audit.OpenCheckpoint([]byte(p.Checkpoint), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(cp, &old); err != nil {
		t.Fatal(err)
	}
	// Against the auditor's earlier checkpoint.
	p = proof(fmt.Sprintf("record=1&size=%d", old.Size))
	if p.Checkpoint != "" {
		t.Error("a proof for an earlier size carries the newest checkpoint")
	}
	if err := p.Check(old, nil); err != nil {
		t.Fatal(err)
	}

	for query, status := range map[string]int{
		"":                                   400,
		"record=1&from=1":                    400,
		"record=0":                           400,
		"record=01":                          400,
		"record=x":                           400,
		"record=1&record=2":                  400,
		"record=1&other=2":                   400,
		"size=3":                             400,
		fmt.Sprintf("record=%d", n+5):        404,
		fmt.Sprintf("record=1&size=%d", n+5): 404,
		fmt.Sprintf("from=%d", n+5):          404,
	} {
		if r := e.admin("GET", "/admin/audit/proof?"+query, ""); r.status != status {
			t.Errorf("%q: %d %s, want %d", query, r.status, r.raw, status)
		}
	}
	req, _ := http.NewRequest("GET", e.adminURL+"/admin/audit/proof?record=1", nil)
	if r := e.do(req); r.status != 401 {
		t.Fatalf("without the admin token: %d", r.status)
	}
}

// POST /admin/audit/export serves the checkpoint and records it as
// exported beside the log, for audit retention.
func TestAdminAuditExport(t *testing.T) {
	e := newEnv(t)
	if r := e.admin("POST", "/admin/audit/export", ""); r.status != 404 || !strings.Contains(r.raw, "AUTHZ_AUDIT_SIGNING_KEY") {
		t.Fatalf("without a key: %d %s", r.status, r.raw)
	}
	if r := e.admin("GET", "/admin/audit/export", ""); r.status == 200 {
		t.Fatal("GET exported a checkpoint; only POST may")
	}
	al, path, verifier := e.signedLog()
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.status != 200 {
		t.Fatalf("call: %d %s", r.status, r.raw)
	}
	r := e.admin("POST", "/admin/audit/export", "")
	if r.status != 200 || r.header.Get("Content-Type") != "text/plain; charset=utf-8" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("export: %d %v %s", r.status, r.header, r.raw)
	}
	c, err := audit.OpenCheckpoint([]byte(r.raw), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := al.Head(); c.Size != n {
		t.Fatalf("exported %d records of %d", c.Size, n)
	}
	saved, err := os.ReadFile(audit.ExportedPath(path))
	if err != nil || string(saved) != r.raw {
		t.Fatalf("the exported checkpoint was not recorded: %v\n%s", err, saved)
	}
	req, _ := http.NewRequest("POST", e.adminURL+"/admin/audit/export", nil)
	if r := e.do(req); r.status != 401 {
		t.Fatalf("without the admin token: %d", r.status)
	}
	al.Close()
	if r := e.admin("POST", "/admin/audit/export", ""); r.status != 500 {
		t.Fatalf("closed log: %d %s", r.status, r.raw)
	}
}
