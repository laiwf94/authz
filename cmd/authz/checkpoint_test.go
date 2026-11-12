//go:build unix

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// TestMainAuditCheckpoints runs authz serve, authz gateway and authz mcp as
// three processes writing and rotating one audit file, all signing
// checkpoints with one key from authz audit keygen (AUTHZ_AUDIT_SIGNING_KEY_FILE)
// every second. An auditor saves the checkpoint GET /admin/audit/checkpoint
// serves; later, holding only the public key, authz audit verify -key
// checks that the grown log still holds what it signed, and catches the
// newest records cut off, which the chain alone cannot. A malformed key
// stops every subcommand, and authz check reports it.
func TestMainAuditCheckpoints(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "audit.jsonl")
	const (
		apiKey     = "checkpoint-api-key-0123456789"
		agentKey   = "tgk_checkpoint_0123456789abcdefghijklm"
		adminToken = "admin-checkpoint-0123456789abcdefghijk"
		auditKey   = "abababababababababababababababababababababababababababababababab"
	)
	keyFile := filepath.Join(dir, "audit.key")
	code, vkey, errs := runToEnd(t, "audit keygen -out "+keyFile+" audit.test")
	if vkey = strings.TrimSpace(vkey); code != 0 || !strings.HasPrefix(vkey, "audit.test+") {
		t.Fatalf("keygen: exit %d %q %s", code, vkey, errs)
	}
	signing := []string{"AUTHZ_AUDIT_SIGNING_KEY_FILE=" + keyFile, "AUTHZ_AUDIT_CHECKPOINT_INTERVAL=1s", "AUTHZ_AUDIT_SIGNING_KEY="}

	box := filepath.Join(dir, "box")
	os.MkdirAll(box, 0o700)
	os.WriteFile(filepath.Join(box, "readme.txt"), []byte("the readme"), 0o600)
	fs, err := fakeserver.New(fakeserver.Config{Sandbox: box})
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(fs)
	defer up.Close()

	serveEnv := append([]string{"GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS=" + apiKey, "GRANTD_DATA_DIR=", "GRANTD_TOKEN_KEY=",
		"GRANTD_AUDIT_LOG=" + chain, "GRANTD_AUDIT_CHECKS=true", "GRANTD_AUDIT_ROTATE_BYTES=8192", "GRANTD_AUDIT_ROTATE_AGE="}, signing...)
	serveCmd, serveCh := startChild(t, "authz", "serve", false, serveEnv...)
	serveLogs := collect(serveCh)
	gwEnv := append([]string{"WICKET_CONFIG=" + writeGatewayConfig(t, dir), "WICKET_COOKIE_KEYS=" + gatewayCookieKey,
		"WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0", "WICKET_SESSION_FILE=", "WICKET_SIGNING_KEYS=",
		"WICKET_ADMIN_TOKEN=", "CORP_SECRET=s", "WICKET_AUDIT_LOG=" + chain, "WICKET_AUDIT_ROTATE_BYTES=8192", "WICKET_AUDIT_ROTATE_AGE="}, signing...)
	gwCmd, gwCh := startChild(t, "authz", "gateway", false, gwEnv...)
	gwLogs := collect(gwCh)

	mcpCfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"checkpoint"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
	  "upstreams":[{"name":"files","url":"%s/mcp"}]}`, sha256Hex(agentKey), up.URL)
	pol := `{"version":1,"rules":[{"id":"files-read","effect":"allow","scopes":["files:read"],"upstreams":["files"],"tools":["read_file"]}]}`
	os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(mcpCfg), 0o600)
	os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o600)
	platform, _ := json.Marshal(map[string]any{"version": 1, "mcp": map[string]any{
		"addr": "127.0.0.1:0", "admin_addr": "127.0.0.1:0", "admin_token": map[string]string{"env": "CP_ADMIN"},
		"config": filepath.Join(dir, "mcp.json"), "policy": filepath.Join(dir, "policy.json"),
		"audit_log": chain, "audit_key": map[string]string{"env": "CP_AUDIT_KEY"}, "policy_poll": "0",
		"audit_rotate_bytes": 8192,
	}})
	platformFile := filepath.Join(dir, "authz.json")
	os.WriteFile(platformFile, platform, 0o600)
	mcpEnv := append([]string{"CP_ADMIN=" + adminToken, "CP_AUDIT_KEY=" + auditKey, "AUTHZ_CONFIG="}, signing...)
	mcpCmd, mcpCh := startChild(t, "authz", "mcp serve -config "+platformFile, false, mcpEnv...)
	mcpLogs := collect(mcpCh)

	serveAddr, gwAddr, mcpAddr := waitAddr(t, serveLogs), waitAddr(t, gwLogs), waitAddr(t, mcpLogs)
	mcpAdmin := waitAdminAddr(t, mcpLogs)

	do := func(req *http.Request, want int) string {
		t.Helper()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d, want %d: %s", req.Method, req.URL, resp.StatusCode, want, body)
		}
		return string(body)
	}
	api := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://"+serveAddr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		do(req, 200)
	}
	api("PUT", "/v1/schema", `{"schema":"definition user {}\ndefinition doc { relation viewer: user\n permission view = viewer }"}`)
	api("POST", "/v1/relationships/write", `{"updates":[{"op":"touch","relationship":"doc:readme#viewer@user:alice"}]}`)
	round := func(i int) {
		t.Helper()
		api("POST", "/v1/check", fmt.Sprintf(`{"resource":"doc:readme","permission":"view","subject":"user:u%d"}`, i))
		req, _ := http.NewRequest("GET", "http://"+gwAddr+"/auth", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", fmt.Sprintf("unknown-%d.example.com", i))
		req.Header.Set("X-Forwarded-Uri", "/")
		do(req, http.StatusForbidden)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files.read_file","arguments":{"path":"readme.txt"},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
		req, _ = http.NewRequest("POST", "http://"+mcpAddr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
			"Mcp-Name": "files.read_file"} {
			req.Header.Set(k, v)
		}
		do(req, 200)
	}
	verifier, err := audit.ParseVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := func() (string, audit.Checkpoint) {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+mcpAdmin+"/admin/audit/checkpoint", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		msg := do(req, 200)
		c, err := audit.OpenCheckpoint([]byte(msg), verifier)
		if err != nil {
			t.Fatalf("served checkpoint: %v\n%s", err, msg)
		}
		return msg, c
	}

	for i := range 20 {
		round(i)
	}
	// The served checkpoint covers what all three wrote: the mcp gateway
	// reads the others' records before it signs.
	msg, saved := checkpoint()
	if n := countRecords(t, chain); saved.Size != n {
		t.Fatalf("served checkpoint covers %d records, the log has %d", saved.Size, n)
	}
	savedFile := filepath.Join(dir, "auditor.checkpoint")
	os.WriteFile(savedFile, []byte(msg), 0o600)

	for i := 20; i < 40; i++ {
		round(i)
	}
	// The timers sign the new records on their own within a few seconds.
	deadline := time.Now().Add(15 * time.Second)
	for {
		b, _ := os.ReadFile(audit.CheckpointPath(chain))
		if c, err := audit.OpenCheckpoint(b, verifier); err == nil && c.Size == countRecords(t, chain) && c.Size > saved.Size {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no timed checkpoint of the new records: %s", b)
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop(t, gwCmd)
	stop(t, mcpCmd)
	stop(t, serveCmd)

	segs, err := audit.Segments(chain)
	if err != nil || len(segs) < 3 {
		t.Fatalf("segments %v %v", segs, err)
	}
	cr, err := audit.VerifyChain(chain, audit.Default())
	if err != nil {
		t.Fatal(err)
	}
	head := fmt.Sprintf("OK %s: %d records in %d segments, head %s\n", chain, cr.Records, len(segs)+1, cr.Head)
	// The auditor's checkpoint, from before the rotations that followed.
	code, out, errs := runToEnd(t, "audit verify -key "+vkey+" -checkpoint "+savedFile+" "+chain)
	if code != 0 || !strings.HasPrefix(out, head) ||
		!strings.Contains(out, fmt.Sprintf("checkpoint signed by audit.test at %s covers %d of the %d records", saved.Time.Format(time.RFC3339), saved.Size, cr.Records)) {
		t.Fatalf("verify against the saved checkpoint: exit %d %q %s", code, out, errs)
	}
	// The newest one, written as the last process stopped, covers all.
	pubFile := filepath.Join(dir, "audit.pub")
	os.WriteFile(pubFile, []byte(vkey+"\n"), 0o644)
	code, out, _ = runToEnd(t, "audit verify -key "+pubFile+" "+chain)
	if code != 0 || !strings.Contains(out, fmt.Sprintf("covers %d of the %d records", cr.Records, cr.Records)) {
		t.Fatalf("verify against the newest checkpoint: exit %d %q", code, out)
	}

	// The newest records cut off (up to three, keeping the active
	// segment's start record): the chain still verifies, the checkpoint
	// does not, and no subcommand with the key starts on it.
	whole, _ := os.ReadFile(chain)
	lines := strings.SplitAfter(strings.TrimSuffix(string(whole), "\n"), "\n")
	cut := min(3, len(lines)-1)
	os.WriteFile(chain, []byte(strings.Join(lines[:len(lines)-cut], "")), 0o600)
	if code, _, _ := runToEnd(t, "audit verify "+chain); code != 0 {
		t.Fatalf("the cut chain without -key: exit %d", code)
	}
	code, out, _ = runToEnd(t, "audit verify -key "+vkey+" "+chain)
	if code != 1 || !strings.Contains(out, fmt.Sprintf("the log has %d records, but the checkpoint signed at", cr.Records-uint64(cut))) {
		t.Fatalf("cut log: exit %d %q", code, out)
	}
	code, _, errs = runToEnd(t, "serve", serveEnv...)
	if code != 1 || !strings.Contains(errs, fmt.Sprintf("covers %d records: records were removed from its end", cr.Records)) {
		t.Fatalf("serve on the cut log: exit %d %s", code, errs)
	}

	// A malformed key stops each subcommand before it writes, and
	// authz check names it.
	os.WriteFile(chain, whole, 0o600)
	bad := []string{"AUTHZ_AUDIT_SIGNING_KEY=" + vkey, "AUTHZ_AUDIT_SIGNING_KEY_FILE="}
	for name, run := range map[string][]string{
		"serve":   append(append([]string{"serve"}, serveEnv...), bad...),
		"gateway": append(append([]string{"gateway"}, gwEnv...), bad...),
		"mcp":     append(append([]string{"mcp serve -config " + platformFile}, mcpEnv...), bad...),
		"check":   append(append([]string{"check -serve"}, serveEnv...), bad...),
		"check -config": append([]string{"check -config " + platformFile, "CP_ADMIN=" + adminToken, "CP_AUDIT_KEY=" + auditKey,
			"UPSTREAM_TOKEN=x"}, bad...),
	} {
		code, out, errs := runToEnd(t, run[0], run[1:]...)
		// authz check prints "VARIABLE: error: message".
		if code != 1 || !strings.Contains(out+errs, "AUTHZ_AUDIT_SIGNING_KEY: ") || !strings.Contains(out+errs, "signing key must have the form PRIVATE+KEY+") {
			t.Errorf("%s with a public key as signing key: exit %d %q %q", name, code, out, errs)
		}
	}
	if after, _ := os.ReadFile(chain); string(after) != string(whole) {
		t.Fatal("a refused start wrote to the log")
	}
}

// countRecords is the number of records in the log at path, across its
// segments.
func countRecords(t *testing.T, path string) uint64 {
	t.Helper()
	cr, err := audit.VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cr.Records
}
