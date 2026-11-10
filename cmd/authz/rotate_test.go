//go:build unix

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// runToEnd runs the binary to completion with args and returns its exit
// code, standard output and standard error.
func runToEnd(t *testing.T, args string, extraEnv ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append([]string{"AUTHZ_TEST_MAIN_ARGS=" + args}, extraEnv...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errb.String()
}

// TestMainAuditRotationShared runs authz serve, authz gateway and authz
// mcp as three processes writing one audit file, each set to rotate it at
// the same size: serve and gateway from their GRANTD_ and WICKET_
// variables, mcp from the mcp section of a platform file. The segments
// they cut between them are one chain that authz audit verify checks, with
// every track in it; a removed segment is named; and a fourth process with
// other limits is refused before it writes anything.
func TestMainAuditRotationShared(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "audit.jsonl")
	const (
		apiKey     = "rotate-api-key-0123456789"
		agentKey   = "tgk_rotate_0123456789abcdefghijklmnop"
		adminToken = "admin-0123456789abcdefghijklmnopqrstuv"
		auditKey   = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
		limit      = "8192"
	)

	box := filepath.Join(dir, "box")
	os.MkdirAll(box, 0o700)
	os.WriteFile(filepath.Join(box, "readme.txt"), []byte("the readme"), 0o600)
	fs, err := fakeserver.New(fakeserver.Config{Sandbox: box})
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(fs)
	defer up.Close()

	serveCmd, serveCh := startChild(t, "authz", "serve", false, "GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS="+apiKey,
		"GRANTD_DATA_DIR=", "GRANTD_TOKEN_KEY=", "GRANTD_AUDIT_LOG="+chain, "GRANTD_AUDIT_CHECKS=true",
		"GRANTD_AUDIT_ROTATE_BYTES="+limit, "GRANTD_AUDIT_ROTATE_AGE=")
	serveLogs := collect(serveCh)

	gwCmd, gwCh := startChild(t, "authz", "gateway", false, "WICKET_CONFIG="+writeGatewayConfig(t, dir),
		"WICKET_COOKIE_KEYS="+gatewayCookieKey, "WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0",
		"WICKET_SESSION_FILE=", "WICKET_SIGNING_KEYS=", "WICKET_ADMIN_TOKEN=", "CORP_SECRET=s",
		"WICKET_AUDIT_LOG="+chain, "WICKET_AUDIT_ROTATE_BYTES="+limit, "WICKET_AUDIT_ROTATE_AGE=")
	gwLogs := collect(gwCh)

	mcpCfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"rotate"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
	  "upstreams":[{"name":"files","url":"%s/mcp"}]}`, sha256Hex(agentKey), up.URL)
	pol := `{"version":1,"rules":[{"id":"files-read","effect":"allow","scopes":["files:read"],"upstreams":["files"],"tools":["read_file"]}]}`
	os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(mcpCfg), 0o600)
	os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o600)
	platform, _ := json.Marshal(map[string]any{"version": 1, "mcp": map[string]any{
		"addr": "127.0.0.1:0", "admin_addr": "127.0.0.1:0", "admin_token": map[string]string{"env": "ROT_ADMIN"},
		"config": filepath.Join(dir, "mcp.json"), "policy": filepath.Join(dir, "policy.json"),
		"audit_log": chain, "audit_key": map[string]string{"env": "ROT_AUDIT_KEY"}, "policy_poll": "0",
		"audit_rotate_bytes": 8192,
	}})
	os.WriteFile(filepath.Join(dir, "authz.json"), platform, 0o600)
	mcpCmd, mcpCh := startChild(t, "authz", "mcp serve -config "+filepath.Join(dir, "authz.json"), false,
		"ROT_ADMIN="+adminToken, "ROT_AUDIT_KEY="+auditKey, "AUTHZ_CONFIG=")
	mcpLogs := collect(mcpCh)

	serveAddr, gwAddr, mcpAddr := waitAddr(t, serveLogs), waitAddr(t, gwLogs), waitAddr(t, mcpLogs)

	do := func(req *http.Request, want int) {
		t.Helper()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d, want %d", req.Method, req.URL, resp.StatusCode, want)
		}
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

	// Rounds of a check, a denied forward-auth and a tool call, so every
	// writer appends to, and rotates, segments the others started.
	for i := range 40 {
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
	// Every segment holds no more than one record past the limit, and the
	// three tracks run through the segments.
	events := map[string]int{}
	var rotations int
	for _, s := range cr.Segments {
		f, err := os.Open(s.Path)
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := f.Stat()
		if fi.Size() > 8192+audit.MaxLineBytes {
			t.Errorf("%s: %d bytes", s.Path, fi.Size())
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, audit.MaxLineBytes)
		for sc.Scan() {
			var r audit.Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			events[r.Event]++
			if r.Event == audit.EventSegmentStarted {
				rotations++
				var ss audit.SegmentStarted
				json.Unmarshal(r.Data, &ss)
				if ss.Reason != audit.RotateSize || ss.MaxBytes != 8192 {
					t.Errorf("segment start %+v", ss)
				}
			}
		}
		f.Close()
	}
	if events["authz.check_decided"] < 40 || events["authn.access_denied"] != 40 || events["tool_call"] < 40 || rotations != len(segs) {
		t.Fatalf("records by event %v, %d rotations for %d segments", events, rotations, len(segs))
	}

	code, out, errs := runToEnd(t, "audit verify -head "+cr.Head+" "+chain)
	want := fmt.Sprintf("OK %s: %d records in %d segments, head %s\n", chain, cr.Records, len(segs)+1, cr.Head)
	if code != 0 || out != want {
		t.Fatalf("authz audit verify: exit %d %q %s, want %q", code, out, errs, want)
	}
	// authz mcp audit verify reads the same chain.
	if code, out, _ := runToEnd(t, "mcp audit verify "+chain); code != 0 || out != want {
		t.Fatalf("authz mcp audit verify: exit %d %q", code, out)
	}

	// A process set to other limits does not start, and adds nothing.
	code, _, errs = runToEnd(t, "serve", "GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS="+apiKey, "GRANTD_DATA_DIR=",
		"GRANTD_TOKEN_KEY=", "GRANTD_AUDIT_LOG="+chain, "GRANTD_AUDIT_ROTATE_BYTES=16384")
	if code != 1 || !strings.Contains(errs, "is rotated with max_bytes=8192, but this writer has max_bytes=16384") {
		t.Fatalf("serve with other limits: exit %d %s", code, errs)
	}
	code, _, errs = runToEnd(t, "gateway", "WICKET_CONFIG="+writeGatewayConfig(t, dir), "WICKET_COOKIE_KEYS="+gatewayCookieKey,
		"WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0", "WICKET_SESSION_FILE=", "WICKET_SIGNING_KEYS=",
		"WICKET_ADMIN_TOKEN=", "CORP_SECRET=s", "WICKET_AUDIT_LOG="+chain, "WICKET_AUDIT_ROTATE_BYTES=")
	if code != 1 || !strings.Contains(errs, "but this writer has no rotation") {
		t.Fatalf("gateway without limits: exit %d %s", code, errs)
	}
	if code, out, _ := runToEnd(t, "audit verify -head "+cr.Head+" "+chain); code != 0 || out != want {
		t.Fatalf("after the refused starts: exit %d %q", code, out)
	}

	// A middle segment removed is named.
	if err := os.Remove(segs[1]); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runToEnd(t, "audit verify "+chain)
	if code != 1 || !strings.Contains(out, filepath.Base(segs[1])+") was removed") {
		t.Fatalf("middle segment removed: exit %d %q", code, out)
	}
}
