package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/policy"
)

const (
	agentKey   = "tgk_demo_0123456789abcdefghijklmnopqrstuv"
	adminToken = "admin-0123456789abcdefghijklmnopqrstuv"
)

var (
	auditKey   = strings.Repeat("ab", 32)
	signingKey = strings.Repeat("cd", 32)
)

type setup struct {
	dir    string
	env    map[string]string
	fake   *fakeserver.Server
	policy string
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	dir := t.TempDir()
	box := filepath.Join(dir, "box")
	if err := os.MkdirAll(filepath.Join(box, "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(box, "notes", "a.txt"), []byte("hello"), 0o600)
	fake, err := fakeserver.New(fakeserver.Config{Sandbox: box, Token: "up-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	ts := httptest.NewServer(fake)
	t.Cleanup(ts.Close)
	h := identity.HashToken(agentKey)
	cfg := fmt.Sprintf(`{"tokens":{"issuer":"toolgate","audience":"demo"},
	  "agents":[{"id":"demo-bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
	  "upstreams":[{"name":"fake","url":%q,"credential_env":"UP_TOKEN"}]}`, hex.EncodeToString(h[:]), ts.URL+"/mcp")
	policy := `{"version":1,"rules":[{"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file","echo"]}]}`
	for name, content := range map[string]string{"config.json": cfg, "policy.json": policy} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &setup{dir: dir, fake: fake, policy: filepath.Join(dir, "policy.json"), env: map[string]string{
		"TOOLGATE_ADDR":         "127.0.0.1:0",
		"TOOLGATE_ADMIN_ADDR":   "127.0.0.1:0",
		"TOOLGATE_ADMIN_TOKEN":  adminToken,
		"TOOLGATE_CONFIG":       filepath.Join(dir, "config.json"),
		"TOOLGATE_POLICY":       filepath.Join(dir, "policy.json"),
		"TOOLGATE_AUDIT_LOG":    filepath.Join(dir, "audit.jsonl"),
		"TOOLGATE_AUDIT_KEY":    auditKey,
		"TOOLGATE_STATE_DIR":    filepath.Join(dir, "state"),
		"TOOLGATE_SIGNING_KEYS": "k2=" + signingKey + ",k1=" + strings.Repeat("ef", 32),
		"TOOLGATE_POLICY_POLL":  "0",
		"TOOLGATE_LOG_LEVEL":    "warn",
		"UP_TOKEN":              "up-0123456789",
	}}
}

func (s *setup) getenv(k string) string { return s.env[k] }

type running struct {
	gw, admin string
	cancel    func()
	done      chan int
	logs      *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (s *setup) start(t *testing.T) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan int, 1), logs: &syncBuffer{}}
	ready := make(chan struct{})
	go func() {
		r.done <- cli(ctx, nil, s.getenv, nil, r.logs, r.logs, func(gw, admin string) {
			r.gw, r.admin = "http://"+gw, "http://"+admin
			close(ready)
		})
	}()
	select {
	case <-ready:
	case code := <-r.done:
		t.Fatalf("exited with %d: %s", code, r.logs.String())
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not start")
	}
	return r
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	if code := <-r.done; code != 0 {
		t.Fatalf("exit code %d: %s", code, r.logs.String())
	}
}

func mcpCall(t *testing.T, url, token, method string, params map[string]any) map[string]any {
	t.Helper()
	params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest("POST", url+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if n, ok := params["name"].(string); ok {
		req.Header.Set("Mcp-Name", n)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func adminGet(t *testing.T, url, path string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", url+path, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestRunRestartAndReload(t *testing.T) {
	s := newSetup(t)
	r := s.start(t)
	res := mcpCall(t, r.gw, agentKey, "tools/call", map[string]any{"name": "fake.read_file", "arguments": map[string]any{"path": "notes/a.txt"}})
	if !strings.Contains(fmt.Sprint(res["result"]), "hello") {
		t.Fatalf("call: %v", res)
	}
	// Signed token from the CLI works against the running gateway.
	var tok bytes.Buffer
	if code := cli(context.Background(), []string{"token", "mint", "-sub", "ci-bot", "-scope", "files:read", "-ttl", "5m"}, s.getenv, nil, &tok, io.Discard, nil); code != 0 {
		t.Fatal("mint failed")
	}
	res = mcpCall(t, r.gw, strings.TrimSpace(tok.String()), "tools/list", map[string]any{})
	if !strings.Contains(fmt.Sprint(res["result"]), "fake.read_file") {
		t.Fatalf("signed token list: %v", res)
	}
	// SIGHUP reloads the policy.
	h1 := adminGet(t, r.admin, "/admin/policy")["hash"]
	if err := os.WriteFile(s.policy, []byte(`{"version":1,"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for adminGet(t, r.admin, "/admin/policy")["hash"] == h1 {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not reload the policy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	head1 := adminGet(t, r.admin, "/admin/audit/head")
	r.stop(t)

	// While the gateway is down the upstream changes a tool; the restarted
	// gateway still remembers the trusted definition and quarantines it.
	s.fake.SetRugPull(true)
	r = s.start(t)
	head2 := adminGet(t, r.admin, "/admin/audit/head")
	if head2["head"] != head1["head"] {
		t.Fatalf("audit head changed across restart: %v vs %v", head1, head2)
	}
	deadline = time.Now().Add(5 * time.Second)
	for !strings.Contains(fmt.Sprint(adminGet(t, r.admin, "/admin/tools")), "quarantined") {
		if time.Now().After(deadline) {
			t.Fatal("tool change across restart not quarantined")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.stop(t)

	var out bytes.Buffer
	if code := cli(context.Background(), []string{"audit", "verify", "-head", fmt.Sprint(adminHeadFromFile(t, s)), s.env["TOOLGATE_AUDIT_LOG"]}, s.getenv, nil, &out, io.Discard, nil); code != 0 {
		t.Fatalf("verify after restarts: %s", out.String())
	}
}

func adminHeadFromFile(t *testing.T, s *setup) string {
	t.Helper()
	var out bytes.Buffer
	cli(context.Background(), []string{"audit", "verify", s.env["TOOLGATE_AUDIT_LOG"]}, s.getenv, nil, &out, io.Discard, nil)
	f := strings.Fields(out.String())
	return f[len(f)-1]
}

func TestAuditVerifyCommand(t *testing.T) {
	s := newSetup(t)
	r := s.start(t)
	for i := range 3 {
		mcpCall(t, r.gw, agentKey, "tools/call", map[string]any{"name": "fake.echo", "arguments": map[string]any{"text": fmt.Sprint(i)}})
	}
	r.stop(t)
	path := s.env["TOOLGATE_AUDIT_LOG"]
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := cli(context.Background(), append([]string{"audit", "verify"}, args...), s.getenv, nil, &out, &errOut, nil)
		return code, out.String() + errOut.String()
	}
	code, out := run(path)
	if code != 0 || !strings.HasPrefix(out, "OK ") {
		t.Fatalf("%d %s", code, out)
	}
	if code, out := run("-head", strings.Repeat("0", 64), path); code != 1 || !strings.Contains(out, "not the expected head") {
		t.Fatalf("head mismatch: %d %s", code, out)
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	lines[1] = strings.Replace(lines[1], `"agent":"demo-bot"`, `"agent":"mallory"`, 1)
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
	if code, out := run(path); code != 1 || !strings.Contains(out, "line 2") {
		t.Fatalf("tampered: %d %s", code, out)
	}
	if code, _ := run(); code != 2 {
		t.Fatal("usage")
	}
	if code, _ := run(filepath.Join(s.dir, "missing")); code != 2 {
		t.Fatal("missing file")
	}
	// The gateway refuses to start on a tampered log.
	var logs bytes.Buffer
	if code := cli(context.Background(), nil, s.getenv, nil, &logs, &logs, nil); code != 1 || !strings.Contains(logs.String(), "failed verification") {
		t.Fatalf("started on a tampered log: %s", logs.String())
	}
}

func TestPolicyTestCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cli(context.Background(), append([]string{"policy", "test"}, args...), nil, nil, &out, &errOut, nil)
		return code, out.String(), errOut.String()
	}
	pol, cases := filepath.Join("..", "..", "..", "..", "toolgate", "examples", "policy.json"), filepath.Join("..", "..", "..", "..", "toolgate", "examples", "policy_cases.json")
	if code, out, errOut := run(pol, cases); code != 0 || !strings.HasPrefix(out, "PASS ") || errOut != "" {
		t.Fatalf("example cases: %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("-v", pol, cases); code != 0 || !strings.Contains(out, "ok   alice reads a report\n") {
		t.Fatalf("verbose: %d %s", code, out)
	}

	// Narrowing read-workspace to reports breaks the notes case, and the
	// report says which case, what was expected and what was decided.
	src, err := os.ReadFile(pol)
	if err != nil {
		t.Fatal(err)
	}
	narrowed := strings.Replace(string(src), `"x-path-prefix": ["reports", "notes"]`, `"x-path-prefix": ["reports"]`, 1)
	if narrowed == string(src) {
		t.Fatal("example policy changed; update this test")
	}
	code, out, _ := run(write("narrow.json", narrowed), cases)
	if code != 1 || !strings.Contains(out, "FAIL alice reads a note\n     decision: want allow\n                got deny\n") ||
		!strings.Contains(out, "path is outside the allowed directories") || !strings.Contains(out, "1 failed") {
		t.Fatalf("narrowed policy: %d\n%s", code, out)
	}

	if code, _, errOut := run(pol); code != 2 || !strings.Contains(errOut, "usage") {
		t.Fatalf("usage: %d %s", code, errOut)
	}
	if code, _, _ := run(filepath.Join(dir, "missing"), cases); code != 2 {
		t.Fatal("missing policy")
	}
	if code, _, _ := run(pol, filepath.Join(dir, "missing")); code != 2 {
		t.Fatal("missing cases")
	}
	if code, _, errOut := run(write("bad.json", `{"version":1,"rules":[{"id":"x"}]}`), cases); code != 2 || !strings.Contains(errOut, "bad.json") {
		t.Fatalf("invalid policy: %d %s", code, errOut)
	}
	if code, _, errOut := run(pol, write("badcases.json", `{"version":1,"cases":[],"x":1}`)); code != 2 || !strings.Contains(errOut, "badcases.json") {
		t.Fatalf("invalid cases: %d %s", code, errOut)
	}
	if code, _, errOut := run(pol, write("huge.json", strings.Repeat(" ", policy.MaxCaseBytes+1))); code != 2 || !strings.Contains(errOut, "larger than") {
		t.Fatalf("oversized cases: %d %s", code, errOut)
	}
}

func TestTokenCommands(t *testing.T) {
	s := newSetup(t)
	var out bytes.Buffer
	if code := cli(context.Background(), []string{"token", "new"}, s.getenv, nil, &out, io.Discard, nil); code != 0 {
		t.Fatal("token new")
	}
	var key, sum string
	fmt.Sscanf(out.String(), "key: %s\ntoken_sha256: %s", &key, &sum)
	out.Reset()
	if code := cli(context.Background(), []string{"token", "hash"}, s.getenv, strings.NewReader(key+"\n"), &out, io.Discard, nil); code != 0 || strings.TrimSpace(out.String()) != sum {
		t.Fatalf("hash %q vs %q", out.String(), sum)
	}
	fail := func(args []string, getenv func(string) string, stdin string) {
		t.Helper()
		var errOut bytes.Buffer
		if code := cli(context.Background(), args, getenv, strings.NewReader(stdin), io.Discard, &errOut, nil); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	fail([]string{"token", "hash"}, s.getenv, "short\n")
	fail([]string{"token", "bogus"}, s.getenv, "")
	fail([]string{"token", "mint", "-sub", "bad id"}, s.getenv, "")
	fail([]string{"token", "mint", "-nope"}, s.getenv, "")
	fail([]string{"token", "mint", "-sub", "x"}, func(k string) string {
		if k == "TOOLGATE_SIGNING_KEYS" {
			return ""
		}
		return s.getenv(k)
	}, "")
	fail([]string{"token", "mint", "-sub", "x"}, func(k string) string {
		if k == "TOOLGATE_CONFIG" {
			return ""
		}
		return s.getenv(k)
	}, "")
	fail([]string{"token", "mint", "-sub", "x"}, func(k string) string {
		if k == "TOOLGATE_SIGNING_KEYS" {
			return "bad"
		}
		return s.getenv(k)
	}, "")
	fail([]string{"token", "mint", "-sub", "x"}, func(k string) string {
		if k == "TOOLGATE_CONFIG" {
			return filepath.Join(s.dir, "missing.json")
		}
		return s.getenv(k)
	}, "")
	fail([]string{"bogus"}, s.getenv, "")
	// Minting does not need upstream credentials in the environment.
	out.Reset()
	noUpstream := func(k string) string {
		if k == "UP_TOKEN" {
			return ""
		}
		return s.getenv(k)
	}
	if code := cli(context.Background(), []string{"token", "mint", "-sub", "ci-bot"}, noUpstream, nil, &out, io.Discard, nil); code != 0 || strings.Count(out.String(), ".") != 2 {
		t.Fatalf("mint without upstream credentials: %q", out.String())
	}
}

func TestConfigErrors(t *testing.T) {
	s := newSetup(t)
	bad := filepath.Join(s.dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{`), 0o600)
	cases := map[string]map[string]string{
		"TOOLGATE_ADMIN_TOKEN is required": {"TOOLGATE_ADMIN_TOKEN": ""},
		"at least 32 characters":           {"TOOLGATE_ADMIN_TOKEN": "short"},
		"TOOLGATE_CONFIG is required":      {"TOOLGATE_CONFIG": ""},
		"TOOLGATE_POLICY is required":      {"TOOLGATE_POLICY": ""},
		"TOOLGATE_AUDIT_LOG is required":   {"TOOLGATE_AUDIT_LOG": ""},
		"TOOLGATE_AUDIT_KEY is required":   {"TOOLGATE_AUDIT_KEY": ""},
		"TOOLGATE_AUDIT_KEY must be":       {"TOOLGATE_AUDIT_KEY": "abc"},
		"TOOLGATE_SIGNING_KEYS must be":    {"TOOLGATE_SIGNING_KEYS": "k=zz"},
		"repeats key id":                   {"TOOLGATE_SIGNING_KEYS": "k=" + signingKey + ",k=" + signingKey},
		"TOOLGATE_POLICY_POLL":             {"TOOLGATE_POLICY_POLL": "soon"},
		"TOOLGATE_LOG_LEVEL":               {"TOOLGATE_LOG_LEVEL": "loud"},
		"config: open":                     {"TOOLGATE_CONFIG": filepath.Join(s.dir, "missing.json")},
		"config: unexpected EOF":           {"TOOLGATE_CONFIG": bad},
		"policy:":                          {"TOOLGATE_POLICY": bad},
		"audit:":                           {"TOOLGATE_AUDIT_LOG": s.dir},
		"pins:":                            {"TOOLGATE_STATE_DIR": filepath.Join(s.dir, "config.json")},
		"listen tcp":                       {"TOOLGATE_ADMIN_ADDR": "127.0.0.1:99999"},
		"environment variable UP_TOKEN":    {"UP_TOKEN": ""},
		"no tokens section":                {"TOOLGATE_CONFIG": writeConfigWithoutTokens(t, s)},
	}
	for want, override := range cases {
		getenv := func(k string) string {
			if v, ok := override[k]; ok {
				return v
			}
			return s.env[k]
		}
		var logs bytes.Buffer
		code := cli(context.Background(), nil, getenv, nil, &logs, &logs, nil)
		matched := false
		for _, w := range strings.Split(want, "|") {
			matched = matched || strings.Contains(logs.String(), w)
		}
		if code != 1 || !matched {
			t.Errorf("%s: code %d, output %s", want, code, logs.String())
		}
	}
	// A missing state dir only warns.
	getenv := func(k string) string {
		if k == "TOOLGATE_STATE_DIR" {
			return ""
		}
		if k == "TOOLGATE_POLICY_POLL" {
			return "50ms"
		}
		return s.env[k]
	}
	ctx, cancel := context.WithCancel(context.Background())
	var logs syncBuffer
	done := make(chan int)
	go func() {
		done <- cli(ctx, []string{"serve"}, getenv, nil, &logs, &logs, func(string, string) { cancel() })
	}()
	if code := <-done; code != 0 || !strings.Contains(logs.String(), "TOOLGATE_STATE_DIR not set") {
		t.Fatalf("memory-only state: %d %s", code, logs.String())
	}
}

func writeConfigWithoutTokens(t *testing.T, s *setup) string {
	data, _ := os.ReadFile(s.env["TOOLGATE_CONFIG"])
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	delete(m, "tokens")
	out, _ := json.Marshal(m)
	p := filepath.Join(s.dir, "notokens.json")
	_ = os.WriteFile(p, out, 0o600)
	return p
}
