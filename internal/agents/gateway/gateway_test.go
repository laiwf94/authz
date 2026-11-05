package gateway

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/agents/metrics"
	"github.com/laiwf94/authz/internal/agents/pins"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/audit"
)

const (
	aliceKey    = "tgk_alice_0123456789abcdefghijklmnopqrstuv"
	bobKey      = "tgk_bob_0123456789abcdefghijklmnopqrstuvwx"
	quotaKey    = "tgk_quota_0123456789abcdefghijklmnopqrstu"
	adminToken  = "admin-token-0123456789abcdefghijklmnop"
	upstreamKey = "upstream-secret-0123456789"
)

const testPolicy = `{"version":1,"rules":[
 {"id":"no-env","effect":"deny","agents":["*"],"upstreams":["fake"],"tools":["read_file"],
  "arguments":{"required":["path"],"properties":{"path":{"pattern":"(^|/)\\.env$"}}}},
 {"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file"],
  "arguments":{"type":"object","required":["path"],"additionalProperties":false,
               "properties":{"path":{"type":"string","maxLength":256,"x-path-prefix":["reports","notes"]}}},
  "output":{"redact":["aws_access_key_id"],"max_bytes":4000}},
 {"id":"echo-all","effect":"allow","agents":["*"],"upstreams":["fake"],"tools":["echo"]},
 {"id":"web","effect":"allow","agents":["alice-bot"],"upstreams":["fake"],"tools":["http_get"],
  "arguments":{"type":"object","properties":{"url":{"type":"string","x-allowed-hosts":["example.com"]}}}},
 {"id":"translate","effect":"allow","agents":["alice-bot","ci-agent"],"upstreams":["fake"],"tools":["translate"],"requires_approval":true}
]}`

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t          testing.TB
	dir        string
	gw         *Gateway
	gwURL      string
	adminURL   string
	fake       *fakeserver.Server
	clk        *clock
	auditLog   *audit.Log
	auditPath  string
	policyPath string
	auth       *identity.Authenticator
}

func hashHex(s string) string { h := identity.HashToken(s); return hex.EncodeToString(h[:]) }

func newEnv(t testing.TB, mutate ...func(*Config)) *env {
	t.Helper()
	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")
	for p, content := range map[string]string{
		"reports/q1.txt":    "Revenue grew 12%.",
		"reports/creds.txt": "aws key AKIAIOSFODNN7EXAMPLE in the open",
		"reports/big.txt":   strings.Repeat("x", 10_000),
		"reports/.env":      "SECRET=1",
		"notes/a.md":        "note",
	} {
		full := filepath.Join(sandbox, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake, err := fakeserver.New(fakeserver.Config{Sandbox: sandbox, Token: upstreamKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	fakeTS := httptest.NewServer(fake)
	t.Cleanup(fakeTS.Close)

	cfgSrc := fmt.Sprintf(`{
	  "tokens": {"issuer": "toolgate", "audience": "toolgate-test", "max_ttl_seconds": 3600},
	  "agents": [
	    {"id": "alice-bot", "owner": "alice", "scopes": ["files:read"], "token_sha256": %q,
	     "limits": {"tool_rps": 1, "tool_burst": 3, "daily_quota": 100}},
	    {"id": "bob-bot", "owner": "bob", "token_sha256": %q},
	    {"id": "quota-bot", "owner": "q", "scopes": ["files:read"], "token_sha256": %q, "limits": {"daily_quota": 2}}
	  ],
	  "upstreams": [{"name": "fake", "url": %q, "credential_env": "FAKE_TOKEN", "timeout_ms": 2000, "tools_ttl_seconds": 30}],
	  "approvals": {"wait_seconds": 0, "pending_ttl_seconds": 600, "max_grant_ttl_seconds": 600}
	}`, hashHex(aliceKey), hashHex(bobKey), hashHex(quotaKey), fakeTS.URL+"/mcp")
	cfg, err := ParseConfig([]byte(cfgSrc), func(k string) string {
		if k == "FAKE_TOKEN" {
			return upstreamKey
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mutate {
		m(cfg)
	}
	clk := &clock{t: time.Now()}
	auth, err := cfg.NewAuthenticator(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.OpenStore(policyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	al, err := audit.Open(auditPath, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	ps, err := pins.Open(filepath.Join(dir, "pins.json"), clk.now)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(Options{Config: cfg, Auth: auth, Policy: pol, Audit: al, Pins: ps, AuditKey: bytes.Repeat([]byte{9}, 32),
		AllowedOrigins: []string{"https://console.example.com"}, Metrics: metrics.New(), Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	gwTS := httptest.NewServer(gw.Handler())
	t.Cleanup(gwTS.Close)
	adminTS := httptest.NewServer(gw.AdminHandler(adminToken))
	t.Cleanup(adminTS.Close)
	return &env{t: t, dir: dir, gw: gw, gwURL: gwTS.URL + "/mcp", adminURL: adminTS.URL, fake: fake, clk: clk,
		auditLog: al, auditPath: auditPath, policyPath: policyPath, auth: auth}
}

type reply struct {
	status int
	header http.Header
	body   map[string]any
	raw    string
}

func (r reply) result() map[string]any { m, _ := r.body["result"].(map[string]any); return m }
func (r reply) errCode() int {
	e, _ := r.body["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return int(c)
}
func (r reply) errData() map[string]any {
	e, _ := r.body["error"].(map[string]any)
	d, _ := e["data"].(map[string]any)
	return d
}

func (r reply) text() string {
	var b strings.Builder
	items, _ := r.result()["content"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		s, _ := m["text"].(string)
		b.WriteString(s)
	}
	return b.String()
}

var reqID atomic.Int64

// rpc sends a modern MCP request as an agent.
func (e *env) rpc(token, method string, params map[string]any, extra map[string]string) reply {
	e.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{mcp.MetaProtocolVersion: mcp.VersionModern, mcp.MetaClientCapabilities: map[string]any{},
		mcp.MetaClientInfo: map[string]any{"name": "test-agent", "version": "1"}}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": reqID.Add(1), "method": method, "params": params})
	h := map[string]string{mcp.HeaderProtocolVersion: mcp.VersionModern, mcp.HeaderMethod: method}
	if name, ok := params["name"].(string); ok {
		h[mcp.HeaderName] = mcp.EncodeHeaderValue(name)
	}
	for k, v := range extra {
		h[k] = v
	}
	return e.post(e.gwURL, token, body, h)
}

func (e *env) call(token, tool string, args map[string]any, extra ...map[string]string) reply {
	e.t.Helper()
	var x map[string]string
	if len(extra) > 0 {
		x = extra[0]
	}
	return e.rpc(token, "tools/call", map[string]any{"name": tool, "arguments": args}, x)
}

func (e *env) post(url, token string, body []byte, h map[string]string) reply {
	e.t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	return e.do(req)
}

func (e *env) do(req *http.Request) reply {
	e.t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	r := reply{status: resp.StatusCode, header: resp.Header, raw: string(data)}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &r.body)
	}
	return r
}

func (e *env) admin(method, path, body string) reply {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.adminURL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return e.do(req)
}

func toolNames(r reply) []string {
	var names []string
	tools, _ := r.result()["tools"].([]any)
	for _, t := range tools {
		names = append(names, t.(map[string]any)["name"].(string))
	}
	return names
}

func (e *env) auditRecords() []audit.Record {
	e.t.Helper()
	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestToolsListIsFilteredPerAgent(t *testing.T) {
	e := newEnv(t)
	r := e.rpc(aliceKey, "tools/list", nil, nil)
	if got := strings.Join(toolNames(r), ","); got != "fake.echo,fake.http_get,fake.read_file,fake.translate" {
		t.Fatalf("alice sees %s (%s)", got, r.raw)
	}
	if r.result()["cacheScope"] != "private" {
		t.Fatal("per-agent list must not be publicly cacheable")
	}
	if got := strings.Join(toolNames(e.rpc(bobKey, "tools/list", nil, nil)), ","); got != "fake.echo" {
		t.Fatalf("bob sees %s", got)
	}
	// Definitions are passed through, renamed, without icons or _meta.
	tools := e.rpc(aliceKey, "tools/list", nil, nil).result()["tools"].([]any)
	echo := tools[0].(map[string]any)
	if echo["description"] != "Return the given text." || echo["inputSchema"] == nil || echo["annotations"] == nil {
		t.Fatalf("definition not passed through: %v", echo)
	}
}

func TestAllowedCallAndCredentialInjection(t *testing.T) {
	e := newEnv(t)
	r := e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/q1.txt"})
	if r.status != 200 || r.text() != "Revenue grew 12%." || r.result()["resultType"] != "complete" {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	// The fake upstream requires upstreamKey; the call only worked because
	// the gateway injected it. The agent's own key was never forwarded,
	// which the next check proves from the other side.
	cfgNoCred := func(c *Config) { c.Upstreams[0].credential = "" }
	e2 := newEnv(t, cfgNoCred)
	if r := e2.call(aliceKey, "fake.echo", map[string]any{"text": "x"}); r.errCode() != mcp.CodeUpstreamError {
		t.Fatalf("without the gateway credential the upstream must refuse: %s", r.raw)
	}
}

func TestArgumentConstraintsAndDeny(t *testing.T) {
	e := newEnv(t)
	before := e.fake.Calls()
	cases := []struct {
		name       string
		token      string
		tool       string
		args       map[string]any
		code       int
		rule       string
		reasonPart string
	}{
		{"traversal", aliceKey, "fake.read_file", map[string]any{"path": "../../etc/passwd"}, mcp.CodePolicyDenied, "default-deny", `".." segments`},
		{"outside prefix", aliceKey, "fake.read_file", map[string]any{"path": "secret.txt"}, mcp.CodePolicyDenied, "default-deny", "outside the allowed directories"},
		{"extra argument", aliceKey, "fake.read_file", map[string]any{"path": "reports/q1.txt", "mode": "x"}, mcp.CodePolicyDenied, "default-deny", "not allowed"},
		{"explicit deny", aliceKey, "fake.read_file", map[string]any{"path": "reports/.env"}, mcp.CodePolicyDenied, "no-env", "rule no-env forbids this call"},
		{"ssrf", aliceKey, "fake.http_get", map[string]any{"url": "http://169.254.169.254/latest/meta-data/"}, mcp.CodePolicyDenied, "default-deny", "not in the allowed list"},
		{"invisible tool", bobKey, "fake.read_file", map[string]any{"path": "reports/q1.txt"}, -32602, "", ""},
		{"unknown upstream", aliceKey, "nope.x", nil, -32602, "", ""},
		{"no namespace", aliceKey, "echo", nil, -32602, "", ""},
		{"unknown tool", aliceKey, "fake.nope", nil, -32602, "", ""},
	}
	for _, c := range cases {
		r := e.call(c.token, c.tool, c.args)
		if r.status != 200 || r.errCode() != c.code {
			t.Errorf("%s: %d %s", c.name, r.status, r.raw)
			continue
		}
		if c.rule != "" {
			d := r.errData()
			if d["rule_id"] != c.rule || !strings.Contains(fmt.Sprint(d["reason"]), c.reasonPart) {
				t.Errorf("%s: data %v", c.name, d)
			}
		}
	}
	if e.fake.Calls() != before {
		t.Fatal("a denied call reached the upstream")
	}
	// Every refusal is audited with its rule.
	var denied int
	for _, rec := range e.auditRecords() {
		if rec.Event == "tool_call" && strings.Contains(string(rec.Data), `"decision":"deny"`) {
			denied++
		}
	}
	if denied != 9 {
		t.Fatalf("audited %d denials, want 9 (every refusal, including unknown tools)", denied)
	}
}

func TestRateLimitAndQuota(t *testing.T) {
	e := newEnv(t)
	for i := range 3 {
		if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.status != 200 || r.body["error"] != nil {
			t.Fatalf("call %d: %s", i, r.raw)
		}
	}
	r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"})
	if r.status != 429 || r.errCode() != mcp.CodeRateLimited || r.header.Get("Retry-After") != "1" || r.errData()["scope"] != "tool" {
		t.Fatalf("rate limit: %d %v %s", r.status, r.header.Get("Retry-After"), r.raw)
	}
	// Another tool has its own bucket.
	if r := e.call(aliceKey, "fake.read_file", map[string]any{"path": "notes/a.md"}); r.status != 200 {
		t.Fatalf("other tool limited: %s", r.raw)
	}
	e.clk.add(time.Second)
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.status != 200 {
		t.Fatalf("after refill: %s", r.raw)
	}
	// Daily quota.
	for i := range 2 {
		if r := e.call(quotaKey, "fake.echo", map[string]any{"text": "q"}); r.status != 200 {
			t.Fatalf("quota call %d: %s", i, r.raw)
		}
	}
	r = e.call(quotaKey, "fake.echo", map[string]any{"text": "q"})
	if r.status != 429 || r.errCode() != mcp.CodeQuotaExceeded || r.header.Get("Retry-After") == "" {
		t.Fatalf("quota: %s", r.raw)
	}
	// Denied calls do not use quota.
	e3 := newEnv(t)
	for range 5 {
		e3.call(quotaKey, "fake.read_file", map[string]any{"path": "../x"})
	}
	if r := e3.call(quotaKey, "fake.echo", map[string]any{"text": "q"}); r.status != 200 {
		t.Fatalf("denials consumed quota: %s", r.raw)
	}
	// The per-agent request limit applies to every method.
	e4 := newEnv(t, func(c *Config) { c.Limits.AgentRPS, c.Limits.AgentBurst = 1, 2 })
	e4.rpc(bobKey, "tools/list", nil, nil)
	e4.rpc(bobKey, "tools/list", nil, nil)
	if r := e4.rpc(bobKey, "tools/list", nil, nil); r.status != 429 || r.errData()["scope"] != "agent" {
		t.Fatalf("agent limit: %s", r.raw)
	}
}

func lang(l string) map[string]string { return map[string]string{"Mcp-Param-Language": l} }

func noToolLimit(c *Config) { c.Agents[0].Limits.ToolRPS = 0 }

func TestApprovalFlow(t *testing.T) {
	e := newEnv(t, noToolLimit)
	args := map[string]any{"text": "hello", "language": "de"}
	r := e.call(aliceKey, "fake.translate", args, lang("de"))
	if r.errCode() != mcp.CodeApprovalPending {
		t.Fatalf("want pending: %s", r.raw)
	}
	id := r.errData()["approval_id"].(string)
	// Polling the same call finds the same request.
	if r := e.call(aliceKey, "fake.translate", args, lang("de")); r.errData()["approval_id"] != id {
		t.Fatalf("poll opened a new request: %s", r.raw)
	}
	list := e.admin("GET", "/admin/approvals", "")
	if !strings.Contains(list.raw, id) || !strings.Contains(list.raw, `"arguments":{"language":"de","text":"hello"}`) {
		t.Fatalf("admin list: %s", list.raw)
	}
	if r := e.admin("GET", "/admin/approvals/"+id, ""); r.body["status"] != "pending" {
		t.Fatalf("get: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/approvals/"+id+"/approve", `{"ttl_seconds":99999}`); r.status != 400 {
		t.Fatalf("over-long ttl: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/approvals/"+id+"/approve", `{"ttl_seconds":120,"note":"ok for demo"}`); r.status != 200 || r.body["status"] != "approved" {
		t.Fatalf("approve: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/approvals/"+id+"/deny", `{}`); r.status != 409 {
		t.Fatalf("second decision: %s", r.raw)
	}
	// Other arguments are not covered.
	if r := e.call(aliceKey, "fake.translate", map[string]any{"text": "other", "language": "de"}, lang("de")); r.errCode() != mcp.CodeApprovalPending {
		t.Fatalf("approval covered other arguments: %s", r.raw)
	}
	r = e.call(aliceKey, "fake.translate", args, lang("de"))
	if r.status != 200 || r.text() != "[de] hello" {
		t.Fatalf("approved call: %s", r.raw)
	}
	// Single use.
	if r := e.call(aliceKey, "fake.translate", args, lang("de")); r.errCode() != mcp.CodeApprovalPending {
		t.Fatalf("approval reused: %s", r.raw)
	}
	// Denial.
	r = e.call(aliceKey, "fake.translate", map[string]any{"text": "bad", "language": "fr"}, lang("fr"))
	did := r.errData()["approval_id"].(string)
	if r := e.admin("POST", "/admin/approvals/"+did+"/deny", `{"note":"no"}`); r.status != 200 {
		t.Fatalf("deny: %s", r.raw)
	}
	if r := e.call(aliceKey, "fake.translate", map[string]any{"text": "bad", "language": "fr"}, lang("fr")); r.errCode() != mcp.CodeApprovalDenied {
		t.Fatalf("denied call: %s", r.raw)
	}
	for path, status := range map[string]int{
		"/admin/approvals/apr_missing":         404,
		"/admin/approvals/apr_missing/approve": 404,
	} {
		method := "GET"
		if strings.HasSuffix(path, "approve") {
			method = "POST"
		}
		if r := e.admin(method, path, ""); r.status != status {
			t.Errorf("%s: %d", path, r.status)
		}
	}
	if r := e.admin("POST", "/admin/approvals/"+did+"/deny", `{"ttl_seconds":5}`); r.status != 400 {
		t.Fatalf("ttl on deny: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/approvals/x/approve", `{"note":"`+strings.Repeat("n", 1100)+`"}`); r.status != 400 {
		t.Fatalf("long note: %s", r.raw)
	}
	events := map[string]int{}
	for _, rec := range e.auditRecords() {
		events[rec.Event]++
	}
	if events["approval_requested"] != 4 || events["approval_decided"] != 2 {
		t.Fatalf("audit events %v", events)
	}
}

func TestApprovalWaitsInline(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Approvals.WaitSeconds = 5 })
	go func() {
		for i := 0; i < 200; i++ {
			time.Sleep(10 * time.Millisecond)
			var list struct {
				Approvals []struct{ ID string } `json:"approvals"`
			}
			r := e.admin("GET", "/admin/approvals", "")
			_ = json.Unmarshal([]byte(r.raw), &list)
			if len(list.Approvals) > 0 {
				e.admin("POST", "/admin/approvals/"+list.Approvals[0].ID+"/approve", `{}`)
				return
			}
		}
	}()
	r := e.call(aliceKey, "fake.translate", map[string]any{"text": "wait", "language": "ja"}, lang("ja"))
	if r.status != 200 || r.text() != "[ja] wait" {
		t.Fatalf("inline approval: %s", r.raw)
	}
}

func TestRugPullQuarantine(t *testing.T) {
	e := newEnv(t)
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "pin me"}); r.status != 200 {
		t.Fatal(r.raw)
	}
	e.fake.SetRugPull(true)
	e.clk.add(31 * time.Second) // past the tool list TTL
	names := strings.Join(toolNames(e.rpc(aliceKey, "tools/list", nil, nil)), ",")
	if strings.Contains(names, "translate") {
		t.Fatalf("changed tool still listed: %s", names)
	}
	r := e.call(aliceKey, "fake.translate", map[string]any{"text": "x", "language": "de"}, lang("de"))
	if r.errCode() != mcp.CodeToolQuarantined {
		t.Fatalf("quarantined call: %s", r.raw)
	}
	tools := e.admin("GET", "/admin/tools", "")
	var view struct {
		Tools []struct {
			Tool, Status, Hash string
			PendingHash        string          `json:"pending_hash"`
			PendingDefinition  json.RawMessage `json:"pending_definition"`
		} `json:"tools"`
	}
	_ = json.Unmarshal([]byte(tools.raw), &view)
	var pending string
	for _, tv := range view.Tools {
		if tv.Tool == "fake.translate" {
			if tv.Status != "quarantined" || !strings.Contains(string(tv.PendingDefinition), "secrets/.env") {
				t.Fatalf("admin view: %+v", tv)
			}
			pending = tv.PendingHash
		}
	}
	if r := e.admin("POST", "/admin/tools/fake.translate/approve", `{"hash":"`+strings.Repeat("0", 64)+`"}`); r.status != 409 {
		t.Fatalf("approve with a stale hash: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/tools/fake.translate/approve", `{"hash":"x"}`); r.status != 400 {
		t.Fatalf("approve with a malformed hash: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/tools/fake.nope/approve", `{"hash":"`+strings.Repeat("0", 64)+`"}`); r.status != 404 {
		t.Fatalf("approve unknown: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/tools/fake.echo/approve", `{"hash":"`+strings.Repeat("0", 64)+`"}`); r.status != 409 {
		t.Fatalf("approve trusted: %s", r.raw)
	}
	if r := e.admin("POST", "/admin/tools/fake.translate/approve", `{"hash":"`+pending+`"}`); r.status != 200 || r.body["status"] != "trusted" {
		t.Fatalf("approve: %s", r.raw)
	}
	if names := strings.Join(toolNames(e.rpc(aliceKey, "tools/list", nil, nil)), ","); !strings.Contains(names, "fake.translate") {
		t.Fatalf("approved tool not listed: %s", names)
	}
	var quarantined bool
	for _, rec := range e.auditRecords() {
		quarantined = quarantined || rec.Event == "tool_quarantined"
	}
	if !quarantined {
		t.Fatal("quarantine not audited")
	}
}

func TestOutputGuarding(t *testing.T) {
	e := newEnv(t)
	r := e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/creds.txt"})
	if r.text() != "aws key [REDACTED] in the open" {
		t.Fatalf("redaction: %s", r.raw)
	}
	r = e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/big.txt"})
	if txt := r.text(); len(txt) > 4100 || !strings.HasSuffix(txt, "…[truncated by toolgate]") {
		t.Fatalf("truncation: %d bytes", len(txt))
	}
	var sawRedaction, sawTruncation bool
	for _, rec := range e.auditRecords() {
		s := string(rec.Data)
		sawRedaction = sawRedaction || strings.Contains(s, `"redactions":1`)
		sawTruncation = sawTruncation || strings.Contains(s, `"truncated":true`)
	}
	if !sawRedaction || !sawTruncation {
		t.Fatal("guarding not recorded in the audit log")
	}
}

func TestAuditRecordsAndSecrets(t *testing.T) {
	e := newEnv(t)
	e.call(aliceKey, "fake.echo", map[string]any{"text": "token=hunter2-secret", "password": "hunter2"})
	e.call(aliceKey, "fake.echo", map[string]any{"text": "Bearer abcdefghijklmnopqrstuvwxyz"})
	data, _ := os.ReadFile(e.auditPath)
	if bytes.Contains(data, []byte(`"password":"hunter2"`)) || bytes.Contains(data, []byte("abcdefghijklmnopqrstuvwxyz")) {
		t.Fatalf("raw secret in the audit log:\n%s", data)
	}
	recs := e.auditRecords()
	var started, completed int
	for _, r := range recs {
		var d map[string]any
		_ = json.Unmarshal(r.Data, &d)
		switch d["stage"] {
		case "started":
			started++
		case "completed":
			completed++
			if d["agent"] != "alice-bot" || d["rule_id"] != "echo-all" || len(d["args_hmac"].(string)) != 64 || d["request_id"] == "" {
				t.Fatalf("record %v", d)
			}
		}
	}
	if started != 2 || completed != 2 {
		t.Fatalf("started %d completed %d", started, completed)
	}
	f, _ := os.Open(e.auditPath)
	defer f.Close()
	res, err := audit.Verify(f)
	if err != nil || int(res.Records) != len(recs) {
		t.Fatalf("verify: %+v %v", res, err)
	}
	head := e.admin("GET", "/admin/audit/head", "")
	if head.body["head"] != res.Head {
		t.Fatalf("admin head %v, file head %s", head.body["head"], res.Head)
	}
}

func TestAuditFailureRefusesCalls(t *testing.T) {
	e := newEnv(t)
	e.auditLog.Close() // every write now fails
	before := e.fake.Calls()
	r := e.call(aliceKey, "fake.echo", map[string]any{"text": "x"})
	if r.status != 503 || r.errCode() != mcp.CodeAuditUnavailable {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if e.fake.Calls() != before {
		t.Fatal("call reached the upstream without an audit record")
	}
	req, _ := http.NewRequest("GET", strings.TrimSuffix(e.gwURL, "/mcp")+"/healthz", nil)
	if r := e.do(req); r.status != 503 {
		t.Fatalf("healthz: %d", r.status)
	}
}

func TestUpstreamFailures(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &m)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case m.Method == "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[
			  {"name":"sleep","inputSchema":{"type":"object"}},{"name":"fail","inputSchema":{"type":"object"}},
			  {"name":"huge","inputSchema":{"type":"object"}},{"name":"ask","inputSchema":{"type":"object"}},
			  {"name":"broken","inputSchema":{"type":"object"}},
			  {"name":"dup","inputSchema":{"type":"object"}},{"name":"dup","inputSchema":{"type":"object"}},
			  {"name":"bad name","inputSchema":{"type":"object"}},{"name":"noschema"},
			  {"name":"badheader","inputSchema":{"type":"object","properties":{"a":{"type":"number","x-mcp-header":"A"}}}}]}}`, m.ID)
		case m.Params.Name == "sleep":
			time.Sleep(500 * time.Millisecond)
		case m.Params.Name == "fail":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"db password hunter2 AKIAIOSFODNN7EXAMPLE"}}`, m.ID)
		case m.Params.Name == "huge":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}`, m.ID, strings.Repeat("x", 4096))
		case m.Params.Name == "ask":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"input_required","inputRequests":{}}}`, m.ID)
		default:
			w.WriteHeader(500)
		}
	}))
	defer slow.Close()
	e := newEnv(t, func(c *Config) {
		c.Upstreams = append(c.Upstreams, UpstreamConfig{Name: "slow", URL: slow.URL, TimeoutMS: 100, MaxResponseBytes: 1024,
			MaxConcurrency: 1, ToolsTTLSeconds: 30})
		c.Upstreams = append(c.Upstreams, UpstreamConfig{Name: "down", URL: "http://127.0.0.1:1/mcp", TimeoutMS: 200,
			MaxResponseBytes: 1024, MaxConcurrency: 1, ToolsTTLSeconds: 30})
		c.Limits.ToolRPS = 0
	})
	writePolicy(t, e, `{"version":1,"rules":[{"id":"all","effect":"allow","agents":["*"],"upstreams":["*"],"tools":["*"],"output":{"redact_patterns":["hunter[0-9]"]}}]}`)
	names := strings.Join(toolNames(e.rpc(bobKey, "tools/list", nil, nil)), ",")
	if names != "fake.echo,fake.http_get,fake.read_file,fake.translate,slow.ask,slow.broken,slow.fail,slow.huge,slow.sleep" {
		t.Fatalf("list with a down upstream and invalid tools: %s", names)
	}
	cases := map[string]struct {
		status, code int
		notIn        string
	}{
		"slow.sleep":  {504, mcp.CodeUpstreamTimeout, ""},
		"slow.fail":   {502, mcp.CodeUpstreamError, "hunter2"},
		"slow.huge":   {502, mcp.CodeUpstreamError, ""},
		"slow.ask":    {502, mcp.CodeUpstreamError, ""},
		"slow.broken": {502, mcp.CodeUpstreamError, ""},
		"down.x":      {502, mcp.CodeUpstreamError, ""},
	}
	for tool, c := range cases {
		r := e.call(bobKey, tool, nil)
		if r.status != c.status || r.errCode() != c.code || c.notIn != "" && strings.Contains(r.raw, c.notIn) {
			t.Errorf("%s: %d %s", tool, r.status, r.raw)
		}
	}
	data, _ := os.ReadFile(e.auditPath)
	if !bytes.Contains(data, []byte(`"outcome":"upstream_unavailable"`)) || !bytes.Contains(data, []byte(`"requested_tool":"down.x"`)) {
		t.Fatal("a call to an unreachable upstream was not audited")
	}
	// Concurrency limit: one slow call holds the only slot.
	var wg sync.WaitGroup
	wg.Go(func() { e.call(bobKey, "slow.sleep", nil) })
	time.Sleep(30 * time.Millisecond)
	busyStart := time.Now()
	r := e.call(bobKey, "slow.fail", nil)
	wg.Wait()
	if r.status != 429 && time.Since(busyStart) < 50*time.Millisecond {
		t.Fatalf("concurrency limit not applied: %s", r.raw)
	}
}

func writePolicy(t *testing.T, e *env, src string) {
	t.Helper()
	if err := os.WriteFile(e.policyPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.admin("POST", "/admin/policy/reload", ""); r.status != 200 {
		t.Fatalf("reload: %s", r.raw)
	}
}

func TestPolicyHotReload(t *testing.T) {
	e := newEnv(t)
	h1 := e.admin("GET", "/admin/policy", "").body["hash"]
	if r := e.admin("POST", "/admin/policy/reload", ""); r.body["changed"] != false {
		t.Fatalf("no-op reload: %s", r.raw)
	}
	writePolicy(t, e, `{"version":1,"rules":[{"id":"bob-files","effect":"allow","agents":["bob-bot"],"upstreams":["fake"],"tools":["read_file"]}]}`)
	if r := e.call(bobKey, "fake.read_file", map[string]any{"path": "notes/a.md"}); r.text() != "note" {
		t.Fatalf("new policy not in force: %s", r.raw)
	}
	if err := os.WriteFile(e.policyPath, []byte(`{"version":1,"rules":[{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.admin("POST", "/admin/policy/reload", ""); r.status != 422 {
		t.Fatalf("invalid policy: %s", r.raw)
	}
	if r := e.call(bobKey, "fake.read_file", map[string]any{"path": "notes/a.md"}); r.text() != "note" {
		t.Fatal("invalid policy replaced the old one")
	}
	if e.admin("GET", "/admin/policy", "").body["hash"] == h1 {
		t.Fatal("hash did not change")
	}
	events := map[string]int{}
	for _, rec := range e.auditRecords() {
		events[rec.Event]++
	}
	if events["policy_applied"] != 1 || events["policy_rejected"] != 1 {
		t.Fatalf("reload events %v", events)
	}
}

func TestSignedTokenAndLegacyAgent(t *testing.T) {
	e := newEnv(t)
	tok, err := e.auth.Mint("ci-agent", "carol", nil, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if names := toolNames(e.rpc(tok, "tools/list", nil, nil)); strings.Join(names, ",") != "fake.echo,fake.translate" {
		t.Fatalf("signed agent sees %v", names)
	}
	// A 2025-11-25 client: initialize, then the session.
	init := e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`), nil)
	sid := init.header.Get(mcp.HeaderSessionID)
	if sid == "" {
		t.Fatalf("no session: %s", init.raw)
	}
	h := map[string]string{mcp.HeaderSessionID: sid, mcp.HeaderProtocolVersion: mcp.Version251125}
	e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), h)
	r := e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fake.read_file","arguments":{"path":"notes/a.md"}}}`), h)
	if r.text() != "note" || r.result()["resultType"] != nil {
		t.Fatalf("legacy call: %s", r.raw)
	}
	// Legacy clients do not send Mcp-Param headers; the gateway still sends
	// them upstream.
	r = e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fake.translate","arguments":{"text":"a","language":"de"}}}`), h)
	if r.errCode() != mcp.CodeApprovalPending {
		t.Fatalf("legacy approval: %s", r.raw)
	}
	// Bob cannot use Alice's session.
	if r := e.post(e.gwURL, bobKey, []byte(`{"jsonrpc":"2.0","id":4,"method":"ping"}`), h); r.status != 404 {
		t.Fatalf("session hijack: %d", r.status)
	}
}

func TestParamHeaderValidation(t *testing.T) {
	e := newEnv(t)
	args := map[string]any{"text": "x", "language": "de"}
	for name, h := range map[string]map[string]string{"missing": nil, "mismatch": lang("fr")} {
		r := e.call(aliceKey, "fake.translate", args, h)
		if r.status != 400 || r.errCode() != mcp.CodeHeaderMismatch {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
}

func TestTransportSecurity(t *testing.T) {
	e := newEnv(t)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if r := e.post(e.gwURL, aliceKey, body, map[string]string{"Origin": "http://attacker.example"}); r.status != 403 {
		t.Fatalf("origin: %d", r.status)
	}
	if r := e.post(e.gwURL, "", body, nil); r.status != 401 || r.header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no credential: %d", r.status)
	}
	if r := e.post(e.gwURL, "wrong-key-0123456789abcdefghijklmn", body, nil); r.status != 401 {
		t.Fatalf("bad credential: %d", r.status)
	}
	req, _ := http.NewRequest("GET", strings.TrimSuffix(e.gwURL, "/mcp")+"/elsewhere", nil)
	if r := e.do(req); r.status != 404 {
		t.Fatalf("unknown path: %d", r.status)
	}
	// Admin API needs the admin token; an agent key is not enough.
	req, _ = http.NewRequest("GET", e.adminURL+"/admin/approvals", nil)
	req.Header.Set("Authorization", "Bearer "+aliceKey)
	if r := e.do(req); r.status != 401 {
		t.Fatalf("agent on admin API: %d", r.status)
	}
	req, _ = http.NewRequest("GET", e.adminURL+"/healthz", nil)
	if r := e.do(req); r.status != 200 {
		t.Fatalf("admin healthz: %d", r.status)
	}
	if r := e.admin("GET", "/nothing", ""); r.status != 404 {
		t.Fatalf("admin unknown path: %d", r.status)
	}
	e.call(aliceKey, "fake.echo", map[string]any{"text": "x"})
	m := e.admin("GET", "/metrics", "")
	for _, want := range []string{`toolgate_tool_calls_total{upstream="fake",tool="echo",outcome="ok"} 1`,
		"toolgate_auth_failures_total 2", "toolgate_audit_records", "toolgate_tools_quarantined 0"} {
		if !strings.Contains(m.raw, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestRefreshAndStaleList(t *testing.T) {
	e := newEnv(t)
	e.gw.Refresh(context.Background())
	if n := len(e.gw.opt.Pins.List()); n != 4 {
		t.Fatalf("refresh pinned %d tools", n)
	}
	// If the upstream goes away, the last good list is still used for checks.
	e.fake.SetRugPull(false)
	e.gw.ups["fake"].client = mcp.NewClient(mcp.ClientConfig{URL: "http://127.0.0.1:1/mcp"})
	e.clk.add(time.Minute)
	if names := toolNames(e.rpc(aliceKey, "tools/list", nil, nil)); len(names) != 4 {
		t.Fatalf("stale list not served: %v", names)
	}
}

func TestConfigErrors(t *testing.T) {
	get := func(k string) string {
		if k == "SET" {
			return "secret"
		}
		if k == "NL" {
			return "a\nb"
		}
		return ""
	}
	h := strings.Repeat("a", 64)
	up := func(extra string) string {
		return `{"upstreams":[{"name":"u","url":"http://x/mcp"` + extra + `}]}`
	}
	cases := map[string]string{
		`{}`:              "at least one upstream",
		`{"x":1}`:         "unknown field",
		`{"a":1,"a":2}`:   "duplicate",
		up(`,"name":"U"`): "duplicate",
		`{"upstreams":[{"name":"Bad","url":"http://x"}]}`:                                         "name must be",
		up(`,"timeout_ms":5`):                                                                     "timeout_ms",
		up(`,"max_response_bytes":5`):                                                             "max_response_bytes",
		up(`,"max_concurrency":5000`):                                                             "max_concurrency",
		up(`,"tools_ttl_seconds":-1`):                                                             "tools_ttl_seconds",
		up(`,"credential_env":"UNSET"`):                                                           "is empty",
		up(`,"credential_env":"NL"`):                                                              "line break",
		up(`,"credential_header":"X-Key"`):                                                        "needs credential_env",
		up(`,"credential_env":"SET","credential_header":"X Key"`):                                 "header name",
		`{"upstreams":[{"name":"u","url":"ftp://x"}]}`:                                            "url must be",
		`{"upstreams":[{"name":"u","url":"http://user:pw@x"}]}`:                                   "url must be",
		`{"upstreams":[{"name":"u","url":"http://x"},{"name":"u","url":"http://y"}]}`:             "twice",
		`{"limits":{"agent_rps":-1},"upstreams":[{"name":"u","url":"http://x"}]}`:                 "negative",
		`{"limits":{"agent_rps":1e9},"upstreams":[{"name":"u","url":"http://x"}]}`:                "at most",
		`{"agents":[{"id":"a","token_sha256":"zz"}],"upstreams":[{"name":"u","url":"http://x"}]}`: "64 hex",
		`{"agents":[{"id":"a","token_sha256":"` + h + `","limits":{"tool_rps":-1}}],"upstreams":[{"name":"u","url":"http://x"}]}`: "negative",
		`{"tokens":{"issuer":"i"},"upstreams":[{"name":"u","url":"http://x"}]}`:                                                   "issuer and audience",
		`{"tokens":{"issuer":"i","audience":"a","max_ttl_seconds":999999},"upstreams":[{"name":"u","url":"http://x"}]}`:           "max_ttl_seconds",
		`{"approvals":{"wait_seconds":99},"upstreams":[{"name":"u","url":"http://x"}]}`:                                           "wait_seconds",
		`{"approvals":{"pending_ttl_seconds":-1},"upstreams":[{"name":"u","url":"http://x"}]}`:                                    "TTLs",
	}
	for src, want := range cases {
		if _, err := ParseConfig([]byte(src), get); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", src, err, want)
		}
	}
	if _, err := ParseConfig(make([]byte, MaxConfigBytes+1), get); err == nil {
		t.Error("oversized config accepted")
	}
	c, err := ParseConfig([]byte(up(`,"credential_env":"SET","credential_header":"X-Api-Key"`)), get)
	if err != nil || c.Upstreams[0].credential != "secret" || c.Upstreams[0].Timeout() != 10*time.Second {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if c2, err := ParseConfig([]byte(up(`,"credential_env":"UNSET"`)), nil); err != nil || c2.Upstreams[0].credential != "" {
		t.Fatalf("nil getenv must skip credentials: %v", err)
	}
	if _, err := c.NewAuthenticator(map[string][]byte{"k": bytes.Repeat([]byte{1}, 32)}, "k"); err == nil {
		t.Fatal("signing keys without a tokens section accepted")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without dependencies")
	}
	e := newEnv(t)
	if _, err := New(Options{Config: e.gw.cfg, Auth: e.auth, Policy: e.gw.opt.Policy, Audit: e.auditLog, Pins: e.gw.opt.Pins, AuditKey: []byte("short")}); err == nil {
		t.Fatal("short audit key accepted")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("héllo", 2) != "h" || truncate("abc", 5) != "abc" || truncate("abc", 2) != "ab" {
		t.Fatal("truncate")
	}
}

func TestCustomCredentialHeader(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &m)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, m.ID)
	}))
	defer up.Close()
	cfg, err := ParseConfig([]byte(`{"upstreams":[{"name":"u","url":"`+up.URL+`","credential_env":"K","credential_header":"X-Api-Key"}]}`),
		func(string) string { return "the-secret" })
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	gw, err := New(Options{Config: cfg, Auth: e.auth, Policy: e.gw.opt.Policy, Audit: e.auditLog, Pins: e.gw.opt.Pins,
		AuditKey: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	gw.Refresh(context.Background())
	if got.Get("X-Api-Key") != "the-secret" || got.Get("Authorization") != "" {
		t.Fatalf("credential headers %v", got)
	}
}

// BenchmarkToolCall measures one allowed tools/call end to end: agent HTTP
// request, authentication, policy, two fsynced audit records, the upstream
// round trip over HTTP, and the response.
func BenchmarkToolCall(b *testing.B) {
	e := newEnv(b)
	args := map[string]any{"text": "hello"}
	if r := e.call(bobKey, "fake.echo", args); r.status != 200 {
		b.Fatal(r.raw)
	}
	for b.Loop() {
		if r := e.call(bobKey, "fake.echo", args); r.status != 200 {
			b.Fatal(r.raw)
		}
	}
}

// BenchmarkToolCallDenied measures a call refused by an argument constraint
// (one audit record, no upstream round trip).
func BenchmarkToolCallDenied(b *testing.B) {
	e := newEnv(b, func(c *Config) { c.Agents[0].Limits = nil })
	args := map[string]any{"path": "../../etc/passwd"}
	for b.Loop() {
		if r := e.call(aliceKey, "fake.read_file", args); r.errCode() != mcp.CodePolicyDenied {
			b.Fatal(r.raw)
		}
	}
}

// BenchmarkToolCallParallel shows throughput with concurrent agents, where
// group commit shares fsyncs between calls.
func BenchmarkToolCallParallel(b *testing.B) {
	e := newEnv(b)
	args := map[string]any{"text": "hello"}
	b.SetParallelism(4)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if r := e.call(bobKey, "fake.echo", args); r.status != 200 {
				b.Error(r.raw)
				return
			}
		}
	})
}

// A call refused after its approval (here by the daily quota) must not use
// the approval up.
func TestApprovalNotWastedByLaterRefusal(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Agents[0].Limits.ToolRPS = 0; c.Agents[0].Limits.DailyQuota = 1 })
	args := map[string]any{"text": "hello", "language": "de"}
	id := e.call(aliceKey, "fake.translate", args, lang("de")).errData()["approval_id"].(string)
	e.admin("POST", "/admin/approvals/"+id+"/approve", `{}`)
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "use the quota"}); r.status != 200 {
		t.Fatal(r.raw)
	}
	if r := e.call(aliceKey, "fake.translate", args, lang("de")); r.errCode() != mcp.CodeQuotaExceeded {
		t.Fatalf("want quota refusal: %s", r.raw)
	}
	if r := e.admin("GET", "/admin/approvals/"+id, ""); r.body["status"] != "approved" {
		t.Fatalf("approval was used by a refused call: %s", r.raw)
	}
}

// A failed tool-list refresh is not retried by every caller in turn.
func TestRefreshBackoff(t *testing.T) {
	var hits atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(500)
	}))
	defer bad.Close()
	e := newEnv(t, func(c *Config) {
		c.Upstreams = append(c.Upstreams, UpstreamConfig{Name: "bad", URL: bad.URL, TimeoutMS: 500,
			MaxResponseBytes: 1024, MaxConcurrency: 1, ToolsTTLSeconds: 30})
	})
	for range 3 {
		if names := toolNames(e.rpc(bobKey, "tools/list", nil, nil)); len(names) != 1 {
			t.Fatalf("list: %v", names)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("failed upstream asked %d times within the backoff", n)
	}
	e.clk.add(refreshBackoff)
	e.rpc(bobKey, "tools/list", nil, nil)
	if n := hits.Load(); n != 2 {
		t.Fatalf("upstream not retried after the backoff: %d", n)
	}
}
