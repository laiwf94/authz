package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
)

type explainReply struct {
	Decision       string `json:"decision"`
	Rule           string `json:"rule"`
	Reason         string `json:"reason"`
	ConstraintRule string `json:"constraint_rule"`
	Hidden         bool   `json:"hidden"`
	Requires       bool   `json:"requires_approval"`
	At             *time.Time
	Outcome        string `json:"outcome"`
	Code           int    `json:"code"`
	Status         int    `json:"status"`
	ToolKnown      *bool  `json:"tool_known"`
	Policy         string `json:"policy"`
	Rules          []struct {
		Rule, Result, Reason string
		Selected, Constraint bool
		Check                *struct {
			Resource, Subject, Outcome, Error string
			Trace                             any
		}
	} `json:"rules"`
}

func (e *env) explain(body string) (reply, explainReply) {
	e.t.Helper()
	r := e.admin("POST", "/admin/explain", body)
	var ex explainReply
	if r.status == http.StatusOK {
		if err := json.Unmarshal([]byte(r.raw), &ex); err != nil {
			e.t.Fatal(err)
		}
	}
	return r, ex
}

func explainBody(agent, owner string, scopes []string, tool string, args map[string]any) string {
	call := map[string]any{"tool": tool}
	if args != nil {
		call["arguments"] = args
	}
	b, _ := json.Marshal(map[string]any{"subject": map[string]any{"agent": agent, "owner": owner, "scopes": scopes}, "call": call})
	return string(b)
}

// toolCallLines is the tool call and check metrics, which explaining must
// not move.
func (e *env) toolCallLines() string {
	e.t.Helper()
	var out []string
	for _, l := range strings.Split(e.admin("GET", "/metrics", "").raw, "\n") {
		if strings.HasPrefix(l, "toolgate_tool_calls_total") || strings.HasPrefix(l, "toolgate_relationship_checks_total") ||
			strings.HasPrefix(l, "toolgate_rate_limited_total") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// TestExplainAgreesWithCallTool explains calls and then makes them: the
// explanation says what the call gets, and explaining changes nothing.
func TestExplainAgreesWithCallTool(t *testing.T) {
	e := newEnv(t, noToolLimit)
	type who struct {
		key, agent, owner string
		scopes            []string
	}
	alice := who{aliceKey, "alice-bot", "alice", []string{"files:read"}}
	bob := alice
	bob.key, bob.agent, bob.owner, bob.scopes = bobKey, "bob-bot", "bob", nil

	// Before the upstream is listed, the gateway does not know its tools.
	if _, ex := e.explain(explainBody(alice.agent, alice.owner, alice.scopes, "fake.echo", nil)); ex.ToolKnown != nil || ex.Outcome != "allowed" {
		t.Fatalf("before listing: %+v", ex)
	}
	e.rpc(aliceKey, "tools/list", nil, nil)

	for _, c := range []struct {
		name    string
		who     who
		tool    string
		args    map[string]any
		outcome string
		code    int
		rule    string
	}{
		{"allowed", alice, "fake.echo", map[string]any{"text": "hi"}, "allowed", 0, "echo-all"},
		{"allowed with a schema", alice, "fake.read_file", map[string]any{"path": "reports/q1.txt"}, "allowed", 0, "files"},
		{"deny rule", alice, "fake.read_file", map[string]any{"path": "reports/.env"}, "denied", mcp.CodePolicyDenied, "no-env"},
		{"constraint", alice, "fake.read_file", map[string]any{"path": "../secret.txt"}, "denied", mcp.CodePolicyDenied, "default-deny"},
		{"hidden", bob, "fake.read_file", map[string]any{"path": "notes/a.md"}, "denied", jsonrpc.CodeInvalidParams, "default-deny"},
		{"unknown tool", alice, "fake.nope", nil, "unknown_tool", jsonrpc.CodeInvalidParams, "default-deny"},
		{"unknown upstream", alice, "other.tool", nil, "unknown_tool", jsonrpc.CodeInvalidParams, "default-deny"},
	} {
		t.Run(c.name, func(t *testing.T) {
			records, metrics := len(e.auditRecords()), e.toolCallLines()
			r, ex := e.explain(explainBody(c.who.agent, c.who.owner, c.who.scopes, c.tool, c.args))
			if r.status != http.StatusOK || ex.Outcome != c.outcome || ex.Code != c.code || ex.Rule != c.rule ||
				r.header.Get("Cache-Control") != "no-store" {
				t.Fatalf("explain: %d %s", r.status, r.raw)
			}
			if got := len(e.auditRecords()); got != records {
				t.Fatalf("explaining wrote %d audit records", got-records)
			}
			if got := e.toolCallLines(); got != metrics {
				t.Fatalf("explaining moved metrics:\n%s\n%s", metrics, got)
			}
			call := e.call(c.who.key, c.tool, c.args)
			if call.errCode() != c.code || call.status != ex.Status {
				t.Fatalf("call: %d %s, explained %+v", call.status, call.raw, ex)
			}
			if c.code == mcp.CodePolicyDenied && call.errData()["rule_id"] != ex.Rule {
				t.Fatalf("call denied by %v, explained %s", call.errData()["rule_id"], ex.Rule)
			}
		})
	}

	_, ex := e.explain(explainBody(alice.agent, alice.owner, alice.scopes, "fake.translate", map[string]any{"text": "x", "language": "de"}))
	if ex.Outcome != "allowed" || !ex.Requires || ex.Rule != "translate" {
		t.Fatalf("translate: %+v", ex)
	}
	if r := e.admin("GET", "/admin/approvals", ""); strings.Contains(r.raw, "translate") {
		t.Fatalf("explaining created an approval: %s", r.raw)
	}
	if _, ex := e.explain(explainBody(alice.agent, alice.owner, alice.scopes, "fake.read_file", map[string]any{"path": "../x"})); ex.ConstraintRule != "files" ||
		len(ex.Rules) != 5 || !ex.Rules[1].Constraint || ex.Rules[1].Result != "arguments_not_matched" {
		t.Fatalf("rules: %+v", ex)
	}
	// The time is the gateway's clock unless the call names one.
	if _, ex := e.explain(explainBody(alice.agent, alice.owner, alice.scopes, "fake.echo", nil)); ex.At == nil || !ex.At.Equal(e.clk.now()) {
		t.Fatalf("at %v, clock %v", ex.At, e.clk.now())
	}
	if _, ex := e.explain(`{"subject":{"agent":"a"},"call":{"tool":"fake.echo"},"now":"2026-12-05T10:00:00Z"}`); ex.At == nil ||
		!ex.At.Equal(time.Date(2026, 12, 5, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("at %v", ex.At)
	}

	// A quarantined tool is refused before the policy.
	e.fake.SetRugPull(true)
	e.clk.add(31 * time.Second)
	e.rpc(aliceKey, "tools/list", nil, nil)
	_, ex = e.explain(explainBody(alice.agent, alice.owner, alice.scopes, "fake.translate", map[string]any{"text": "x", "language": "de"}))
	if ex.Outcome != "quarantined" || ex.Code != mcp.CodeToolQuarantined || ex.Decision != "allow" {
		t.Fatalf("quarantined: %+v", ex)
	}
	if r := e.call(aliceKey, "fake.translate", map[string]any{"text": "x", "language": "de"}, lang("de")); r.errCode() != mcp.CodeToolQuarantined {
		t.Fatalf("call: %s", r.raw)
	}
}

func TestExplainInput(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("POST", e.adminURL+"/admin/explain", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if r := e.do(req); r.status != http.StatusUnauthorized {
		t.Fatalf("no token: %d", r.status)
	}
	req, _ = http.NewRequest("POST", e.adminURL+"/admin/explain", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "text/plain")
	if r := e.do(req); r.status != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d %s", r.status, r.raw)
	}
	for _, c := range []struct {
		body   string
		status int
		want   string
	}{
		{"  ", 400, "the body must be a call"},
		{`{"subject":{"agent":"a"}}`, 400, "with the tool and its arguments"},
		{`{"subject":{"agent":"a"},"call":{"tool":"fake.echo"},"bogus":1}`, 400, "unknown field"},
		{`{"subject":{"agent":"a"},"call":{"tool":"fake.echo"},"checks":{"project:p#edit@user:u":"allowed"}}`, 400, "leave it out"},
		{`{"subject":{"agent":"a"},"call":{"tool":"fake.echo"},"trace_nodes":100000}`, 400, "trace_nodes"},
		{`{"subject":{"agent":"a"},"call":{"tool":"fake.echo","arguments":{"s":"` + strings.Repeat("x", 1<<20) + `"}}}`, 413, ""},
	} {
		r := e.admin("POST", "/admin/explain", c.body)
		if r.status != c.status || !strings.Contains(r.raw, c.want) {
			t.Errorf("%.80s: %d %.200s", c.body, r.status, r.raw)
		}
	}
	if r := e.admin("GET", "/admin/explain", ""); r.status != http.StatusNotFound {
		t.Errorf("GET: %d", r.status)
	}
}

func TestExplainAsksTheEngine(t *testing.T) {
	f, err := enginetest.NewFake(checkTestSchema, "project:p1#editor@user:alice")
	if err != nil {
		t.Fatal(err)
	}
	var fail error
	e := newCheckEnv(t, func(context.Context) (engine.Engine, error) { return f, fail })
	e.rpc(aliceKey, "tools/list", nil, nil)
	metrics := e.toolCallLines()
	_, ex := e.explain(explainBody("alice-bot", "alice", nil, "fake.echo", map[string]any{"text": "p1"}))
	if ex.Outcome != "allowed" || ex.Rule != "echo-projects" || ex.Rules[0].Check == nil ||
		ex.Rules[0].Check.Resource != "project:p1" || ex.Rules[0].Check.Outcome != "allowed" {
		t.Fatalf("%+v", ex)
	}
	_, ex = e.explain(explainBody("alice-bot", "alice", nil, "fake.echo", map[string]any{"text": "p2"}))
	if ex.Outcome != "denied" || ex.Code != mcp.CodePolicyDenied || ex.ConstraintRule != "echo-projects" || ex.Rules[0].Result != "check_denied" {
		t.Fatalf("%+v", ex)
	}
	if got := e.toolCallLines(); got != metrics {
		t.Fatalf("explaining counted checks:\n%s\n%s", metrics, got)
	}
	fail = errors.New("engine down")
	_, ex = e.explain(explainBody("alice-bot", "alice", nil, "fake.echo", map[string]any{"text": "p1"}))
	if ex.Outcome != "check_unavailable" || ex.Code != mcp.CodeCheckUnavailable || ex.Status != http.StatusServiceUnavailable ||
		ex.Rules[0].Check == nil || ex.Rules[0].Check.Error != "engine down" {
		t.Fatalf("%+v", ex)
	}
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "p1"}); r.status != ex.Status || r.errCode() != ex.Code {
		t.Fatalf("call: %d %s", r.status, r.raw)
	}
}
