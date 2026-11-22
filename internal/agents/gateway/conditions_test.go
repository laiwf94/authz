package gateway

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/agents/policy"
)

// setClock moves the test clock to t, which must be later than it is.
func (e *env) setClock(t time.Time) {
	e.t.Helper()
	d := t.Sub(e.clk.now())
	if d < 0 {
		e.t.Fatalf("clock would go back to %v", t)
	}
	e.clk.add(d)
}

func berlin(t testing.TB) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// Windows and when expressions are decided at the gateway's clock, with the
// session facts of the agent's connection.
func TestRuleWindowsAndConditions(t *testing.T) {
	e := newEnv(t, noToolLimit)
	writePolicy(t, e, `{"version":1,"rules":[
	 {"id":"echo-office-hours","effect":"allow","agents":["alice-bot"],"upstreams":["fake"],"tools":["echo"],
	  "windows":[{"zone":"Europe/Berlin","days":["mon","tue","wed","thu","fri"],"from":"09:00","to":"17:00"}]},
	 {"id":"echo-static-only","effect":"allow","agents":["bob-bot"],"upstreams":["fake"],"tools":["echo"],
	  "when":"session.auth == 'static' && session.protocol != '' && args.text.size() < 5"}
	]}`)
	loc := berlin(t)
	// Monday 1 March 2027, 16:30 in Berlin (UTC+1).
	e.setClock(time.Date(2027, 3, 1, 16, 30, 0, 0, loc))
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.text() != "hi" {
		t.Fatalf("inside the window: %s", r.raw)
	}
	e.clk.add(30 * time.Minute) // 17:00
	r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"})
	if r.errCode() != mcp.CodePolicyDenied || r.errData()["rule_id"] != "default-deny" ||
		!strings.Contains(r.raw, "rule echo-office-hours applies only mon,tue,wed,thu,fri 09:00-17:00 Europe/Berlin") {
		t.Fatalf("after the window: %s", r.raw)
	}
	// Monday 29 March 2027, 16:30 in Berlin is 14:30 UTC (summer time):
	// the same UTC time as before the change is now outside.
	e.setClock(time.Date(2027, 3, 29, 15, 30, 0, 0, time.UTC))
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"}); r.errCode() != mcp.CodePolicyDenied {
		t.Fatalf("17:30 summer time: %s", r.raw)
	}
	if r := e.call(bobKey, "fake.echo", map[string]any{"text": "abc"}); r.text() != "abc" {
		t.Fatalf("bob with a static key: %s", r.raw)
	}
	if r := e.call(bobKey, "fake.echo", map[string]any{"text": "too long"}); r.errCode() != mcp.CodePolicyDenied ||
		!strings.Contains(r.raw, "condition of rule echo-static-only is false") {
		t.Fatalf("bob, long text: %s", r.raw)
	}
	var reasons []string
	for _, rec := range e.auditRecords() {
		if d := recordData(t, rec); rec.Event == "tool_call" && d["outcome"] == "denied" {
			reasons = append(reasons, d["reason"].(string))
		}
	}
	if len(reasons) != 3 || !strings.Contains(reasons[0], "applies only") || !strings.Contains(reasons[2], "is false") {
		t.Fatalf("audit reasons %q", reasons)
	}
}

const ruleLimitPolicy = `{"version":1,"rules":[
 {"id":"capped-echo","effect":"allow","agents":["alice-bot","bob-bot"],"upstreams":["fake"],"tools":["echo"],
  "limits":{"rate":1,"burst":2,"daily":3,"zone":"Europe/Berlin"}%s}
]}`

func TestRuleLimits(t *testing.T) {
	e := newEnv(t, noToolLimit)
	loc := berlin(t)
	e.setClock(time.Date(2027, 3, 1, 22, 0, 0, 0, loc))
	writePolicy(t, e, strings.Replace(ruleLimitPolicy, "%s", "", 1))
	echo := func(key string) reply { return e.call(key, "fake.echo", map[string]any{"text": "x"}) }
	for i := range 2 {
		if r := echo(aliceKey); r.text() != "x" {
			t.Fatalf("burst call %d: %s", i, r.raw)
		}
	}
	r := echo(aliceKey)
	if r.status != http.StatusTooManyRequests || r.errCode() != mcp.CodeRateLimited || r.errData()["scope"] != "rule" ||
		r.errData()["rule_id"] != "capped-echo" || r.header.Get("Retry-After") != "1" {
		t.Fatalf("rule rate limit: %d %s", r.status, r.raw)
	}
	// Each agent has its own counts under the rule.
	if r := echo(bobKey); r.text() != "x" {
		t.Fatalf("bob: %s", r.raw)
	}
	e.clk.add(time.Second)
	if r := echo(aliceKey); r.text() != "x" {
		t.Fatalf("third call of the day: %s", r.raw)
	}
	e.clk.add(5 * time.Second)
	r = echo(aliceKey)
	if r.status != http.StatusTooManyRequests || r.errCode() != mcp.CodeQuotaExceeded || r.errData()["rule_id"] != "capped-echo" {
		t.Fatalf("rule quota: %d %s", r.status, r.raw)
	}
	// Midnight in Berlin is 2h minus 6s away.
	if ra, _ := strconv.Atoi(r.header.Get("Retry-After")); ra != 2*3600-6 {
		t.Fatalf("Retry-After %q, want %d", r.header.Get("Retry-After"), 2*3600-6)
	}

	// A reload that changes the rule but not its limits keeps the counts.
	writePolicy(t, e, strings.Replace(ruleLimitPolicy, "%s", `,"description":"still capped"`, 1))
	if r := echo(aliceKey); r.errCode() != mcp.CodeQuotaExceeded {
		t.Fatalf("after a reload with the same limits: %s", r.raw)
	}
	// Changing the limits starts the rule's counts afresh.
	writePolicy(t, e, strings.Replace(strings.Replace(ruleLimitPolicy, `"daily":3`, `"daily":4`, 1), "%s", "", 1))
	if r := echo(aliceKey); r.text() != "x" {
		t.Fatalf("after changing the limits: %s", r.raw)
	}
	if r := echo(aliceKey); r.text() != "x" {
		t.Fatalf("second call under the new limits: %s", r.raw)
	}
	e.clk.add(time.Second)
	// The day ends at midnight in Berlin.
	e.setClock(time.Date(2027, 3, 2, 0, 0, 0, 0, loc))
	for i := range 2 {
		if r := echo(aliceKey); r.text() != "x" {
			t.Fatalf("new day, call %d: %s", i, r.raw)
		}
	}

	var scopes []string
	for _, rec := range e.auditRecords() {
		if d := recordData(t, rec); rec.Event == "tool_call" && d["outcome"] != "ok" && d["stage"] == "refused" {
			scopes = append(scopes, d["outcome"].(string))
		}
	}
	if strings.Join(scopes, ",") != "rate_limited,quota_exceeded,quota_exceeded" {
		t.Fatalf("refusals %v", scopes)
	}
	if m := e.admin("GET", "/metrics", "").raw; !strings.Contains(m, `toolgate_rate_limited_total{scope="rule"} 1`) {
		t.Error("metrics lack the rule rate limit")
	}
}

// A call refused after its quota was counted gives back the rule's count
// as well as the agent's.
func TestRuleQuotaRefund(t *testing.T) {
	e := newEnv(t, noToolLimit)
	writePolicy(t, e, `{"version":1,"rules":[
	 {"id":"capped-echo","effect":"allow","agents":["alice-bot"],"upstreams":["fake"],"tools":["echo"],"limits":{"daily":5}}]}`)
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "x"}); r.text() != "x" {
		t.Fatal(r.raw)
	}
	d := e.gw.opt.Policy.Current().Evaluate(policy.Subject{AgentID: "alice-bot"}, "fake", "echo", nil)
	key := d.Limits.Key("alice-bot")
	if n, _ := e.gw.ruleQuota.Used(key); n != 1 {
		t.Fatalf("used %d", n)
	}
	e.auditLog.Close()
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "x"}); r.errCode() != mcp.CodeAuditUnavailable {
		t.Fatal(r.raw)
	}
	if n, _ := e.gw.ruleQuota.Used(key); n != 1 {
		t.Fatalf("after a refused call: used %d, want 1", n)
	}
}
