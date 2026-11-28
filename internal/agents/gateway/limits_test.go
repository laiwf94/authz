package gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/mcp"
	platformlimit "github.com/laiwf94/authz/internal/platform/ratelimit"
)

const limitsPolicy = `{"version":1,"rules":[
 {"id":"capped-echo","effect":"allow","agents":["alice-bot","bob-bot"],"upstreams":["fake"],"tools":["echo"],
  "limits":{"rate":1,"burst":2,"daily":3,"zone":"Europe/Berlin"}},
 {"id":"quota-echo","effect":"allow","agents":["quota-bot"],"upstreams":["fake"],"tools":["echo"],"limits":{"daily":1}},
 {"id":"files","effect":"allow","agents":["*"],"upstreams":["fake"],"tools":["read_file"]}
]}`

type limitsReply struct {
	Policy string `json:"policy"`
	Now    string `json:"now"`
	Rules  []struct {
		RuleID string `json:"rule_id"`
		Rate   *struct {
			PerSecond float64 `json:"per_second"`
			Burst     int     `json:"burst"`
			Agents    int     `json:"agents"`
			Exhausted int     `json:"exhausted"`
		} `json:"rate"`
		Daily *struct {
			Limit     int    `json:"limit"`
			Zone      string `json:"zone"`
			Agents    int    `json:"agents"`
			Exhausted int    `json:"exhausted"`
			Used      int    `json:"used"`
		} `json:"daily"`
		Agents []struct {
			Agent     string   `json:"agent"`
			Tokens    *float64 `json:"tokens"`
			FullInMs  *int64   `json:"full_in_ms"`
			Used      *int     `json:"used"`
			Remaining *int     `json:"remaining"`
			ResetsAt  string   `json:"resets_at"`
		} `json:"agents"`
		Omitted int `json:"agents_omitted"`
	} `json:"rules"`
}

func (e *env) limits(query string) limitsReply {
	e.t.Helper()
	r := e.admin("GET", "/admin/limits"+query, "")
	if r.status != http.StatusOK {
		e.t.Fatalf("GET /admin/limits%s: %d %s", query, r.status, r.raw)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		e.t.Errorf("Cache-Control %q", r.header.Get("Cache-Control"))
	}
	var out limitsReply
	if err := json.Unmarshal([]byte(r.raw), &out); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func TestAdminLimits(t *testing.T) {
	e := newEnv(t, noToolLimit)
	loc := berlin(t)
	// Monday 1 March 2027, 22:00 in Berlin (21:00 UTC); the day ends at
	// 23:00 UTC there and at midnight UTC for quota-echo.
	e.setClock(time.Date(2027, 3, 1, 22, 0, 0, 0, loc))
	writePolicy(t, e, limitsPolicy)
	echo := func(key string) reply { return e.call(key, "fake.echo", map[string]any{"text": "x"}) }

	// Before any call: both limited rules with no agents; the rule
	// without limits is not listed.
	got := e.limits("")
	if len(got.Rules) != 2 || got.Rules[0].RuleID != "capped-echo" || got.Rules[1].RuleID != "quota-echo" ||
		len(got.Rules[0].Agents) != 0 || got.Rules[0].Rate.Agents != 0 || got.Rules[1].Rate != nil ||
		got.Now != "2027-03-01T21:00:00Z" || got.Policy != e.gw.opt.Policy.Current().Hash {
		t.Fatalf("before any call: %+v", got)
	}
	if r := e.admin("GET", "/admin/limits", ""); !strings.Contains(r.raw, `"agents":[]`) {
		t.Fatalf("an empty agent list is not null: %s", r.raw)
	}

	for i := range 2 {
		if r := echo(aliceKey); r.text() != "x" {
			t.Fatalf("alice %d: %s", i, r.raw)
		}
	}
	if r := echo(bobKey); r.text() != "x" {
		t.Fatalf("bob: %s", r.raw)
	}
	if r := echo(quotaKey); r.text() != "x" {
		t.Fatalf("quota-bot: %s", r.raw)
	}
	// Agents calling under a rule without limits hold no rule state.
	if r := e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/q1.txt"}); r.errCode() != 0 {
		t.Fatalf("read_file: %s", r.raw)
	}

	got = e.limits("")
	c, q := got.Rules[0], got.Rules[1]
	if c.Rate == nil || c.Rate.PerSecond != 1 || c.Rate.Burst != 2 || c.Rate.Agents != 2 || c.Rate.Exhausted != 1 {
		t.Fatalf("capped-echo rate: %+v", c.Rate)
	}
	if c.Daily == nil || c.Daily.Limit != 3 || c.Daily.Zone != "Europe/Berlin" || c.Daily.Agents != 2 ||
		c.Daily.Exhausted != 0 || c.Daily.Used != 3 {
		t.Fatalf("capped-echo daily: %+v", c.Daily)
	}
	// Nearest to being refused first: alice has no token left.
	if len(c.Agents) != 2 || c.Agents[0].Agent != "alice-bot" || c.Agents[1].Agent != "bob-bot" {
		t.Fatalf("capped-echo agents: %+v", c.Agents)
	}
	a, b := c.Agents[0], c.Agents[1]
	if *a.Tokens != 0 || *a.FullInMs != 2000 || *a.Used != 2 || *a.Remaining != 1 || a.ResetsAt != "2027-03-01T23:00:00Z" {
		t.Fatalf("alice: tokens %v full in %v used %v remaining %v resets %s", *a.Tokens, *a.FullInMs, *a.Used, *a.Remaining, a.ResetsAt)
	}
	if *b.Tokens != 1 || *b.FullInMs != 1000 || *b.Used != 1 || *b.Remaining != 2 {
		t.Fatalf("bob: %+v", b)
	}
	if q.Rate != nil || q.Daily == nil || q.Daily.Limit != 1 || q.Daily.Zone != "UTC" || q.Daily.Exhausted != 1 ||
		len(q.Agents) != 1 || q.Agents[0].Tokens != nil || *q.Agents[0].Remaining != 0 ||
		q.Agents[0].ResetsAt != "2027-03-02T00:00:00Z" {
		t.Fatalf("quota-echo: %+v", q)
	}

	// Reading changes nothing: alice is still refused, once.
	again := e.limits("")
	if *again.Rules[0].Agents[0].Used != 2 || *again.Rules[0].Agents[0].Tokens != 0 {
		t.Fatalf("a second read: %+v", again.Rules[0].Agents[0])
	}
	if r := echo(aliceKey); r.errCode() != mcp.CodeRateLimited || r.errData()["rule_id"] != "capped-echo" {
		t.Fatalf("alice after the reads: %s", r.raw)
	}
	if r := echo(quotaKey); r.errCode() != mcp.CodeQuotaExceeded || r.errData()["rule_id"] != "quota-echo" {
		t.Fatalf("quota-bot's second call: %s", r.raw)
	}

	m := e.admin("GET", "/metrics", "").raw
	for _, line := range []string{
		`toolgate_rule_limit_agents{rule_id="capped-echo",limit="rate"} 2`,
		`toolgate_rule_limit_agents{rule_id="capped-echo",limit="daily"} 2`,
		`toolgate_rule_limit_exhausted{rule_id="capped-echo",limit="rate"} 1`,
		`toolgate_rule_limit_exhausted{rule_id="capped-echo",limit="daily"} 0`,
		`toolgate_rule_limit_daily_used{rule_id="capped-echo"} 3`,
		`toolgate_rule_limit_agents{rule_id="quota-echo",limit="daily"} 1`,
		`toolgate_rule_limit_exhausted{rule_id="quota-echo",limit="daily"} 1`,
		`toolgate_rule_limit_daily_used{rule_id="quota-echo"} 1`,
		`toolgate_rule_limit_refusals_total{rule_id="capped-echo",limit="rate"} 1`,
		`toolgate_rule_limit_refusals_total{rule_id="quota-echo",limit="daily"} 1`,
	} {
		if !strings.Contains(m, line+"\n") {
			t.Errorf("metrics lack %s", line)
		}
	}
	// No agent id is a label, and a rule has only the series of its limits.
	if strings.Contains(m, "alice-bot") || strings.Contains(m, `rule_id="quota-echo",limit="rate"`) ||
		strings.Contains(m, `rule_id="files"`) {
		t.Errorf("unexpected series:\n%s", m)
	}

	// Filters and the agent cut.
	got = e.limits("?rule=capped-echo&agent=bob-bot")
	if len(got.Rules) != 1 || len(got.Rules[0].Agents) != 1 || got.Rules[0].Agents[0].Agent != "bob-bot" ||
		got.Rules[0].Rate.Agents != 1 || got.Rules[0].Daily.Used != 1 {
		t.Fatalf("one rule, one agent: %+v", got)
	}
	got = e.limits("?agents=1")
	if len(got.Rules[0].Agents) != 1 || got.Rules[0].Agents[0].Agent != "alice-bot" || got.Rules[0].Omitted != 1 ||
		got.Rules[0].Rate.Agents != 2 {
		t.Fatalf("agents=1: %+v", got.Rules[0])
	}
	if got = e.limits("?agents=0"); len(got.Rules[0].Agents) != 0 || got.Rules[0].Omitted != 2 {
		t.Fatalf("agents=0: %+v", got.Rules[0])
	}
	if got = e.limits("?agent=nobody"); len(got.Rules) != 2 || len(got.Rules[0].Agents) != 0 || got.Rules[0].Rate.Agents != 0 {
		t.Fatalf("an agent with no state: %+v", got)
	}
	if got = e.limits("?rule=files"); len(got.Rules) != 0 {
		t.Fatalf("a rule without limits: %+v", got)
	}
	if r := e.admin("GET", "/admin/limits?rule=nope", ""); r.status != http.StatusNotFound || !strings.Contains(r.raw, `no rule \"nope\"`) {
		t.Fatalf("unknown rule: %d %s", r.status, r.raw)
	}
	for _, bad := range []string{"?agents=x", "?agents=-1", "?agents=1001", "?agents=01", "?agents=", "?limit=5",
		"?rule=a&rule=b", "?rule=", "?agent="} {
		if r := e.admin("GET", "/admin/limits"+bad, ""); r.status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, r.status, r.raw)
		}
	}
	req, _ := http.NewRequest("GET", e.adminURL+"/admin/limits", nil)
	if r := e.do(req); r.status != http.StatusUnauthorized {
		t.Fatalf("without the admin token: %d", r.status)
	}

	// Buckets refill: after two seconds alice's is full and only her
	// daily count holds her in the list.
	e.clk.add(2 * time.Second)
	got = e.limits("?rule=capped-echo")
	if got.Rules[0].Rate.Agents != 0 || *got.Rules[0].Agents[0].Tokens != 2 || *got.Rules[0].Agents[0].FullInMs != 0 {
		t.Fatalf("after two seconds: %+v", got.Rules[0])
	}

	// Changing the limits starts the counts afresh, and the old counts
	// are not reported; removing a rule removes its series.
	writePolicy(t, e, strings.Replace(strings.Replace(limitsPolicy, `"daily":3`, `"daily":4`, 1),
		`{"id":"quota-echo","effect":"allow","agents":["quota-bot"],"upstreams":["fake"],"tools":["echo"],"limits":{"daily":1}},`, "", 1))
	got = e.limits("")
	if len(got.Rules) != 1 || got.Rules[0].Daily.Limit != 4 || got.Rules[0].Daily.Used != 0 || len(got.Rules[0].Agents) != 0 {
		t.Fatalf("after changing the limits: %+v", got)
	}
	m = e.admin("GET", "/metrics", "").raw
	if strings.Contains(m, `toolgate_rule_limit_agents{rule_id="quota-echo"`) ||
		!strings.Contains(m, `toolgate_rule_limit_daily_used{rule_id="capped-echo"} 0`+"\n") {
		t.Fatalf("metrics after the reload:\n%s", m)
	}
	// Refusal counts stay, as counters do.
	if !strings.Contains(m, `toolgate_rule_limit_refusals_total{rule_id="quota-echo",limit="daily"} 1`) {
		t.Error("the refusal count went")
	}

	// A new day in Berlin clears the daily counts.
	if r := echo(aliceKey); r.text() != "x" {
		t.Fatalf("alice under the new limits: %s", r.raw)
	}
	if got = e.limits(""); *got.Rules[0].Agents[0].Used != 1 {
		t.Fatalf("one call under the new limits: %+v", got.Rules[0].Agents[0])
	}
	e.setClock(time.Date(2027, 3, 2, 0, 0, 0, 0, loc))
	if got = e.limits(""); len(got.Rules[0].Agents) != 0 || got.Rules[0].Daily.Agents != 0 {
		t.Fatalf("after midnight in Berlin: %+v", got.Rules[0])
	}
}

// A rule with only a rate limit has no daily fields and no daily series.
func TestAdminLimitsRateOnly(t *testing.T) {
	e := newEnv(t, noToolLimit)
	e.setClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	writePolicy(t, e, `{"version":1,"rules":[
	 {"id":"rate-only","effect":"allow","agents":["alice-bot"],"upstreams":["fake"],"tools":["echo"],"limits":{"rate":0.5,"burst":3}}]}`)
	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "x"}); r.text() != "x" {
		t.Fatal(r.raw)
	}
	got := e.limits("")
	r := got.Rules[0]
	if r.Daily != nil || len(r.Agents) != 1 || *r.Agents[0].Tokens != 2 || *r.Agents[0].FullInMs != 2000 ||
		r.Agents[0].Used != nil || r.Agents[0].ResetsAt != "" {
		t.Fatalf("rate only: %+v", r)
	}
	m := e.admin("GET", "/metrics", "").raw
	if strings.Contains(m, "toolgate_rule_limit_daily_used") || !strings.Contains(m, `toolgate_rule_limit_exhausted{rule_id="rate-only",limit="rate"} 0`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

// BenchmarkRuleLimitsScan is what a metrics scrape costs with 10,000
// agents holding state under a rule with both limits, next to 10,000
// agent and tool buckets that the scan passes over.
func BenchmarkRuleLimitsScan(b *testing.B) {
	e := newEnv(b, noToolLimit)
	if err := os.WriteFile(e.policyPath, []byte(limitsPolicy), 0o600); err != nil {
		b.Fatal(err)
	}
	if r := e.admin("POST", "/admin/policy/reload", ""); r.status != http.StatusOK {
		b.Fatal(r.raw)
	}
	p := e.gw.opt.Policy.Current()
	lim := p.Rules[0].Limits()
	for i := range 10_000 {
		agent := "agent-" + strconv.Itoa(i)
		e.gw.limiter.Take(lim.Key(agent), lim.Rate)
		e.gw.ruleQuota.Take(lim.Key(agent), lim.Daily, lim.Zone)
		e.gw.limiter.Take(platformlimit.Key("tool", agent, "fake.echo"), platformlimit.Limit{Rate: 1, Burst: 3})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rules := e.gw.scanRuleLimits(p, false, "", "")
		if rules[0].rateAgents != 10_000 || rules[0].dailyUsed != 10_000 {
			b.Fatalf("scan found %d agents, %d calls", rules[0].rateAgents, rules[0].dailyUsed)
		}
	}
}
