package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
)

// decisionText is a Decision as text, its checks by their String, so that
// two decisions with equal errors of different identity compare equal.
func decisionText(d Decision) string {
	checks := make([]string, len(d.Checks))
	for i, c := range d.Checks {
		checks[i] = fmt.Sprintf("%s %s cached=%v err=%v", c.RuleID, c.String(), c.Cached, c.Err)
	}
	d.Checks = nil
	return fmt.Sprintf("%+v %v", d, checks)
}

// TestExplainAgreesWithDecide decides many calls under policies with
// argument schemas, relationship checks, windows and when expressions,
// with and without an engine: Explain gives exactly DecideAt's decision,
// lists every rule for the upstream once, deny rules first, and marks the
// rule the decision names and the constraint rule.
func TestExplainAgreesWithDecide(t *testing.T) {
	eng := fakeEngine(t, "project:p1#editor@user:alice", "project:p3#editor@user:alice", "project:p3#frozen@user:*",
		"project:p-7#editor@user:ci-bot")
	engines := map[string]CheckEngine{"engine": eng.get, "none": nil,
		"failing": func(context.Context) (Checker, error) { return nil, errors.New("engine down") }}
	subjects := []Subject{
		{AgentID: "alice-bot", Owner: "alice", Scopes: []string{"files:read"}},
		{AgentID: "carol-bot", Owner: "carol"},
		{AgentID: "ci-bot", Owner: "team-ops", Scopes: []string{"ops:deploy"}, Session: Session{Auth: "signed", Protocol: "2025-06-18"}},
		{AgentID: "ci-bot", Session: Session{Protocol: "2024-11-05"}},
	}
	argSets := []string{`{}`, `{"project":"p1"}`, `{"project":"p3"}`, `{"project":"p1","target":{"project":"p1"}}`,
		`{"n":7}`, `{"env":"prod","count":3}`, `{"env":"staging","count":30}`, `{"path":"reports/q1.txt"}`, `{"path":"a/.env"}`,
		`{"project":"two words"}`}
	times := []time.Time{{}, at(t, "2026-12-04T10:00:00+01:00"), at(t, "2026-12-04T23:30:00+01:00"), at(t, "2026-12-05T10:00:00+01:00")}
	extra := `{"version":1,"rules":[{"id":"elsewhere","effect":"allow","agents":["*"],"upstreams":["other"],"tools":["*"]}]}`
	policies := map[string]*Policy{"check": mustParse(t, checkPolicy), "when": mustParse(t, whenPolicy),
		"window": mustParse(t, windowPolicy), "example": mustParse(t, example), "extra": mustParse(t, extra)}
	tools := []ToolRef{{"fs", "write_file"}, {"fs", "rename"}, {"fs", "read_file"}, {"fs", "nope"}, {"ops", "deploy"},
		{"ops", "report"}, {"fake", "read_file"}, {"fake", "echo"}, {"other", "x"}}
	ctx := context.Background()
	n := 0
	for pname, p := range policies {
		for ename, get := range engines {
			for _, s := range subjects {
				for _, tool := range tools {
					for _, a := range argSets {
						for _, now := range times {
							args := args(t, a)
							want := p.DecideAt(ctx, now, s, tool.Upstream, tool.Tool, args, get)
							got, ex := p.Explain(ctx, now, s, tool.Upstream, tool.Tool, args, get, 0)
							where := fmt.Sprintf("%s/%s %s %s %s at %v", pname, ename, s.AgentID, tool, a, now)
							if decisionText(got) != decisionText(want) {
								t.Fatalf("%s:\nexplain %s\ndecide  %s", where, decisionText(got), decisionText(want))
							}
							checkExplanation(t, where, p, got, ex)
							n++
						}
					}
				}
			}
		}
	}
	t.Logf("%d calls explained", n)
}

func checkExplanation(t *testing.T, where string, p *Policy, d Decision, ex *Explanation) {
	t.Helper()
	if ex.Rule != d.RuleID || ex.Reason != d.Reason || ex.ConstraintRule != d.ConstraintRuleID ||
		ex.Unavailable != d.Unavailable || (ex.Decision == "allow") != d.Allowed || ex.Policy != p.Hash {
		t.Fatalf("%s: explanation %+v does not state the decision %+v", where, ex, d)
	}
	cands := p.candidates(ex.Upstream)
	if len(ex.Rules) != len(cands) || ex.OtherUpstreams != len(p.Rules)-len(cands) {
		t.Fatalf("%s: %d rules and %d elsewhere, want %d of %d", where, len(ex.Rules), ex.OtherUpstreams, len(cands), len(p.Rules))
	}
	selected, constraint, sawAllow, reached := 0, 0, false, 0
	for _, r := range ex.Rules {
		if r.Effect == Allow {
			sawAllow = true
		} else if sawAllow {
			t.Fatalf("%s: deny rule %s listed after an allow rule", where, r.Rule)
		}
		if r.Selected {
			selected++
			if r.Rule != d.RuleID || r.Result == ResultNotReached {
				t.Fatalf("%s: selected %+v", where, r)
			}
			if r.Effect == Allow && r.Result != ResultMatched {
				t.Fatalf("%s: allowed by %+v", where, r)
			}
		}
		if r.Constraint {
			constraint++
			if r.Rule != d.ConstraintRuleID || r.Effect != Allow || r.Result == ResultMatched || r.Result == ResultNotReached {
				t.Fatalf("%s: constraint %+v", where, r)
			}
		}
		if r.Result != ResultNotReached {
			reached++
		}
		if (r.Check != nil) != strings.HasPrefix(r.Result, ResultCheckPrefix) && r.Result != ResultMatched {
			t.Fatalf("%s: check %+v", where, r)
		}
	}
	if want := btoi(d.RuleID != DefaultDenyID); selected != want {
		t.Fatalf("%s: %d rules selected, want %d", where, selected, want)
	}
	if want := btoi(d.ConstraintRuleID != ""); constraint != want {
		t.Fatalf("%s: %d constraint rules, want %d", where, constraint, want)
	}
	// After the rule that decided, nothing is reached.
	if d.RuleID != DefaultDenyID {
		after := false
		for _, r := range ex.Rules {
			if after && r.Result != ResultNotReached {
				t.Fatalf("%s: %s reached after %s decided", where, r.Rule, d.RuleID)
			}
			after = after || r.Selected
		}
	} else if reached != len(ex.Rules) {
		t.Fatalf("%s: a default deny reached only %d of %d rules", where, reached, len(ex.Rules))
	}
	var checks int
	for _, r := range ex.Rules {
		if r.Check != nil {
			checks++
		}
	}
	if checks != len(d.Checks) {
		t.Fatalf("%s: %d checks in the rules, %d made", where, checks, len(d.Checks))
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func results(ex *Explanation) []string {
	out := make([]string, len(ex.Rules))
	for i, r := range ex.Rules {
		out[i] = r.Rule + "=" + r.Result
		if r.Selected {
			out[i] += "*"
		}
		if r.Constraint {
			out[i] += "!"
		}
	}
	return out
}

func TestExplainRuleResults(t *testing.T) {
	ctx := context.Background()
	eng := fakeEngine(t, "project:p1#editor@user:alice", "project:p3#editor@user:alice", "project:p3#frozen@user:*")
	cp := mustParse(t, checkPolicy)
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	carol := Subject{AgentID: "carol-bot", Owner: "carol"}

	t.Run("deny rule check holds", func(t *testing.T) {
		_, ex := cp.Explain(ctx, time.Time{}, alice, "fs", "write_file", args(t, `{"project":"p3"}`), eng.get, 0)
		want := []string{"frozen=matched*", "edit-projects=not_reached", "team-files=not_reached", "agent-edit=not_reached", "read=not_reached"}
		if got := results(ex); !slices.Equal(got, want) {
			t.Fatalf("%v, want %v", got, want)
		}
		if c := ex.Rules[0].Check; c == nil || c.Resource != "project:p3" || c.Permission != "frozen" || c.Subject != "user:alice" ||
			c.Outcome != CheckAllowed || c.Revision == 0 || c.Cached || c.Trace != nil {
			t.Fatalf("check %+v", c)
		}
	})
	t.Run("default deny names the constraint", func(t *testing.T) {
		_, ex := cp.Explain(ctx, time.Time{}, carol, "fs", "write_file", args(t, `{"project":"p1"}`), eng.get, 0)
		want := []string{"frozen=check_denied", "edit-projects=check_denied!", "team-files=tool_not_matched",
			"agent-edit=subject_not_matched", "read=tool_not_matched"}
		if got := results(ex); !slices.Equal(got, want) {
			t.Fatalf("%v, want %v", got, want)
		}
		if r := ex.Rules[1]; r.Reason != "denied: project:p1#edit@user:carol" {
			t.Fatalf("reason %q", r.Reason)
		}
		if ex.Hidden || !ex.Visible || ex.Decision != "deny" {
			t.Fatalf("%+v", ex)
		}
	})
	t.Run("identical check is cached", func(t *testing.T) {
		_, ex := cp.Explain(ctx, time.Time{}, carol, "fs", "rename", args(t, `{"project":"p1","target":{"project":"p1"}}`), eng.get, 0)
		want := []string{"frozen=tool_not_matched", "edit-projects=check_denied!", "team-files=check_denied",
			"agent-edit=subject_not_matched", "read=tool_not_matched"}
		if got := results(ex); !slices.Equal(got, want) {
			t.Fatalf("%v, want %v", got, want)
		}
		if ex.Rules[1].Check.Cached || !ex.Rules[2].Check.Cached {
			t.Fatalf("cache: %+v %+v", ex.Rules[1].Check, ex.Rules[2].Check)
		}
	})
	t.Run("deny rule fails closed on bad input", func(t *testing.T) {
		_, ex := cp.Explain(ctx, time.Time{}, alice, "fs", "write_file", args(t, `{}`), eng.get, 0)
		r := ex.Rules[0]
		if !r.Selected || r.Result != "check_bad_input" || !strings.Contains(r.Reason, "counts that as allowed") ||
			r.Check.Error == "" || r.Check.Outcome != CheckBadInput {
			t.Fatalf("%+v %+v", r, r.Check)
		}
	})
	t.Run("no engine", func(t *testing.T) {
		_, ex := cp.Explain(ctx, time.Time{}, alice, "fs", "write_file", args(t, `{"project":"p1"}`), nil, 0)
		if r := ex.Rules[0]; !ex.Unavailable || !r.Selected || r.Result != "check_unavailable" ||
			!strings.Contains(r.Check.Error, "no authorization engine") {
			t.Fatalf("%+v %+v", ex, r)
		}
	})
	t.Run("arguments", func(t *testing.T) {
		_, ex := mustParse(t, example).Explain(ctx, time.Time{}, Subject{AgentID: "alice-bot", Scopes: []string{"files:read"}},
			"fs", "read_file", args(t, `{"path":"/etc/passwd"}`), nil, 0)
		var got []string
		for _, r := range ex.Rules {
			if r.Result == ResultArgumentsNotMatched {
				got = append(got, r.Rule+": "+r.Reason)
			}
		}
		if len(got) != 2 || !strings.HasPrefix(got[0], "no-secrets: ") || got[1] != "fs-read: $.path: path is outside the allowed directories" {
			t.Fatalf("%v\n%v", got, results(ex))
		}
	})
	wp := mustParse(t, windowPolicy)
	ci := Subject{AgentID: "ci-bot"}
	t.Run("windows at an unknown time", func(t *testing.T) {
		_, ex := wp.Explain(ctx, time.Time{}, ci, "ops", "deploy", args(t, `{"env":"prod"}`), nil, 0)
		r := ex.Rules[0]
		if !r.Selected || r.Result != ResultConditionsUnknown || !strings.Contains(r.Reason, "time of the call is unknown") || ex.At != nil {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("windows", func(t *testing.T) {
		now := at(t, "2026-12-04T10:00:00+01:00") // a Friday
		_, ex := wp.Explain(ctx, now, ci, "ops", "deploy", args(t, `{"env":"prod"}`), nil, 0)
		want := []string{"no-deploy-friday-night=conditions_false", "deploy-office-hours=matched*", "deploy-staging=not_reached"}
		if got := results(ex); !slices.Equal(got, want) || ex.At == nil || !ex.At.Equal(now) {
			t.Fatalf("%v, want %v (at %v)", got, want, ex.At)
		}
		if !strings.Contains(ex.Rules[0].Reason, "applies only") {
			t.Fatalf("reason %q", ex.Rules[0].Reason)
		}
		_, ex = wp.Explain(ctx, at(t, "2026-12-05T10:00:00+01:00"), ci, "ops", "deploy", args(t, `{"env":"prod"}`), nil, 0)
		want = []string{"no-deploy-friday-night=conditions_false", "deploy-office-hours=conditions_false!", "deploy-staging=conditions_false"}
		if got := results(ex); !slices.Equal(got, want) {
			t.Fatalf("saturday: %v, want %v", got, want)
		}
	})
	t.Run("when", func(t *testing.T) {
		s := Subject{AgentID: "a1", Owner: "team-ops", Scopes: []string{"ops:deploy"}, Session: Session{Auth: "signed", Protocol: "2025-06-18"}}
		_, ex := mustParse(t, whenPolicy).Explain(ctx, time.Time{}, s, "ops", "report", args(t, `{}`), nil, 0)
		// At an unknown time the allow rule that reads now cannot hold.
		want := []string{"no-prod-unsigned=conditions_false", "old-protocol=conditions_false",
			"small-batches=tool_not_matched", "berlin-mornings=conditions_unknown!"}
		if got := results(ex); !slices.Equal(got, want) {
			t.Fatalf("%v, want %v", got, want)
		}
	})
	t.Run("hidden, other upstreams, limits and result rules", func(t *testing.T) {
		p := mustParse(t, `{"version":1,"rules":[
		 {"id":"elsewhere","effect":"allow","agents":["*"],"upstreams":["other"],"tools":["*"]},
		 {"id":"search","effect":"allow","agents":["a"],"upstreams":["web"],"tools":["search"],
		  "limits":{"rate":2,"burst":4,"daily":100,"zone":"Europe/Berlin"},"requires_approval":true,
		  "output":{"deny":["github_token"],"deny_patterns":["secret-[0-9]+"]}}]}`)
		_, ex := p.Explain(ctx, time.Time{}, Subject{AgentID: "b"}, "web", "search", nil, nil, 0)
		if !ex.Hidden || ex.Visible || ex.OtherUpstreams != 1 || len(ex.Rules) != 1 || ex.Rules[0].Result != ResultSubjectNotMatched {
			t.Fatalf("%+v", ex)
		}
		_, ex = p.Explain(ctx, time.Time{}, Subject{AgentID: "a"}, "web", "search", nil, nil, 0)
		if ex.Hidden || !ex.RequiresApproval || ex.Limits != "2/s burst 4, 100 a day (Europe/Berlin)" ||
			!slices.Equal(ex.ResultDenies, []string{"github_token", "deny_patterns[0]"}) {
			t.Fatalf("%+v", ex)
		}
	})
}

// explainingEngine is an Explainer that records how it was asked.
type explainingEngine struct {
	checks, explains int
	nodes            []int
}

func (e *explainingEngine) Check(context.Context, engine.CheckRequest) (engine.CheckResult, error) {
	e.checks++
	return engine.CheckResult{Allowed: true, Permissionship: check.Allowed}, nil
}

func (e *explainingEngine) Explain(_ context.Context, req engine.CheckRequest, maxNodes int) (engine.CheckResult, *check.Trace, error) {
	e.explains++
	e.nodes = append(e.nodes, maxNodes)
	root := &check.TraceNode{Kind: check.KindPermission, Object: req.ResourceType + ":" + req.ResourceID, Relation: req.Permission}
	return engine.CheckResult{Allowed: true, Permissionship: check.Allowed, At: engine.Snapshot{Revision: 9}},
		&check.Trace{Root: root, Nodes: 1, Truncated: true}, nil
}

func TestExplainAsksAnExplainer(t *testing.T) {
	p := mustParse(t, checkPolicy)
	e := &explainingEngine{}
	get := func(context.Context) (Checker, error) { return e, nil }
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	a := args(t, `{"project":"p1"}`)
	// Deciding checks; only explaining explains.
	if d := p.Decide(context.Background(), alice, "fs", "write_file", a, get); d.RuleID != "frozen" || e.checks != 1 || e.explains != 0 {
		t.Fatalf("decide: %+v, %d checks, %d explains", d, e.checks, e.explains)
	}
	for _, n := range []int{0, 5, MaxExplainTraceNodes + 1} {
		_, ex := p.Explain(context.Background(), time.Time{}, alice, "fs", "write_file", a, get, n)
		c := ex.Rules[0].Check
		if c == nil || c.Trace == nil || c.Trace.Nodes != 1 || !c.Trace.Truncated || c.Revision != 9 ||
			c.Trace.Root.Object != "project:p1" || c.Trace.Root.Relation != "frozen" {
			t.Fatalf("trace %+v", c)
		}
	}
	if e.checks != 1 || !slices.Equal(e.nodes, []int{DefaultExplainTraceNodes, 5, MaxExplainTraceNodes}) {
		t.Fatalf("%d checks, explained with bounds %v", e.checks, e.nodes)
	}
	b, err := json.Marshal(mustExplain(t, p, alice, get))
	if err != nil || !strings.Contains(string(b), `"trace":{"root":{"kind":"permission","object":"project:p1","relation":"frozen"`) {
		t.Fatalf("%s %v", b, err)
	}
}

func mustExplain(t *testing.T, p *Policy, s Subject, get CheckEngine) *Explanation {
	t.Helper()
	_, ex := p.Explain(context.Background(), time.Time{}, s, "fs", "write_file", args(t, `{"project":"p1"}`), get, 0)
	return ex
}

// The untraced path allocates exactly what it allocated before the
// collector existed, measured on the parent commit: an allow over plain
// rules only its reason, a denial no rule matched nothing at all, however
// many rules are passed over, and one over an argument schema only what
// the schema's validation and the reason do.
func TestDecideUntracedAllocations(t *testing.T) {
	p := benchPolicy(t)
	ctx := context.Background()
	plain := map[string]any{"x": "y"}
	a := args(t, `{"path":"/sandbox/reports/q1.csv"}`)
	for _, c := range []struct {
		name       string
		s          Subject
		up, tool   string
		args       any
		allowed    bool
		wantAllocs float64
	}{
		{"allow over plain rules", Subject{AgentID: "agent-150"}, "up0", "tool_150", plain, true, 1},
		{"no rule matches", Subject{AgentID: "nobody"}, "up0", "tool_150", plain, false, 0},
		{"allow over a schema", Subject{AgentID: "alice", Scopes: []string{"files:read"}}, "fs", "read_file", a, true, 3},
	} {
		n := testing.AllocsPerRun(200, func() {
			if p.DecideAt(ctx, time.Time{}, c.s, c.up, c.tool, c.args, nil).Allowed != c.allowed {
				t.Fatal(c.name)
			}
		})
		if n != c.wantAllocs {
			t.Errorf("%s: %v allocations untraced, want %v", c.name, n, c.wantAllocs)
		}
		if n := testing.AllocsPerRun(20, func() { p.Explain(ctx, time.Time{}, c.s, c.up, c.tool, c.args, nil, 0) }); n <= c.wantAllocs {
			t.Errorf("%s: an explanation allocates %v: is the collector on?", c.name, n)
		}
	}
}

// benchPolicy is BenchmarkEvaluate's policy: 200 plain rules over ten
// upstreams and one rule with an argument schema.
func benchPolicy(t testing.TB) *Policy {
	var rules []string
	for i := range 200 {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","effect":"allow","agents":["agent-%d"],"upstreams":["up%d"],"tools":["tool_%d"]}`, i, i, i%10, i))
	}
	rules = append(rules, `{"id":"fs-read","effect":"allow","scopes":["files:read"],"upstreams":["fs"],"tools":["read_file"],
	  "arguments":{"type":"object","required":["path"],"properties":{"path":{"type":"string","x-path-prefix":["/sandbox"]}}}}`)
	return mustParse(t, `{"version":1,"rules":[`+strings.Join(rules, ",")+`]}`)
}

// BenchmarkExplain compares deciding a call with explaining it, over the
// policy of BenchmarkEvaluate. untraced is DecideAt with the collector
// off; it is the path every tools/call takes.
func BenchmarkExplain(b *testing.B) {
	p := benchPolicy(b)
	ctx := context.Background()
	s := Subject{AgentID: "agent-150"}
	plain := map[string]any{"x": "y"}
	reader := Subject{AgentID: "alice", Scopes: []string{"files:read"}}
	a := args(b, `{"path":"/sandbox/reports/q1.csv"}`)
	b.Run("untraced/plain", func(b *testing.B) {
		for b.Loop() {
			p.DecideAt(ctx, time.Time{}, s, "up0", "tool_150", plain, nil)
		}
	})
	b.Run("traced/plain", func(b *testing.B) {
		for b.Loop() {
			p.Explain(ctx, time.Time{}, s, "up0", "tool_150", plain, nil, 0)
		}
	})
	b.Run("untraced/schema", func(b *testing.B) {
		for b.Loop() {
			p.DecideAt(ctx, time.Time{}, reader, "fs", "read_file", a, nil)
		}
	})
	b.Run("traced/schema", func(b *testing.B) {
		for b.Loop() {
			p.Explain(ctx, time.Time{}, reader, "fs", "read_file", a, nil, 0)
		}
	})
}

func TestParseCall(t *testing.T) {
	c, err := ParseCall([]byte(`{"subject":{"agent":"alice-bot","owner":"alice","scopes":["files:read"],"session":{"auth":"signed"}},
	  "call":{"tool":"fs.write_file","arguments":{"project":"p1","n":3}},"now":"2026-12-05T10:00:00+01:00",
	  "checks":{"project:p1#edit@user:alice":"allowed"},"trace_nodes":200}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.AgentID != "alice-bot" || c.Subject.Owner != "alice" || c.Subject.Session.Auth != "signed" ||
		c.Tool != (ToolRef{"fs", "write_file"}) || c.Now.IsZero() || c.TraceNodes != 200 || c.Checks["project:p1#edit@user:alice"] != "allowed" {
		t.Fatalf("%+v", c)
	}
	if n, ok := c.Arguments.(map[string]any)["n"].(json.Number); !ok || n != "3" {
		t.Fatalf("arguments %#v", c.Arguments)
	}
	d, ex := mustParse(t, checkPolicy).ExplainCall(c)
	if !d.Allowed || d.RuleID != "edit-projects" || ex.Rules[0].Result != "check_denied" {
		t.Fatalf("%+v\n%v", d, results(ex))
	}
	c, err = ParseCall([]byte(`{"subject":{"agent":"a"},"call":{"tool":"u.t"}}`))
	if err != nil || c.Arguments != nil || !c.Now.IsZero() || c.Checks != nil {
		t.Fatalf("%+v %v", c, err)
	}

	for _, tc := range []struct{ src, want string }{
		{`{"subject":{"agent":"a"}}`, `"call" with the tool`},
		{`{"subject":{"agent":""},"call":{"tool":"u.t"}}`, "not a valid agent id"},
		{`{"subject":{"agent":"a","scopes":["*"]},"call":{"tool":"u.t"}}`, "scope"},
		{`{"subject":{"agent":"a"},"call":{"tool":"nodot"}}`, "upstream.tool"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t","arguments":[1]}}`, "must be an object"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"},"now":"tomorrow"}`, "RFC 3339"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"},"checks":{"bad":"allowed"}}`, "type:id#permission@subject"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"},"checks":{"p:1#e@user:x":"yes"}}`, `must be "allowed"`},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"},"trace_nodes":-1}`, "trace_nodes"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"},"trace_nodes":10001}`, "trace_nodes"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"},"expect":{}}`, "unknown field"},
		{`{"subject":{"agent":"a"},"subject":{"agent":"b"},"call":{"tool":"u.t"}}`, "duplicate"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t"}} {}`, "after the JSON value"},
		{`{"subject":{"agent":"a","owner":"x\u0001"},"call":{"tool":"u.t"}}`, "owner"},
		{`[]`, "call:"},
		{`{"subject":{"agent":"a"},"call":{"tool":"u.t","arguments":{"s":"` + strings.Repeat("x", MaxCallBytes) + `"}}}`, "larger than"},
	} {
		if _, err := ParseCall([]byte(tc.src)); err == nil || !strings.Contains(err.Error(), tc.want) {
			src := tc.src
			if len(src) > 100 {
				src = src[:100]
			}
			t.Errorf("%s: %v, want %q", src, err, tc.want)
		}
	}
}

func TestExplanationText(t *testing.T) {
	c, err := ParseCall([]byte(`{"subject":{"agent":"carol-bot","owner":"carol"},
	  "call":{"tool":"fs.rename","arguments":{"project":"p1","target":{"project":"p1"}}},"now":"2026-12-05T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, ex := mustParse(t, checkPolicy).ExplainCall(c)
	var b bytes.Buffer
	ex.WriteText(&b)
	for _, want := range []string{
		"fs.rename: deny by default-deny\n",
		"  reason: relationship check of rule edit-projects is denied: project:p1#edit@user:carol\n",
		"  constraint rule: edit-projects\n",
		"  at: 2026-12-05T10:00:00Z\n",
		"rules (5 for this upstream, 0 for others):\n",
		"    deny  frozen                   tool_not_matched\n",
		"  ! allow edit-projects            check_denied: denied: project:p1#edit@user:carol\n",
		"          check project:p1#edit@user:carol: denied\n",
		"          check project:p1#edit@user:carol: denied (cached)\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, b.String())
		}
	}
	_, ex = mustParse(t, `{"version":1,"rules":[{"id":"s","effect":"allow","agents":["a"],"upstreams":["web"],"tools":["search"],
	  "limits":{"daily":5},"requires_approval":true,"output":{"deny":["github_token"]}}]}`).
		Explain(context.Background(), time.Time{}, Subject{AgentID: "a"}, "web", "search", nil, nil, 0)
	b.Reset()
	ex.WriteText(&b)
	for _, want := range []string{"web.search: allow by s\n", "  requires approval\n", "  limits: 5 a day (UTC)\n",
		"  result deny patterns: github_token\n", "  at: unknown time\n", "  * allow s "} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, b.String())
		}
	}
	_, ex = mustParse(t, `{"version":1,"rules":[]}`).Explain(context.Background(), time.Time{}, Subject{AgentID: "a"}, "web", "search", nil, nil, 0)
	b.Reset()
	ex.WriteText(&b)
	if !strings.Contains(b.String(), "  hidden: ") {
		t.Errorf("hidden not said:\n%s", b.String())
	}
	_, ex = mustParse(t, checkPolicy).Explain(context.Background(), time.Time{}, Subject{AgentID: "a", Owner: "o"}, "fs", "write_file",
		args(t, `{"project":"p1"}`), nil, 0)
	b.Reset()
	ex.WriteText(&b)
	if !strings.Contains(b.String(), "  unavailable: ") {
		t.Errorf("unavailable not said:\n%s", b.String())
	}
}
