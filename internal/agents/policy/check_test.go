package policy

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
)

const checkSchema = `definition user {}

definition team {
  relation member: user
}

definition project {
  relation editor: user | team#member
  relation frozen: user:*
  permission edit = editor
}
`

const checkPolicy = `{"version": 1, "rules": [
  {"id": "frozen", "effect": "deny", "agents": ["*"], "upstreams": ["fs"], "tools": ["write_file"],
   "check": {"resource": "project:{args.project}", "permission": "frozen", "subject": "user:{owner}"}},
  {"id": "edit-projects", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["write_file", "rename"],
   "arguments": {"type": "object", "required": ["project"]},
   "check": {"resource": "project:{args.project}", "permission": "edit"}},
  {"id": "team-files", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["rename"],
   "check": {"resource": "project:{args.target.project}", "permission": "edit", "subject": "user:{owner}"}},
  {"id": "agent-edit", "effect": "allow", "agents": ["ci-bot"], "upstreams": ["fs"], "tools": ["write_file"],
   "check": {"resource": "project:p-{args.n}", "permission": "edit", "subject": "user:{agent}"}},
  {"id": "read", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["read_file"]}
]}`

func mustParse(t testing.TB, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// countingEngine counts the checks it answers and the calls of its getter.
type countingEngine struct {
	inner  Checker
	checks atomic.Int64
	gets   atomic.Int64
}

func (c *countingEngine) Check(ctx context.Context, req engine.CheckRequest) (engine.CheckResult, error) {
	c.checks.Add(1)
	return c.inner.Check(ctx, req)
}

func (c *countingEngine) get(context.Context) (Checker, error) {
	c.gets.Add(1)
	return c, nil
}

func fakeEngine(t testing.TB, rels ...string) *countingEngine {
	t.Helper()
	f, err := enginetest.NewFake(checkSchema, rels...)
	if err != nil {
		t.Fatal(err)
	}
	return &countingEngine{inner: f}
}

func TestDecideRelationshipChecks(t *testing.T) {
	p := mustParse(t, checkPolicy)
	if !p.HasChecks() || !p.Rules[0].HasCheck() || p.Rules[4].HasCheck() {
		t.Fatal("HasChecks")
	}
	eng := fakeEngine(t,
		"project:p1#editor@user:alice",
		"project:p2#editor@team:core#member", "team:core#member@user:bob",
		"project:p3#editor@user:alice", "project:p3#frozen@user:*",
		"project:p-7#editor@user:ci-bot",
	)
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	bob := Subject{AgentID: "bob-bot", Owner: "bob"}
	carol := Subject{AgentID: "carol-bot", Owner: "carol"}
	ci := Subject{AgentID: "ci-bot", Owner: "ci"}
	orphan := Subject{AgentID: "ci-bot"}
	cases := []struct {
		name       string
		s          Subject
		tool, args string
		allowed    bool
		rule       string
		constraint string
		reason     string
		checks     []string
	}{
		{"owner edits", alice, "write_file", `{"project":"p1"}`, true, "edit-projects", "", "",
			[]string{"project:p1#frozen@user:alice: denied", "project:p1#edit@user:alice: allowed"}},
		{"through a team", bob, "write_file", `{"project":"p2"}`, true, "edit-projects", "", "",
			[]string{"project:p2#frozen@user:bob: denied", "project:p2#edit@user:bob: allowed"}},
		{"not an editor", carol, "write_file", `{"project":"p1"}`, false, DefaultDenyID, "edit-projects",
			"relationship check of rule edit-projects is denied: project:p1#edit@user:carol",
			[]string{"project:p1#frozen@user:carol: denied", "project:p1#edit@user:carol: denied"}},
		{"frozen project", alice, "write_file", `{"project":"p3"}`, false, "frozen", "", "rule frozen forbids this call",
			[]string{"project:p3#frozen@user:alice: allowed"}},
		// A deny rule that cannot build its check fails closed.
		{"deny rule without input", alice, "write_file", `{}`, false, "frozen", "",
			"its relationship check is missing its input: resource: argument project is missing",
			[]string{"project:#frozen@user:alice: bad_input"}},
		{"deny rule with an invalid id", alice, "write_file", `{"project":"a b"}`, false, "frozen", "",
			`resource id "a b" is not a valid object id`, []string{"project:a b#frozen@user:alice: bad_input"}},
		{"wildcard is not an id", alice, "write_file", `{"project":"*"}`, false, "frozen", "", `resource id "*"`, nil},
		// The first allow rule fails, a later one allows: nested arguments.
		{"second rule allows", alice, "rename", `{"project":"p9","target":{"project":"p1"}}`, true, "team-files", "", "",
			[]string{"project:p9#edit@user:alice: denied", "project:p1#edit@user:alice: allowed"}},
		{"first schema failure is reported", alice, "rename", `{"target":{"project":"p9"}}`, false, DefaultDenyID, "edit-projects",
			"arguments rejected by rule edit-projects", []string{"project:p9#edit@user:alice: denied"}},
		{"object where a string is needed", alice, "rename", `{"project":"p9","target":{"project":{"x":1}}}`, false, DefaultDenyID,
			"edit-projects", "denied: project:p9", nil},
		// Integers fill templates; the agent id is a subject too.
		{"integer argument", ci, "write_file", `{"project":"p0","n":7}`, true, "agent-edit", "", "", nil},
		{"fraction argument", ci, "write_file", `{"project":"p0","n":7.5}`, false, DefaultDenyID, "edit-projects", "", nil},
		// No owner: the default subject cannot be built.
		{"agent without owner", orphan, "write_file", `{"project":"p1"}`, false, "frozen", "", "the agent has no owner", nil},
		// A rule without a check does not ask.
		{"plain rule", carol, "read_file", `{}`, true, "read", "", "", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := p.Decide(context.Background(), c.s, "fs", c.tool, args(t, c.args), eng.get)
			if d.Allowed != c.allowed || d.RuleID != c.rule || d.ConstraintRuleID != c.constraint || d.Unavailable {
				t.Fatalf("got %+v", d)
			}
			if !strings.Contains(d.Reason, c.reason) {
				t.Errorf("reason %q does not contain %q", d.Reason, c.reason)
			}
			if c.checks != nil {
				got := []string{}
				for _, tr := range d.Checks {
					got = append(got, tr.String())
				}
				if strings.Join(got, "|") != strings.Join(c.checks, "|") {
					t.Errorf("checks %q, want %q", got, c.checks)
				}
			}
		})
	}
}

func TestDecideCachesChecksPerCall(t *testing.T) {
	p := mustParse(t, `{"version": 1, "rules": [
	  {"id": "a", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"],
	   "arguments": {"required": ["x"]}, "check": {"resource": "project:{args.p}", "permission": "edit"}},
	  {"id": "b", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"],
	   "check": {"resource": "project:{args.p}", "permission": "edit", "subject": "user:{owner}"}},
	  {"id": "c", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"],
	   "check": {"resource": "project:{args.p}", "permission": "edit"}},
	  {"id": "d", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"],
	   "check": {"resource": "project:{args.q}", "permission": "edit"}}
	]}`)
	eng := fakeEngine(t, "project:q1#editor@user:alice")
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	d := p.Decide(context.Background(), alice, "fs", "t", args(t, `{"p":"p1","q":"q1"}`), eng.get)
	if !d.Allowed || d.RuleID != "d" {
		t.Fatalf("got %+v", d)
	}
	// a fails its schema before asking; b asks; c is the same check as b;
	// d asks another.
	if n := eng.checks.Load(); n != 2 {
		t.Errorf("engine asked %d times, want 2", n)
	}
	if n := eng.gets.Load(); n != 1 {
		t.Errorf("engine fetched %d times, want 1", n)
	}
	if len(d.Checks) != 3 || d.Checks[0].Cached || !d.Checks[1].Cached || d.Checks[1].RuleID != "c" || d.Checks[2].Cached {
		t.Errorf("traces %+v", d.Checks)
	}
	// The cache lives for one call only.
	p.Decide(context.Background(), alice, "fs", "t", args(t, `{"p":"p1","q":"q1"}`), eng.get)
	if n := eng.checks.Load(); n != 4 {
		t.Errorf("engine asked %d times over two calls, want 4", n)
	}
	// A call that reaches no check never fetches the engine.
	gets := eng.gets.Load()
	if d := p.Decide(context.Background(), alice, "fs", "other", nil, eng.get); d.Allowed || len(d.Checks) != 0 {
		t.Errorf("got %+v", d)
	}
	if eng.gets.Load() != gets {
		t.Error("the engine was fetched for a call without checks")
	}
}

type stubChecker struct {
	res engine.CheckResult
	err error
}

func (s stubChecker) Check(context.Context, engine.CheckRequest) (engine.CheckResult, error) {
	return s.res, s.err
}

func TestDecideUnavailableAndConditional(t *testing.T) {
	p := mustParse(t, `{"version": 1, "rules": [
	  {"id": "blocked", "effect": "deny", "agents": ["*"], "upstreams": ["fs"], "tools": ["deny_me"],
	   "check": {"resource": "project:x", "permission": "frozen"}},
	  {"id": "edit", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t", "u"],
	   "check": {"resource": "project:{args.p}", "permission": "edit"}},
	  {"id": "u-anyway", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["u"]},
	  {"id": "later", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["deny_me"]}
	]}`)
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	a := args(t, `{"p":"p1"}`)
	boom := errors.New("store is down")
	failing := func(context.Context) (Checker, error) { return stubChecker{err: boom}, nil }
	noEngine := func(context.Context) (Checker, error) { return nil, errors.New("no engine here") }
	conditional := func(context.Context) (Checker, error) {
		return stubChecker{res: engine.CheckResult{Permissionship: check.Conditional, Missing: []string{"ip", "now"}}}, nil
	}
	allowed := func(context.Context) (Checker, error) {
		return stubChecker{res: engine.CheckResult{Allowed: true, Permissionship: check.Allowed}}, nil
	}
	denied := func(context.Context) (Checker, error) { return stubChecker{}, nil }

	for _, c := range []struct {
		name        string
		tool        string
		get         CheckEngine
		allowed     bool
		unavailable bool
		rule        string
		reason      string
	}{
		{"engine error", "t", failing, false, true, DefaultDenyID, "store is down"},
		{"no engine", "t", noEngine, false, true, DefaultDenyID, "no engine here"},
		{"nil getter", "t", nil, false, true, DefaultDenyID, "run authz run with its serve part"},
		{"later rule allows anyway", "u", failing, true, false, "u-anyway", ""},
		{"conditional is not allowed", "t", conditional, false, false, DefaultDenyID, "conditional on ip, now"},
		{"deny rule fails closed on an outage", "deny_me", failing, false, true, "blocked", "store is down"},
		{"deny rule fails closed on conditional", "deny_me", conditional, false, false, "blocked", "conditional on ip, now"},
		{"deny rule holds", "deny_me", allowed, false, false, "blocked", "forbids this call"},
		{"deny rule does not hold", "deny_me", denied, true, false, "later", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := p.Decide(context.Background(), alice, "fs", c.tool, a, c.get)
			if d.Allowed != c.allowed || d.Unavailable != c.unavailable || d.RuleID != c.rule || !strings.Contains(d.Reason, c.reason) {
				t.Fatalf("got %+v", d)
			}
		})
	}
	// Evaluate has no engine.
	if d := p.Evaluate(alice, "fs", "t", a); !d.Unavailable || d.ConstraintRuleID != "edit" {
		t.Errorf("Evaluate: %+v", d)
	}
}

func TestVisibleIgnoresCheckedDenyRules(t *testing.T) {
	p := mustParse(t, checkPolicy)
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	// The deny rule on write_file has a check, so it does not hide the tool.
	if !p.Visible(alice, "fs", "write_file") || p.Visible(alice, "fs", "delete") {
		t.Error("visibility")
	}
}

func TestParseCheckErrors(t *testing.T) {
	rule := func(check string) string {
		return `{"version": 1, "rules": [{"id": "r", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"], "check": ` + check + `}]}`
	}
	for _, c := range []struct{ check, want string }{
		{`{"permission": "edit"}`, "check.resource is required"},
		{`{"resource": "project", "permission": "edit"}`, "must be type:id"},
		{`{"resource": "Project:x", "permission": "edit"}`, `type "Project"`},
		{`{"resource": "project:x#editor", "permission": "edit"}`, "without #relation"},
		{`{"resource": "project:x", "permission": "Edit"}`, `check.permission "Edit"`},
		{`{"resource": "project:x", "permission": ""}`, "check.permission"},
		{`{"resource": "project:{user}", "permission": "edit"}`, "unknown variable {user}"},
		{`{"resource": "project:{args.}", "permission": "edit"}`, "an argument name is empty"},
		{`{"resource": "project:{args.a.b.c.d.e.f.g.h.i}", "permission": "edit"}`, "at most 8 names"},
		{`{"resource": "project:{args.p", "permission": "edit"}`, "'{' without '}'"},
		{`{"resource": "project:a}b", "permission": "edit"}`, "'}' without '{'"},
		{`{"resource": "project:", "permission": "edit"}`, "the id is empty"},
		{`{"resource": "project:a b", "permission": "edit"}`, "not made of object ID characters"},
		{`{"resource": "project:x", "permission": "edit", "subject": "user:{owner}#Member"}`, `relation "Member"`},
		{`{"resource": "project:x", "permission": "edit", "subject": "user"}`, "check.subject"},
		{`{"resource": "project:x", "permission": "edit", "relation": "x"}`, "unknown field"},
	} {
		_, err := Parse([]byte(rule(c.check)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.check, err, c.want)
		}
	}
	// Usersets as subjects, literal prefixes and deny rules are fine.
	mustParse(t, rule(`{"resource": "project:p-{args.p}-x", "permission": "edit", "subject": "team:{args.team}#member"}`))
	mustParse(t, `{"version": 1, "rules": [{"id": "r", "effect": "deny", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"],
	  "check": {"resource": "project:x", "permission": "frozen", "subject": "user:{agent}"}}]}`)
	if mustParse(t, `{"version": 1, "rules": [{"id": "r", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"]}]}`).HasChecks() {
		t.Error("HasChecks without checks")
	}
}

func TestDecideUsersetSubject(t *testing.T) {
	p := mustParse(t, `{"version": 1, "rules": [
	  {"id": "team", "effect": "allow", "agents": ["*"], "upstreams": ["fs"], "tools": ["t"],
	   "check": {"resource": "project:{args.p}", "permission": "edit", "subject": "team:{args.team}#member"}}]}`)
	eng := fakeEngine(t, "project:p2#editor@team:core#member")
	s := Subject{AgentID: "x"}
	if d := p.Decide(context.Background(), s, "fs", "t", args(t, `{"p":"p2","team":"core"}`), eng.get); !d.Allowed {
		t.Errorf("got %+v", d)
	}
	if d := p.Decide(context.Background(), s, "fs", "t", args(t, `{"p":"p2","team":"other"}`), eng.get); d.Allowed {
		t.Errorf("got %+v", d)
	}
}

func TestCasesWithChecks(t *testing.T) {
	p := mustParse(t, checkPolicy)
	cs, err := ParseCases([]byte(`{"version": 1, "cases": [
	  {"name": "alice edits", "subject": {"agent": "alice-bot", "owner": "alice"},
	   "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
	   "checks": {"project:p1#edit@user:alice": "allowed"},
	   "expect": {"decision": "allow", "rule": "edit-projects"}},
	  {"name": "unlisted is denied", "subject": {"agent": "alice-bot", "owner": "alice"},
	   "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
	   "expect": {"decision": "deny", "rule": "default-deny", "constraint_rule": "edit-projects", "hidden": false}},
	  {"name": "frozen", "subject": {"agent": "alice-bot", "owner": "alice"},
	   "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
	   "checks": {"project:p1#edit@user:alice": "allowed", "project:p1#frozen@user:alice": "allowed"},
	   "expect": {"decision": "deny", "rule": "frozen"}},
	  {"name": "outage", "subject": {"agent": "alice-bot", "owner": "alice"},
	   "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
	   "checks": {"project:p1#edit@user:alice": "unavailable"},
	   "expect": {"decision": "deny", "constraint_rule": "edit-projects", "reason_contains": "could not be made"}},
	  {"name": "conditional", "subject": {"agent": "alice-bot", "owner": "alice"},
	   "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
	   "checks": {"project:p1#edit@user:alice": "conditional"},
	   "expect": {"decision": "deny", "reason_contains": "conditional"}},
	  {"name": "wrong on purpose", "subject": {"agent": "alice-bot", "owner": "alice"},
	   "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
	   "expect": {"decision": "allow"}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep := RunCases(p, cs)
	if rep.Passed != 5 || rep.Failed != 1 || rep.Results[5].Passed() {
		t.Fatalf("report %+v", rep)
	}
	for i, want := range []string{"", " (check of edit-projects failed)", "", " (check of edit-projects unavailable)", " (check of edit-projects failed)"} {
		if want != "" && !strings.Contains(rep.Results[i].Got, want) {
			t.Errorf("case %d: %q does not contain %q", i, rep.Results[i].Got, want)
		}
	}
	for _, c := range []struct{ src, want string }{
		{`"checks": {"project:p1#edit@user:alice": "yes"}`, `must be "allowed"`},
		{`"checks": {"project:p1@user:alice": "allowed"}`, "must be type:id#permission@subject"},
		{`"checks": {"project:p1#edit": "allowed"}`, "must be type:id#permission@subject"},
		{`"checks": {"project:p1#edit@alice": "allowed"}`, "project:p1#edit@alice"},
		{`"checks": {"project:a b#edit@user:alice": "allowed"}`, "must be type:id#permission@subject"},
	} {
		_, err := ParseCases([]byte(`{"version": 1, "cases": [{"name": "c", "subject": {"agent": "a"},
		  "call": {"tool": "fs.t"}, ` + c.src + `, "expect": {"decision": "deny"}}]}`))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.src, err, c.want)
		}
	}
	for _, c := range []struct{ src, want string }{
		{`{"name": "c", "subject": {"agent": "a"}, "list": ["fs.t"], "checks": {}, "expect": {"visible": []}}`, "only to call cases"},
		{`{"name": "c", "subject": {"agent": "a", "owner": "a\u0001"}, "call": {"tool": "fs.t"}, "expect": {"decision": "deny"}}`, "subject owner"},
	} {
		_, err := ParseCases([]byte(`{"version": 1, "cases": [` + c.src + `]}`))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.src, err, c.want)
		}
	}
}
