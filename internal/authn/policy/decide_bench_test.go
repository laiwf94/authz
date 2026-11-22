package policy

import (
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"testing"
)

// bigRules is the number of path rules in the benchmark app.
const bigRules = 1000

// bigApp is an app with 1,000 path rules of every kind, about half of them
// with claim conditions: 40 areas, each with literal and {parameter}
// prefixes, exact rules, method-specific rules, public and deny rules,
// rules by group and by email domain, and claim conditions with equality,
// membership and patterns, some on the identity's groups and email.
func bigApp() App {
	a := App{
		Rule:   Rule{Providers: []string{"corp", "partner"}, Claims: []ClaimCondition{{Claim: "tenant", Matches: "t-*"}}},
		Public: []string{"/static", "/health"},
	}
	methods := [][]string{nil, {"GET"}, {"POST", "PUT"}, {"DELETE"}}
	for i := 0; len(a.Paths) < bigRules-len(a.Public); i++ {
		area := fmt.Sprintf("/area%d", i%40)
		k := i / 40
		pr := PathRule{Methods: methods[k%len(methods)]}
		switch k % 8 {
		case 0:
			pr.Path = fmt.Sprintf("%s/team%d", area, k)
		case 1:
			pr.Path = fmt.Sprintf("%s/team%d/{project}/docs", area, k)
		case 2:
			pr.Path = fmt.Sprintf("%s/{org}/report%d", area, k)
			pr.Exact = true
		case 3:
			pr.Path = fmt.Sprintf("%s/team%d/{project}/{doc}/history", area, k)
		case 4:
			pr.Path = fmt.Sprintf("%s/pub%d", area, k)
		case 5:
			pr.Path = fmt.Sprintf("%s/locked%d", area, k)
		case 6:
			pr.Path = fmt.Sprintf("%s/team%d/settings", area, k)
		default:
			pr.Path = fmt.Sprintf("%s/svc%d/{version}", area, k)
		}
		switch i % 10 {
		case 0:
			pr.Public, pr.Methods = true, nil
			pr.Path = fmt.Sprintf("%s/open%d", area, k)
		case 1:
			pr.Deny = true
		case 2:
			pr.Groups = []string{fmt.Sprintf("team%d", k), "admins"}
		case 3:
			pr.EmailDomains = []string{"example.org"}
		case 4:
			pr.Claims = []ClaimCondition{{Claim: "department", Equals: fmt.Sprintf("dept%d", k%7)}}
		case 5:
			pr.Claims = []ClaimCondition{{Claim: "roles", In: []string{"viewer", "editor", fmt.Sprintf("role%d", k)}}}
		case 6:
			pr.Claims = []ClaimCondition{{Claim: "email", Matches: "*@example.org"}, {Claim: "roles", Matches: "wiki-*"}}
		case 7:
			pr.Groups = []string{"eng"}
			pr.Claims = []ClaimCondition{{Claim: "groups", In: []string{"eng", "ops"}}, {Claim: "tenant", Equals: "t-42"}}
		case 8:
			pr.AnyUser = true
			pr.Claims = []ClaimCondition{{Claim: "http://schemas.example.org/claims/level", In: []string{"2", "3"}}}
		default:
			pr.AnyUser = true
		}
		a.Paths = append(a.Paths, pr)
	}
	return a
}

// bigRequests are requests made from the app's own rules, so they reach
// every kind of rule, with parameters filled in and prefixes extended, in
// methods the rule may or may not list, plus misses that fall to a
// shorter rule or the app-wide rule.
func bigRequests(a App) [][2]string {
	var reqs [][2]string
	r := mrand.New(mrand.NewPCG(82, 5))
	verbs := []string{"GET", "POST", "PUT", "DELETE", "HEAD"}
	for i := 0; i < 512; i++ {
		verb := verbs[r.IntN(len(verbs))]
		if i%8 == 7 {
			reqs = append(reqs, [2]string{verb, fmt.Sprintf("/nowhere/%d/x", r.IntN(100))})
			continue
		}
		pr := a.Paths[r.IntN(len(a.Paths))]
		if len(pr.Methods) > 0 && r.IntN(4) > 0 {
			verb = pr.Methods[r.IntN(len(pr.Methods))]
		}
		var b strings.Builder
		for _, seg := range strings.Split(pr.Path[1:], "/") {
			b.WriteByte('/')
			if seg[0] == '{' {
				fmt.Fprintf(&b, "v%d", r.IntN(1000))
			} else {
				b.WriteString(seg)
			}
		}
		if !pr.Exact && r.IntN(2) == 0 {
			b.WriteString("/page/1")
		}
		reqs = append(reqs, [2]string{verb, b.String()})
	}
	return reqs
}

var bigIdentity = &Identity{Provider: "corp", Subject: "carol", Email: "carol@example.org",
	Groups: []string{"eng", "team3", "finance"},
	Claims: map[string][]string{
		"department": {"dept3"},
		"roles":      {"viewer", "wiki-editor"},
		"tenant":     {"t-42"},
		"http://schemas.example.org/claims/level": {"2"},
	}}

// TestBigAppDecides: the benchmark app compiles to 1,000 rules, its
// requests reach a spread of rules and outcomes, and deciding them
// allocates nothing.
func TestBigAppDecides(t *testing.T) {
	a := bigApp()
	p := mustCompile(t, a)
	if len(p.rules) != bigRules {
		t.Fatalf("%d rules, want %d", len(p.rules), bigRules)
	}
	reqs := bigRequests(a)
	rules, reasons := map[int]bool{}, map[string]int{}
	for _, rq := range reqs {
		m := p.Match(rq[0], rq[1])
		rules[m.Rule] = true
		_, reason := p.Evaluate(&m, bigIdentity)
		reasons[reason]++
	}
	if len(rules) < 100 {
		t.Errorf("the requests reach only %d rules", len(rules))
	}
	for _, want := range []string{Allowed, AllowedPublic, DeniedRule, DeniedClaims, DeniedNoMatch} {
		if reasons[want] == 0 {
			t.Errorf("no request is decided %s: %v", want, reasons)
		}
	}
	for _, rq := range reqs {
		if n := testing.AllocsPerRun(10, func() { p.Decide(rq[0], rq[1], bigIdentity) }); n != 0 {
			t.Fatalf("%s %s allocates %v times", rq[0], rq[1], n)
		}
	}
}

// BenchmarkDecide is one decision (match and evaluate) in an app with
// 1,000 path and claim rules, cycling through requests that reach every
// kind of rule. The target is under 2 µs and no allocations.
func BenchmarkDecide(b *testing.B) {
	a := bigApp()
	p := mustCompile(b, a)
	reqs := bigRequests(a)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rq := reqs[i%len(reqs)]
		p.Decide(rq[0], rq[1], bigIdentity)
	}
}
