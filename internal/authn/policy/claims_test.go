package policy

import (
	mrand "math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

var carol = &Identity{Provider: "corp", Subject: "carol", Email: "carol@example.org", Name: "Carol",
	Groups: []string{"eng"},
	Claims: map[string][]string{
		"department": {"finance"},
		"roles":      {"viewer", "wiki-editor"},
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": {"Approver"},
		"tenant": {"t-42"},
	}}

func TestClaimOperators(t *testing.T) {
	cases := []struct {
		c    ClaimCondition
		want bool
	}{
		{ClaimCondition{Claim: "department", Equals: "finance"}, true},
		{ClaimCondition{Claim: "department", Equals: "Finance"}, false}, // case-sensitive
		{ClaimCondition{Claim: "department", Equals: "fin"}, false},
		{ClaimCondition{Claim: "roles", Equals: "wiki-editor"}, true}, // any value of a multi-valued claim
		{ClaimCondition{Claim: "roles", In: []string{"admin", "viewer"}}, true},
		{ClaimCondition{Claim: "roles", In: []string{"admin", "owner"}}, false},
		{ClaimCondition{Claim: "roles", Matches: "wiki-*"}, true},
		{ClaimCondition{Claim: "roles", Matches: "*-admin"}, false},
		{ClaimCondition{Claim: "tenant", Matches: "t-??"}, true},
		{ClaimCondition{Claim: "tenant", Matches: "t-?"}, false},
		{ClaimCondition{Claim: "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", In: []string{"Approver"}}, true},
		// An absent claim satisfies no operator, not even "*".
		{ClaimCondition{Claim: "missing", Matches: "*"}, false},
		{ClaimCondition{Claim: "missing", Equals: "x"}, false},
		// The verified identity's own fields.
		{ClaimCondition{Claim: "sub", Equals: "carol"}, true},
		{ClaimCondition{Claim: "idp", In: []string{"corp", "partner"}}, true},
		{ClaimCondition{Claim: "email", Matches: "*@example.org"}, true},
		{ClaimCondition{Claim: "email", Matches: "*@example.com"}, false},
		{ClaimCondition{Claim: "name", Equals: "Carol"}, true},
		{ClaimCondition{Claim: "groups", Equals: "eng"}, true},
		{ClaimCondition{Claim: "groups", Equals: "admins"}, false},
	}
	for _, c := range cases {
		cc, err := compileClaim(c.c)
		if err != nil {
			t.Fatalf("%+v: %v", c.c, err)
		}
		if got := cc.holds(carol); got != c.want {
			t.Errorf("%+v holds = %v, want %v", c.c, got, c.want)
		}
	}
	// The fields always win over Claims of the same name: a provider's
	// raw "sub" or "groups" claim cannot stand in for the verified ones.
	spoof := &Identity{Provider: "corp", Subject: "eve", Claims: map[string][]string{"sub": {"alice"}, "groups": {"admins"}}}
	for _, c := range []ClaimCondition{{Claim: "sub", Equals: "alice"}, {Claim: "groups", Equals: "admins"}} {
		cc, _ := compileClaim(c)
		if cc.holds(spoof) {
			t.Errorf("%+v holds from Identity.Claims", c)
		}
	}
	// An empty value is treated as absent.
	cc, _ := compileClaim(ClaimCondition{Claim: "email", Matches: "*"})
	if cc.holds(&Identity{Subject: "x"}) {
		t.Error("an empty email matches '*'")
	}
}

func TestClaimRules(t *testing.T) {
	p := mustCompile(t, App{
		Rule: Rule{Providers: []string{"corp"}, Claims: []ClaimCondition{{Claim: "tenant", Equals: "t-42"}}},
		Paths: []PathRule{
			// Claims only: every user of the providers who meets them.
			{Path: "/finance", Claims: []ClaimCondition{{Claim: "department", In: []string{"finance", "audit"}}}},
			// Claims and a list: both.
			{Path: "/wiki/edit", Groups: []string{"eng"}, Claims: []ClaimCondition{{Claim: "roles", Matches: "wiki-*"}}},
			// Every condition must hold.
			{Path: "/approve", Claims: []ClaimCondition{
				{Claim: "department", Equals: "finance"},
				{Claim: "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Equals: "Approver"},
			}},
			{Path: "/approve/all", Claims: []ClaimCondition{
				{Claim: "department", Equals: "finance"},
				{Claim: "roles", Equals: "admin"},
			}},
		},
	})
	dave := &Identity{Provider: "corp", Subject: "dave", Groups: []string{"eng"},
		Claims: map[string][]string{"roles": {"wiki-editor"}, "tenant": {"t-7"}}}
	other := &Identity{Provider: "other", Subject: "olga", Claims: carol.Claims}
	cases := []struct {
		path   string
		id     *Identity
		ok     bool
		reason string
	}{
		{"/finance/q3", carol, true, Allowed},
		{"/finance/q3", dave, false, DeniedClaims},
		{"/finance/q3", other, false, DeniedProvider},
		{"/finance/q3", nil, false, DeniedNoSubject},
		{"/wiki/edit/home", carol, true, Allowed},
		{"/wiki/edit/home", dave, true, Allowed},
		{"/wiki/edit/home", alice, false, DeniedClaims}, // in eng, but no role
		{"/approve", carol, true, Allowed},
		{"/approve/all", carol, false, DeniedClaims},
		// The app-wide rule has its own claim condition.
		{"/elsewhere", carol, true, Allowed},
		{"/elsewhere", dave, false, DeniedClaims},
	}
	for _, c := range cases {
		ok, reason := p.Decide("GET", c.path, c.id)
		if ok != c.ok || reason != c.reason {
			who := "nobody"
			if c.id != nil {
				who = c.id.Subject
			}
			t.Errorf("%s for %s = %v %s, want %v %s", c.path, who, ok, reason, c.ok, c.reason)
		}
	}
	m := p.Match("GET", "/approve")
	if n := testing.AllocsPerRun(100, func() { p.Evaluate(&m, carol) }); n != 0 {
		t.Errorf("evaluating claim conditions allocates %v times", n)
	}
}

// TestClaimRuleWithCheck: a relationship rule's claim conditions are
// prerequisites, checked before the engine is asked.
func TestClaimRuleWithCheck(t *testing.T) {
	p := mustCompile(t, App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{
		{Path: "/docs/{id}", Check: &CheckRule{Resource: "doc:{path.id}", Permission: "edit"},
			Claims: []ClaimCondition{{Claim: "tenant", Equals: "t-42"}}},
	}})
	if ok, reason := p.Decide("GET", "/docs/d1", carol); ok || reason != CheckRequired {
		t.Errorf("carol: %v %s, want the check", ok, reason)
	}
	if ok, reason := p.Decide("GET", "/docs/d1", alice); ok || reason != DeniedClaims {
		t.Errorf("alice: %v %s, want %s", ok, reason, DeniedClaims)
	}
}

func TestClaimCompileErrors(t *testing.T) {
	long := strings.Repeat("x", MaxClaimValueBytes+1)
	many := make([]string, MaxClaimIn+1)
	for i := range many {
		many[i] = string(rune('a'+i%26)) + strings.Repeat("y", i)
	}
	conds := make([]ClaimCondition, MaxClaimConditions+1)
	for i := range conds {
		conds[i] = ClaimCondition{Claim: "c", Equals: "v"}
	}
	cases := []struct {
		claims []ClaimCondition
		want   string
	}{
		{[]ClaimCondition{{Equals: "x"}}, "claims[0]: a claim name is 1 to"},
		{[]ClaimCondition{{Claim: "a b", Equals: "x"}}, "visible ASCII"},
		{[]ClaimCondition{{Claim: strings.Repeat("n", 257), Equals: "x"}}, "a claim name is 1 to"},
		{[]ClaimCondition{{Claim: "a"}}, "exactly one of equals, in or matches"},
		{[]ClaimCondition{{Claim: "a", Equals: "x", Matches: "y*"}}, "exactly one of"},
		{[]ClaimCondition{{Claim: "a", Equals: "x", In: []string{"x"}}}, "exactly one of"},
		{[]ClaimCondition{{Claim: "a", Equals: long}}, "at most 1024 bytes"},
		{[]ClaimCondition{{Claim: "a", Matches: long}}, "a pattern is at most"},
		{[]ClaimCondition{{Claim: "a", Matches: `ab\`}}, "lone '\\'"},
		{[]ClaimCondition{{Claim: "a", In: []string{"x", ""}}}, "an in value is 1 to"},
		{[]ClaimCondition{{Claim: "a", In: []string{"x", "x"}}}, `lists "x" twice`},
		{[]ClaimCondition{{Claim: "a", In: many}}, "at most 256 values"},
		{conds, "at most 16 conditions"},
		{[]ClaimCondition{{Claim: "ok", Equals: "v"}, {Claim: "a"}}, "claims[1]:"},
	}
	for _, c := range cases {
		_, err := CompileApp(App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{{Path: "/x", Claims: c.claims}}})
		if err == nil || !strings.Contains(err.Error(), "paths[0]: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: error %v, want one containing %q", c.claims, err, c.want)
		}
		_, err = CompileApp(App{Rule: Rule{Providers: []string{"corp"}, Claims: c.claims}})
		if err == nil || !strings.Contains(err.Error(), "allow: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("app-wide %v: error %v, want one containing %q", c.claims, err, c.want)
		}
		// Compiled on its own, the rule fails closed.
		if ok, _ := Compile(Rule{Providers: []string{"corp"}, AnyUser: true, Claims: c.claims}).Evaluate(*carol); ok {
			t.Errorf("%v: a rule whose conditions do not compile allows", c.claims)
		}
	}
	for _, pr := range []PathRule{
		{Path: "/x", Public: true, Claims: []ClaimCondition{{Claim: "a", Equals: "b"}}},
		{Path: "/x", Deny: true, Claims: []ClaimCondition{{Claim: "a", Equals: "b"}}},
	} {
		if _, err := CompileApp(App{Paths: []PathRule{pr}}); err == nil || !strings.Contains(err.Error(), "takes no allow") {
			t.Errorf("%+v: error %v", pr, err)
		}
	}
}

// globRef restates a pattern as an anchored regular expression.
func globRef(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`^(?s:`)
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			i++
			b.WriteString(regexp.QuoteMeta(p[i : i+1]))
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(p[i : i+1]))
		}
	}
	b.WriteString(`)$`)
	return regexp.MustCompile(b.String())
}

// asciiOnly keeps the reference honest: '.' in a regexp is a rune, '?' in
// a pattern is a byte.
func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func TestGlobAgainstRegexp(t *testing.T) {
	fixed := []struct {
		p, v string
		want bool
	}{
		{"", "", true}, {"", "a", false}, {"*", "", true}, {"*", "anything", true},
		{"a*b*c", "abc", true}, {"a*b*c", "aXbYc", true}, {"a*b*c", "acb", false},
		{"*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{`\*x`, "*x", true}, {`\*x`, "ax", false}, {`a\?`, "a?", true}, {`a\?`, "ab", false},
		{`\\`, `\`, true}, {"**a", "ba", true}, {"?*?", "a", false}, {"?*?", "ab", true},
	}
	for _, c := range fixed {
		g, err := compileGlob(c.p)
		if err != nil {
			t.Fatal(err)
		}
		if got := globMatch(g, c.v); got != c.want {
			t.Errorf("%q ~ %q = %v, want %v", c.p, c.v, got, c.want)
		}
	}
	r := mrand.New(mrand.NewPCG(4, 82))
	const alpha = `ab*?\`
	for i := 0; i < 20000; i++ {
		var p, v []byte
		for n := r.IntN(8); n > 0; n-- {
			p = append(p, alpha[r.IntN(len(alpha))])
		}
		for n := r.IntN(10); n > 0; n-- {
			v = append(v, "ab*?\\"[r.IntN(5)])
		}
		g, err := compileGlob(string(p))
		if err != nil {
			continue
		}
		if got, want := globMatch(g, string(v)), globRef(string(p)).MatchString(string(v)); got != want {
			t.Fatalf("%q ~ %q = %v, regexp says %v", p, v, got, want)
		}
	}
}

func FuzzGlob(f *testing.F) {
	f.Add("a*b?c", "aXXbYc")
	f.Add(`\**`, "*star")
	f.Add("*a*a*b", "aaaaaaaaab")
	f.Fuzz(func(t *testing.T, p, v string) {
		if len(p) > 64 || len(v) > 256 || !asciiOnly(p) || !asciiOnly(v) {
			return
		}
		g, err := compileGlob(p)
		if err != nil {
			if !strings.HasSuffix(p, `\`) {
				t.Fatalf("%q refused: %v", p, err)
			}
			return
		}
		if got, want := globMatch(g, v), globRef(p).MatchString(v); got != want {
			t.Fatalf("%q ~ %q = %v, regexp says %v", p, v, got, want)
		}
	})
}
