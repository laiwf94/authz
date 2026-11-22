package policy

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
)

// chain is a candidate list as "rule*" for the selected rule, "rule-" for
// one whose methods do not match, and "rule" for the others.
func chain(cs []Candidate) string {
	var parts []string
	for _, c := range cs {
		s := c.Rule
		switch {
		case c.Selected:
			s += "*"
		case !c.MethodMatches:
			s += "-"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func TestCandidatesWiki(t *testing.T) {
	p := wiki(t)
	cases := []struct{ method, path, chain string }{
		{"GET", "/", "paths[8]- public[0]* allow"},
		{"POST", "/", "paths[8]* public[0] allow"},
		{"GET", "/about", "public[0]* allow"},
		{"GET", "/wiki/home", "paths[0]* paths[1] public[0] allow"},
		{"POST", "/wiki/home", "paths[0]- paths[1]* public[0] allow"},
		{"GET", "/wiki/new", "paths[3]* paths[0] paths[1] public[0] allow"},
		{"GET", "/wiki/new/history", "paths[2]* paths[0] paths[1] public[0] allow"},
		// The deny rule lists DELETE only: a GET passes it over.
		{"GET", "/admin/audit/7", "paths[5]- paths[4]* public[0] allow"},
		{"DELETE", "/admin/audit/7", "paths[5]* paths[4] public[0] allow"},
		// The literal "acme" is tried before the {org} parameter, but
		// the deeper rule still wins.
		{"GET", "/api/acme/docs/d1", "paths[6]* paths[7] public[0] allow"},
		{"GET", "/api/acme/docs", "paths[7]* public[0] allow"},
		{"GET", "/wiki/./a/../home", "paths[0]* paths[1] public[0] allow"},
	}
	for _, c := range cases {
		m, cs := p.Candidates(c.method, c.path)
		if got := chain(cs); got != c.chain {
			t.Errorf("%s %s: chain %q, want %q", c.method, c.path, got, c.chain)
		}
		if want := p.Match(c.method, c.path); m != want {
			t.Errorf("%s %s: Candidates matched %+v, Match %+v", c.method, c.path, m, want)
		}
	}

	_, cs := p.Candidates("GET", "/api/acme/docs/d%20e")
	if c := cs[0]; c.Pattern != "/api/{org}/docs/{doc}" || c.Kind != KindAllow || c.Params["org"] != "acme" ||
		c.Params["doc"] != "d e" || len(c.Params) != 2 || c.Exact || c.Methods != nil {
		t.Errorf("parameter rule: %+v", c)
	}
	_, cs = p.Candidates("DELETE", "/admin/audit")
	if c := cs[0]; c.Kind != KindDeny || !slices.Equal(c.Methods, []string{"DELETE"}) || c.Params != nil {
		t.Errorf("deny rule: %+v", c)
	}
	_, cs = p.Candidates("GET", "/wiki/new")
	if cs[0].Kind != KindAllow || !cs[0].Exact || cs[1].Kind != KindPublic || !slices.Equal(cs[1].Methods, []string{"GET"}) {
		t.Errorf("exact and public rules: %+v %+v", cs[0], cs[1])
	}
	if last := cs[len(cs)-1]; last.Rule != "allow" || last.Kind != KindAllow || last.Selected || !last.MethodMatches {
		t.Errorf("app-wide rule: %+v", last)
	}

	// A bad path matches nothing.
	if m, cs := p.Candidates("GET", "/a%2Fb"); !m.Bad || cs != nil {
		t.Errorf("bad path: %+v %v", m, cs)
	}
	// An app without path rules has only its app-wide rule.
	np := mustCompile(t, App{Rule: Rule{Providers: []string{"corp"}, AnyUser: true}})
	if _, cs := np.Candidates("GET", "/x"); chain(cs) != "allow*" {
		t.Errorf("no path rules: %q", chain(cs))
	}
}

func TestCandidateKindsAndMethods(t *testing.T) {
	p := mustCompile(t, App{
		Rule: Rule{Providers: []string{"corp"}},
		Paths: []PathRule{
			{Path: "/docs/{id}", Methods: []string{"PUT", "GET"}, Check: &CheckRule{Resource: "doc:{path.id}", Permission: "edit"}},
			{Path: "/docs", Methods: []string{"HEAD"}, AnyUser: true,
				StepUp: &StepUp{ACRValues: []string{"mfa"}}},
		},
	})
	_, cs := p.Candidates("GET", "/docs/plan")
	if c := cs[0]; c.Kind != KindCheck || !slices.Equal(c.Methods, []string{"GET", "PUT"}) || !c.Selected || c.Params["id"] != "plan" {
		t.Errorf("check rule: %+v", c)
	}
	if c := cs[1]; !slices.Equal(c.Methods, []string{"HEAD"}) || !c.StepUp || c.MethodMatches || c.Selected {
		t.Errorf("HEAD rule: %+v", c)
	}
	if got := chain(cs); got != "paths[0]* paths[1]- allow" {
		t.Errorf("chain %q", got)
	}
}

// refCandidates lists the rules whose pattern matches clean, whatever
// their methods, with the specificity refMatch ranks them by.
type refCand struct {
	name     string
	depth    int
	exact    bool
	shape    string
	specific bool
}

func refCandidates(a App, clean string) []refCand {
	var out []refCand
	try := func(name string, r PathRule) {
		pat := strings.Split(strings.Trim(r.Path, "/"), "/")
		if strings.Trim(r.Path, "/") == "" {
			pat = nil
		}
		segs := strings.Split(strings.Trim(clean, "/"), "/")
		if strings.Trim(clean, "/") == "" {
			segs = nil
		}
		if len(pat) > len(segs) || (r.Exact && len(pat) != len(segs)) {
			return
		}
		shape := ""
		for i, s := range pat {
			if strings.HasPrefix(s, "{") {
				shape += "p"
				continue
			}
			if s != segs[i] {
				return
			}
			shape += "l"
		}
		out = append(out, refCand{name: name, depth: len(pat), exact: r.Exact, shape: shape, specific: len(r.Methods) > 0})
	}
	for i, r := range a.Paths {
		try(fmt.Sprintf("paths[%d]", i), r)
	}
	for i, pub := range a.Public {
		try(fmt.Sprintf("public[%d]", i), PathRule{Path: pub, Public: true})
	}
	return out
}

// TestPropertyCandidates checks the chain on random rule sets: it holds
// exactly the rules whose pattern matches, each tried before every rule
// less specific, the selected rule is the first whose methods match and is
// the one Match selects, and nothing after it is selected.
func TestPropertyCandidates(t *testing.T) {
	r := mrand.New(mrand.NewPCG(21, 22))
	segs := []string{"a", "b", "docs", "{x}", "{y}"}
	reqSegs := []string{"a", "b", "docs", "c", ".", "..", "%61"}
	methods := []string{"GET", "HEAD", "POST", "DELETE"}
	randPattern := func() string {
		var b strings.Builder
		used := map[string]bool{}
		for n := r.IntN(4); n > 0; n-- {
			s := segs[r.IntN(len(segs))]
			if used[s] && s[0] == '{' {
				s = "c"
			}
			used[s] = true
			b.WriteString("/" + s)
		}
		if b.Len() == 0 {
			b.WriteByte('/')
		}
		return b.String()
	}
	// rank orders reference candidates as App's order rules do, apart
	// from methods.
	rank := func(x, y refCand) int {
		switch {
		case x.depth != y.depth:
			return y.depth - x.depth
		case x.exact != y.exact:
			if x.exact {
				return -1
			}
			return 1
		}
		return strings.Compare(x.shape, y.shape)
	}
	checked := 0
	for i := 0; i < 2000; i++ {
		var a App
		for j := 1 + r.IntN(8); j > 0; j-- {
			if r.IntN(4) == 0 {
				a.Public = append(a.Public, randPattern())
				continue
			}
			pr := PathRule{Path: randPattern(), Exact: r.IntN(3) == 0, AnyUser: true}
			for _, m := range methods {
				if r.IntN(5) == 0 {
					pr.Methods = append(pr.Methods, m)
				}
			}
			a.Paths = append(a.Paths, pr)
		}
		p, err := CompileApp(a)
		if err != nil {
			continue
		}
		for k := 0; k < 20; k++ {
			var b strings.Builder
			for n := r.IntN(5); n > 0; n-- {
				b.WriteString("/" + reqSegs[r.IntN(len(reqSegs))])
			}
			raw := b.String()
			if raw == "" {
				raw = "/"
			}
			method := methods[r.IntN(len(methods))]
			m, cs := p.Candidates(method, raw)
			if m != p.Match(method, raw) {
				t.Fatalf("%s %s: Candidates and Match disagree", method, raw)
			}
			ref := refCandidates(a, m.Path)
			byName := map[string]refCand{}
			for _, c := range ref {
				byName[c.name] = c
			}
			if len(cs) != len(ref)+1 || cs[len(cs)-1].Rule != "allow" {
				t.Fatalf("app %+v\n%s %s: chain %q, reference %+v", a, method, raw, chain(cs), ref)
			}
			selected, firstMatch := -1, -1
			for j, c := range cs {
				if c.Selected {
					if selected >= 0 {
						t.Fatalf("%s %s: two selected rules in %q", method, raw, chain(cs))
					}
					selected = j
				}
				if c.MethodMatches && firstMatch < 0 {
					firstMatch = j
				}
				if j == len(cs)-1 {
					break
				}
				rc, ok := byName[c.Rule]
				if !ok {
					t.Fatalf("app %+v\n%s %s: %s in the chain does not match", a, method, raw, c.Rule)
				}
				if j > 0 && j < len(cs)-1 {
					prev := byName[cs[j-1].Rule]
					if o := rank(prev, rc); o > 0 || (o == 0 && !prev.specific && rc.specific) {
						t.Fatalf("app %+v\n%s %s: %s tried before the more specific %s in %q", a, method, raw, prev.name, rc.name, chain(cs))
					}
				}
			}
			if selected != firstMatch || p.RuleName(m.Rule) != cs[selected].Rule {
				t.Fatalf("app %+v\n%s %s: chain %q, Match chose %s", a, method, raw, chain(cs), p.RuleName(m.Rule))
			}
			checked++
		}
	}
	if checked < 10000 {
		t.Fatalf("only %d requests checked", checked)
	}
}

// TestAuthorizeExplain: an explained decision is Authorize's, with the
// engine's trace when the engine can explain, and without it otherwise.
func TestAuthorizeExplain(t *testing.T) {
	p := wikiPolicy(t)
	ctx := context.Background()
	local := enginetest.NewLocal(t, wikiSchema, engine.Options{},
		"page:plan#viewer@user:alice", "page:plan#space@space:eng",
		"space:eng#admin@group:leads#member", "group:leads#member@user:carol")
	user := func(sub string) *Identity { return &Identity{Provider: "corp", Subject: sub} }
	cases := []struct {
		method, path string
		id           *Identity
		reason       string
		role         check.TraceRole
	}{
		{"GET", "/pages/plan", user("alice"), Allowed, check.RoleGrant},
		{"PUT", "/pages/plan", user("carol"), Allowed, check.RoleGrant},
		{"PUT", "/pages/plan", user("alice"), DeniedCheck, check.RoleDeny},
		{"GET", "/pages/a%20b", user("alice"), DeniedCheckInput, ""},
		{"POST", "/pages/plan", user("alice"), Allowed, ""},
	}
	for _, c := range cases {
		m := p.Match(c.method, c.path)
		want := p.Authorize(ctx, &m, c.id, local, "")
		d := p.AuthorizeExplain(ctx, &m, c.id, local, "", 0)
		if d.Allowed != want.Allowed || d.Reason != want.Reason || d.Reason != c.reason {
			t.Errorf("%s %s: explained %v %s, authorized %v %s, want %s", c.method, c.path, d.Allowed, d.Reason, want.Allowed, want.Reason, c.reason)
			continue
		}
		if c.role == "" {
			if d.Check != nil && d.Check.Trace != nil {
				t.Errorf("%s %s: a trace without a check", c.method, c.path)
			}
			continue
		}
		if want.Check.Trace != nil {
			t.Errorf("%s %s: Authorize traced", c.method, c.path)
		}
		tr := d.Check.Trace
		if tr == nil || tr.Root == nil || tr.Root.Role != c.role || tr.Root.Object != "page:plan" {
			t.Errorf("%s %s: trace %+v", c.method, c.path, tr)
		}
	}

	// The node limit is passed on.
	m := p.Match("PUT", "/pages/plan")
	if d := p.AuthorizeExplain(ctx, &m, user("carol"), local, "", 2); !d.Allowed || d.Check.Trace.Nodes != 2 || !d.Check.Trace.Truncated {
		t.Fatalf("two nodes: %+v %+v", d, d.Check.Trace)
	}
	// A refused token is retried fully consistent, and the retry is
	// explained.
	m = p.Match("GET", "/pages/plan")
	if d := p.AuthorizeExplain(ctx, &m, user("alice"), local, local.Tokens().Encode(1_000_000), 0); !d.Allowed ||
		!d.Check.Retried || d.Check.Trace == nil || d.Check.Request.Consistency.Mode != engine.FullyConsistent {
		t.Fatalf("refused token: %+v %+v", d, d.Check)
	}
	// An engine that cannot explain still answers, without a trace.
	eng := &recorder{Engine: wikiEngine(t)}
	if d := p.AuthorizeExplain(ctx, &m, user("alice"), eng, "", 0); !d.Allowed || d.Check.Trace != nil || eng.count() != 1 {
		t.Fatalf("non-explaining engine: %+v %+v", d, d.Check)
	}
	// Without an engine the answer is the outage, as Authorize's.
	if d := p.AuthorizeExplain(ctx, &m, user("alice"), nil, "", 0); d.Reason != CheckUnavailable || d.Check.Trace != nil {
		t.Fatalf("no engine: %+v", d)
	}
}
