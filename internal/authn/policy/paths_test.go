package policy

import (
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"path"
	"strings"
	"testing"
)

func mustCompile(t testing.TB, a App) *Policy {
	t.Helper()
	p, err := CompileApp(a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var (
	alice = &Identity{Provider: "corp", Subject: "alice", Email: "alice@example.org", Groups: []string{"eng", "admins"}}
	bob   = &Identity{Provider: "corp", Subject: "bob", Email: "bob@example.org"}
	eve   = &Identity{Provider: "other", Subject: "eve", Groups: []string{"admins"}}
)

func wiki(t testing.TB) *Policy {
	return mustCompile(t, App{
		Rule:   Rule{Providers: []string{"corp"}, AnyUser: true},
		Public: []string{"/", "/static/"},
		Paths: []PathRule{
			{Path: "/wiki", Methods: []string{"GET"}, Public: true},              // paths[0]
			{Path: "/wiki", AnyUser: true},                                       // paths[1]
			{Path: "/wiki/{page}/history", Groups: []string{"eng"}},              // paths[2]
			{Path: "/wiki/new", Exact: true, Groups: []string{"eng"}},            // paths[3]
			{Path: "/admin", Groups: []string{"admins"}},                         // paths[4]
			{Path: "/admin/audit", Methods: []string{"DELETE"}, Deny: true},      // paths[5]
			{Path: "/api/{org}/docs/{doc}", Emails: []string{"bob@example.org"}}, // paths[6]
			{Path: "/api/acme/docs", Groups: []string{"admins"}},                 // paths[7]
			{Path: "/", Exact: true, Methods: []string{"POST"}, Deny: true},      // paths[8]
		},
	})
}

func TestMatchOrder(t *testing.T) {
	p := wiki(t)
	cases := []struct {
		method, path string
		rule         string
		params       []string
	}{
		// The root prefix catches everything no deeper rule takes.
		{"GET", "/", "public[0]", nil},
		{"GET", "/about", "public[0]", nil},
		{"POST", "/elsewhere", "public[0]", nil},
		// An exact rule beats a prefix at the same depth, for its methods.
		{"POST", "/", "paths[8]", nil},
		{"GET", "/static/app.js", "public[1]", nil},
		// A rule that lists the method beats one that lists none; GET
		// covers HEAD; other methods fall to the every-method rule.
		{"GET", "/wiki/home", "paths[0]", nil},
		{"HEAD", "/wiki/home", "paths[0]", nil},
		{"POST", "/wiki/home", "paths[1]", nil},
		{"PROPFIND", "/wiki/home", "paths[1]", nil},
		// Deeper wins, through a parameter.
		{"GET", "/wiki/home/history", "paths[2]", []string{"home"}},
		{"GET", "/wiki/home/history/3", "paths[2]", []string{"home"}},
		// Exact only at its own path.
		{"GET", "/wiki/new", "paths[3]", nil},
		{"GET", "/wiki/new/", "paths[3]", nil},
		{"GET", "/wiki/new/draft", "paths[0]", nil},
		// "new" is also a page name: the parameter rule is deeper.
		{"GET", "/wiki/new/history", "paths[2]", []string{"new"}},
		// Segment boundaries.
		{"GET", "/wikipedia", "public[0]", nil},
		{"GET", "/admin", "paths[4]", nil},
		{"GET", "/admin/audit", "paths[4]", nil},
		{"DELETE", "/admin/audit/7", "paths[5]", nil},
		// A literal beats a parameter at the same depth; deeper still wins.
		{"GET", "/api/acme/docs", "paths[7]", nil},
		{"GET", "/api/other/docs", "public[0]", nil},
		{"GET", "/api/acme/docs/d1", "paths[6]", []string{"acme", "d1"}},
		{"GET", "/api/x/docs/d%20e", "paths[6]", []string{"x", "d e"}},
	}
	for _, c := range cases {
		m := p.Match(c.method, c.path)
		if m.Bad || p.RuleName(m.Rule) != c.rule {
			t.Errorf("%s %s: matched %s (bad %v), want %s", c.method, c.path, p.RuleName(m.Rule), m.Bad, c.rule)
			continue
		}
		if got := m.Params[:m.NParams]; strings.Join(got, ",") != strings.Join(c.params, ",") {
			t.Errorf("%s %s: params %q, want %q", c.method, c.path, got, c.params)
		}
	}
	m := p.Match("GET", "/api/acme/docs/d1")
	if v, ok := p.Param(&m, "doc"); !ok || v != "d1" {
		t.Errorf("Param(doc) = %q %v", v, ok)
	}
	if v, ok := p.Param(&m, "org"); !ok || v != "acme" {
		t.Errorf("Param(org) = %q %v", v, ok)
	}
	if _, ok := p.Param(&m, "page"); ok {
		t.Error("Param(page) of a rule without it")
	}
	if p.RulePattern(m.Rule) != "/api/{org}/docs/{doc}" || p.RulePattern(-1) != "" || p.RuleName(-1) != "allow" {
		t.Errorf("patterns: %q %q %q", p.RulePattern(m.Rule), p.RulePattern(-1), p.RuleName(-1))
	}
}

func TestEvaluatePaths(t *testing.T) {
	p := wiki(t)
	cases := []struct {
		method, path string
		id           *Identity
		ok           bool
		reason       string
	}{
		{"GET", "/wiki/home", nil, true, AllowedPublic},
		{"POST", "/wiki/home", nil, false, DeniedNoSubject},
		{"POST", "/wiki/home", bob, true, Allowed},
		{"POST", "/wiki/home", eve, false, DeniedProvider},
		{"GET", "/wiki/home/history", bob, false, DeniedNoMatch},
		{"GET", "/wiki/home/history", alice, true, Allowed},
		{"GET", "/admin/users", alice, true, Allowed},
		{"GET", "/admin/users", bob, false, DeniedNoMatch},
		// The app's providers bind every path rule.
		{"GET", "/admin/users", eve, false, DeniedProvider},
		{"DELETE", "/admin/audit", alice, false, DeniedRule},
		{"POST", "/", alice, false, DeniedRule},
		{"GET", "/api/acme/docs/1", bob, true, Allowed},
		{"GET", "/api/acme/docs", bob, false, DeniedNoMatch},
		// Traversal is resolved before matching, so it cannot reach a
		// public prefix from a protected path or the reverse.
		{"GET", "/static/../admin/users", bob, false, DeniedNoMatch},
		{"GET", "/static/%2e%2e/admin/users", bob, false, DeniedNoMatch},
		{"GET", "/wiki/x/./history", bob, false, DeniedNoMatch},
		{"GET", "//admin//users", bob, false, DeniedNoMatch},
		{"GET", "/admin/../static/x", nil, true, AllowedPublic},
		// What upstreams read differently is refused.
		{"GET", "/static%2F..%2Fadmin", alice, false, DeniedBadPath},
		{"GET", "/static/..%5Cadmin", alice, false, DeniedBadPath},
		{"GET", "/static/..\\admin", alice, false, DeniedBadPath},
		{"GET", "/static/..;/admin", alice, false, DeniedBadPath},
		{"GET", "/admin;jsessionid=1", alice, false, DeniedBadPath},
		{"GET", "/admin%00", alice, false, DeniedBadPath},
		{"GET", "/admin%zz", alice, false, DeniedBadPath},
		{"GET", "/admin%2", alice, false, DeniedBadPath},
		{"GET", "admin", alice, false, DeniedBadPath},
		{"GET", "", alice, false, DeniedBadPath},
	}
	for _, c := range cases {
		ok, reason := p.Decide(c.method, c.path, c.id)
		if ok != c.ok || reason != c.reason {
			who := "anonymous"
			if c.id != nil {
				who = c.id.Subject
			}
			t.Errorf("%s %s as %s: got %v %s, want %v %s", c.method, c.path, who, ok, reason, c.ok, c.reason)
		}
	}
}

// TestNoPathRules: an app with only the app-wide rule never looks at the
// path, so its decisions are those it made before path rules existed,
// whatever the path, even one with path rules would refuse.
func TestNoPathRules(t *testing.T) {
	p := mustCompile(t, App{Rule: Rule{Providers: []string{"corp"}, Groups: []string{"eng"}}})
	if p.HasPathRules() {
		t.Fatal("HasPathRules")
	}
	for _, raw := range []string{"/", "", "/a;b", "/%2F", "x"} {
		m := p.Match("GET", raw)
		if m.Bad || m.Public || m.Rule != -1 {
			t.Errorf("%q: %+v", raw, m)
		}
		if ok, reason := p.Evaluate(&m, alice); !ok || reason != Allowed {
			t.Errorf("%q alice: %v %s", raw, ok, reason)
		}
		if ok, reason := p.Evaluate(&m, bob); ok || reason != DeniedNoMatch {
			t.Errorf("%q bob: %v %s", raw, ok, reason)
		}
	}
}

func TestCompileAppErrors(t *testing.T) {
	cases := []struct {
		name string
		app  App
		want []string
	}{
		{"relative", App{Paths: []PathRule{{Path: "docs", AnyUser: true}}}, []string{"paths[0]: path \"docs\" must start with '/'"}},
		{"empty", App{Public: []string{""}}, []string{"public[0]: path \"\" must start with '/'"}},
		{"dot dot", App{Public: []string{"/a/../b"}}, []string{"public[0]: path \"/a/../b\" has an empty, '.' or '..' segment"}},
		{"double slash", App{Public: []string{"/a//b"}}, []string{"empty, '.' or '..' segment"}},
		{"escape", App{Public: []string{"/a%20b"}}, []string{"may not contain"}},
		{"wildcard", App{Public: []string{"/a/*"}}, []string{"may not contain"}},
		{"space", App{Public: []string{"/a b"}}, []string{"visible ASCII"}},
		{"partial param", App{Public: []string{"/a/x{id}"}}, []string{"a parameter is a whole segment"}},
		{"bad param", App{Public: []string{"/a/{ID}"}}, []string{"a parameter is a whole segment"}},
		{"unclosed param", App{Public: []string{"/a/{id"}}, []string{"a parameter is a whole segment"}},
		{"digit param", App{Public: []string{"/a/{1x}"}}, []string{"a parameter is a whole segment"}},
		{"repeated param", App{Public: []string{"/a/{id}/{id}"}}, []string{"parameter {id} appears twice"}},
		{"too many params", App{Public: []string{"/{a}/{b}/{c}/{d}/{e}/{f}/{g}/{h}/{i}"}}, []string{"more than 8 parameters"}},
		{"unknown method", App{Paths: []PathRule{{Path: "/", Methods: []string{"get"}, Deny: true}}}, []string{"unknown method \"get\""}},
		{"repeated method", App{Paths: []PathRule{{Path: "/", Methods: []string{"PUT", "PUT"}, Deny: true}}}, []string{"method \"PUT\" is listed twice"}},
		{"public and deny", App{Paths: []PathRule{{Path: "/", Public: true, Deny: true}}}, []string{"both public and deny"}},
		{"public with allow", App{Paths: []PathRule{{Path: "/", Public: true, Groups: []string{"x"}}}}, []string{"takes no allow"}},
		{"duplicate", App{Public: []string{"/a"}, Paths: []PathRule{{Path: "/a/", AnyUser: true}}},
			[]string{`public[0]: pattern "/a" overlaps paths[0] ("/a") for the same methods`}},
		{"same shape", App{Paths: []PathRule{{Path: "/d/{id}", AnyUser: true}, {Path: "/d/{name}", Deny: true}}},
			[]string{`paths[1]: pattern "/d/{name}" overlaps paths[0] ("/d/{id}")`}},
		{"method overlap", App{Paths: []PathRule{{Path: "/d", Methods: []string{"GET", "POST"}, AnyUser: true},
			{Path: "/d", Methods: []string{"HEAD"}, Deny: true}}}, []string{"paths[1]: pattern \"/d\" overlaps paths[0]"}},
		{"every error", App{Public: []string{"x", "/a/../b"}}, []string{"public[0]", "public[1]"}},
	}
	for _, c := range cases {
		_, err := CompileApp(c.app)
		if err == nil {
			t.Errorf("%s: compiled", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not mention %q", c.name, err, w)
			}
		}
		var re *RuleError
		if !errors.As(err, &re) {
			t.Errorf("%s: %T is not a RuleError", c.name, err)
		}
	}
	// These do not overlap: different exactness, disjoint methods, an
	// every-method rule beside method rules, a literal beside a parameter.
	mustCompile(t, App{Paths: []PathRule{
		{Path: "/d", AnyUser: true}, {Path: "/d", Exact: true, Deny: true},
		{Path: "/d", Methods: []string{"GET"}, Public: true}, {Path: "/d", Methods: []string{"POST", "PUT"}, Deny: true},
		{Path: "/d/{id}", AnyUser: true}, {Path: "/d/new", Deny: true},
	}})
}

func TestCleanPath(t *testing.T) {
	cases := []struct{ in, out string }{
		{"/", "/"},
		{"/a/b", "/a/b"},
		{"/a/b/", "/a/b/"},
		{"/a//b", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/b/..", "/a"},
		{"/..", "/"},
		{"/../../a", "/a"},
		{"/%61%62", "/ab"},
		{"/a%2e%2E/b", "/a../b"},
		{"/%2e%2e/a", "/a"},
		{"/a/%2E", "/a"},
		{"/%25", "/%"},
		{"/caf%C3%A9", "/café"},
		{"/a..b/.c", "/a..b/.c"},
	}
	for _, c := range cases {
		if got, ok := cleanPath(c.in); !ok || got != c.out {
			t.Errorf("cleanPath(%q) = %q %v, want %q", c.in, got, ok, c.out)
		}
	}
	for _, bad := range []string{"", "a", "/a%2fb", "/a%5cb", "/a%3bb", "/a%00", "/a%1f", "/a%7f", "/a\x01", "/a\\b", "/a;b", "/%", "/%a", "/%g0"} {
		if got, ok := cleanPath(bad); ok {
			t.Errorf("cleanPath(%q) = %q, want refused", bad, got)
		}
	}
	if n := testing.AllocsPerRun(100, func() { cleanPath("/wiki/page/history") }); n != 0 {
		t.Errorf("a clean path allocates %v times", n)
	}
}

// TestMatchDoesNotAllocate: matching a clean path, with parameters,
// allocates nothing.
func TestMatchDoesNotAllocate(t *testing.T) {
	p := wiki(t)
	for _, c := range [][2]string{{"GET", "/api/acme/docs/d1"}, {"POST", "/wiki/x"}, {"GET", "/nowhere/at/all"}} {
		if n := testing.AllocsPerRun(100, func() { p.Decide(c[0], c[1], alice) }); n != 0 {
			t.Errorf("%s %s allocates %v times", c[0], c[1], n)
		}
	}
}

// refMatch is a deliberately naive restatement of the matching order: for
// every rule, test it against the path with plain string handling, then
// sort the candidates by the four order rules.
func refMatch(a App, method, raw string) (string, bool) {
	clean, ok := refClean(raw)
	if !ok {
		return "", false
	}
	type cand struct {
		name     string
		depth    int
		exact    bool
		shape    string // per segment 'l' literal or 'p' parameter
		specific bool
	}
	var cands []cand
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
		specific := false
		if len(r.Methods) > 0 {
			for _, m := range r.Methods {
				if m == method || (m == "GET" && method == "HEAD") {
					specific = true
				}
			}
			if !specific {
				return
			}
		}
		cands = append(cands, cand{name, len(pat), r.Exact, shape, specific})
	}
	for i, r := range a.Paths {
		try(fmt.Sprintf("paths[%d]", i), r)
	}
	for i, pub := range a.Public {
		try(fmt.Sprintf("public[%d]", i), PathRule{Path: pub, Public: true})
	}
	best := -1
	better := func(x, y cand) bool {
		if x.depth != y.depth {
			return x.depth > y.depth
		}
		if x.exact != y.exact {
			return x.exact
		}
		if x.shape != y.shape {
			return x.shape < y.shape // 'l' < 'p': literal first at the first difference
		}
		return x.specific && !y.specific
	}
	for i, c := range cands {
		if best < 0 || better(c, cands[best]) {
			best = i
		}
	}
	if best < 0 {
		return "allow", true
	}
	return cands[best].name, true
}

func refClean(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\;") {
		return "", false
	}
	var b []byte
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '%' {
			if i+2 >= len(raw) {
				return "", false
			}
			var v byte
			if _, err := fmt.Sscanf(raw[i+1:i+3], "%02x", &v); err != nil || strings.ContainsAny(raw[i+1:i+3], "+- ") {
				return "", false
			}
			c = v
			i += 2
			if c == '/' || c == '\\' || c == ';' {
				return "", false
			}
		}
		if c < 0x20 || c == 0x7f {
			return "", false
		}
		b = append(b, c)
	}
	return path.Clean(string(b)), true
}

// TestPropertyMatchMatchesReference compares the trie with the naive
// matcher on random rule sets and requests over a small alphabet, so
// overlaps, parameters, traversal and method fallbacks are frequent.
func TestPropertyMatchMatchesReference(t *testing.T) {
	r := mrand.New(mrand.NewPCG(11, 12))
	segs := []string{"a", "b", "docs", "{x}", "{y}"}
	reqSegs := []string{"a", "b", "docs", "c", ".", "..", "", "%61", "%2e%2e", "d%3Bx"}
	methods := []string{"GET", "HEAD", "POST", "DELETE"}
	randPattern := func() string {
		var b strings.Builder
		n := r.IntN(4)
		used := map[string]bool{}
		for i := 0; i < n; i++ {
			s := segs[r.IntN(len(segs))]
			if used[s] && s[0] == '{' {
				s = "c"
			}
			used[s] = true
			b.WriteString("/" + s)
		}
		if b.Len() == 0 || r.IntN(4) == 0 {
			b.WriteByte('/')
		}
		return b.String()
	}
	checked := 0
	for i := 0; i < 3000; i++ {
		var a App
		for j := r.IntN(8); j > 0; j-- {
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
			continue // overlapping rules; the compile error tests cover them
		}
		for k := 0; k < 30; k++ {
			var b strings.Builder
			for n := r.IntN(5); n > 0; n-- {
				b.WriteString("/" + reqSegs[r.IntN(len(reqSegs))])
			}
			raw := b.String()
			if raw == "" {
				raw = "/"
			}
			method := methods[r.IntN(len(methods))]
			m := p.Match(method, raw)
			want, ok := refMatch(a, method, raw)
			if !p.HasPathRules() {
				continue
			}
			checked++
			if m.Bad != !ok || (ok && p.RuleName(m.Rule) != want) {
				t.Fatalf("app %+v\n%s %s: matched %s (bad %v), reference %s (ok %v)", a, method, raw, p.RuleName(m.Rule), m.Bad, want, ok)
			}
		}
	}
	if checked < 10000 {
		t.Fatalf("only %d requests checked", checked)
	}
}

// FuzzMatch: whatever the path, matching does not panic, a path it accepts
// is clean (no '\', ';', control bytes, "." or ".." segments or repeated
// slashes) and resolves to itself, and the trie agrees with the naive
// matcher on a rule set with overlaps, parameters and methods.
func FuzzMatch(f *testing.F) {
	for _, s := range []string{"/", "/wiki/x/history", "/static/../admin", "/a%2fb", "/api/acme/docs/d1", "//x/./y/..", "/%2e%2e/%2e", "/a;b"} {
		f.Add("GET", s)
	}
	f.Add("DELETE", "/admin/audit/1")
	f.Add("PROPFIND", "/wiki")
	p := wiki(f)
	a := App{
		Rule:   Rule{Providers: []string{"corp"}, AnyUser: true},
		Public: []string{"/", "/static/"},
		Paths: []PathRule{
			{Path: "/wiki", Methods: []string{"GET"}, Public: true},
			{Path: "/wiki", AnyUser: true},
			{Path: "/wiki/{page}/history", Groups: []string{"eng"}},
			{Path: "/wiki/new", Exact: true, Groups: []string{"eng"}},
			{Path: "/admin", Groups: []string{"admins"}},
			{Path: "/admin/audit", Methods: []string{"DELETE"}, Deny: true},
			{Path: "/api/{org}/docs/{doc}", Emails: []string{"bob@example.org"}},
			{Path: "/api/acme/docs", Groups: []string{"admins"}},
			{Path: "/", Exact: true, Methods: []string{"POST"}, Deny: true},
		},
	}
	f.Fuzz(func(t *testing.T, method, raw string) {
		m := p.Match(method, raw)
		p.Evaluate(&m, alice)
		want, ok := refMatch(a, method, raw)
		if m.Bad == ok {
			t.Fatalf("%q: bad %v, reference ok %v", raw, m.Bad, ok)
		}
		if !ok {
			return
		}
		if p.RuleName(m.Rule) != want {
			t.Fatalf("%s %q: matched %s, reference %s", method, raw, p.RuleName(m.Rule), want)
		}
		if strings.ContainsAny(m.Path, `\;`) || needsClean(m.Path) || m.Path[0] != '/' {
			t.Fatalf("%q cleaned to %q", raw, m.Path)
		}
		if again, ok := cleanPath(strings.ReplaceAll(m.Path, "%", "%25")); !ok || again != m.Path {
			t.Fatalf("%q cleaned to %q, which cleans to %q %v", raw, m.Path, again, ok)
		}
		for _, v := range m.Params[:m.NParams] {
			if v == "" || strings.Contains(v, "/") {
				t.Fatalf("%q: parameter %q", raw, v)
			}
		}
	})
}

// TestMethods: every method a rule can list matches itself only, and GET
// also HEAD.
func TestMethods(t *testing.T) {
	for _, m := range methodBits {
		p := mustCompile(t, App{Rule: Rule{Providers: []string{"corp"}, AnyUser: true},
			Paths: []PathRule{{Path: "/x", Methods: []string{m}, Deny: true}}})
		for _, req := range methodBits {
			want := req == m || (m == "GET" && req == "HEAD")
			if got := p.Match(req, "/x").Rule == 0; got != want {
				t.Errorf("rule %s, request %s: matched %v", m, req, got)
			}
		}
		if p.Match("get", "/x").Rule != -1 {
			t.Errorf("rule %s matches a lower-case method", m)
		}
	}
}
