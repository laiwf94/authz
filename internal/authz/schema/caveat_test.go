package schema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/cel"
)

const caveated = `
definition user {}

definition group {
  relation member: user | user with on_shift
}

// Caveats may come after the definitions that use them.
definition document {
  relation viewer: user | user with ip_allowed | user:* with ip_allowed | group#member with ip_allowed
  relation editor: user with on_shift
  permission view = viewer + editor
}

caveat ip_allowed(allowed list<cidr>, client_ip ipaddress) {
  // Any of the allowed ranges.
  allowed.exists(r, r.containsIP(client_ip))
}

caveat on_shift(now timestamp, start timestamp, length duration, tags map<string, list<string>>) {
  now >= start &&
    now < start + length &&
    "{}" != '}' // braces inside strings and comments: } {
}
`

func TestCaveatsParse(t *testing.T) {
	s := mustParse(t, caveated)
	if got := strings.Join(s.CaveatOrder, ","); got != "ip_allowed,on_shift" {
		t.Fatalf("caveat order = %s", got)
	}
	if got := strings.Join(s.Order, ","); got != "user,group,document" {
		t.Fatalf("definition order = %s", got)
	}
	c := s.Caveats["on_shift"]
	want := []string{"now timestamp", "start timestamp", "length duration", "tags map<string, list<string>>"}
	for i, p := range c.Params {
		if got := p.Name + " " + p.Type.String(); got != want[i] {
			t.Errorf("param %d = %s, want %s", i, got, want[i])
		}
	}
	if typ, ok := c.Param("length"); !ok || !typ.Equal(cel.Duration) {
		t.Fatalf("Param(length) = %v, %v", typ, ok)
	}
	if _, ok := c.Param("nope"); ok {
		t.Fatal("Param found an undeclared name")
	}
	if !strings.HasPrefix(c.Expr, "now >= start &&\n") || !strings.HasSuffix(c.Expr, "} {") {
		t.Fatalf("Expr = %q", c.Expr)
	}
	if got := strings.Join(c.Checked.Vars(), ","); got != "length,now,start" {
		t.Fatalf("Vars = %s", got)
	}

	ip := s.Caveats["ip_allowed"]
	r, err := ip.Program.Eval(map[string]any{"allowed": []any{"10.0.0.0/8"}, "client_ip": "10.1.2.3"})
	if err != nil || r.Value != true {
		t.Fatalf("ip_allowed in range = %+v, %v", r, err)
	}
	r, err = ip.Program.Eval(map[string]any{"allowed": []any{"10.0.0.0/8"}})
	if err != nil || r.Known() || strings.Join(r.Missing, ",") != "client_ip" {
		t.Fatalf("ip_allowed without client_ip = %+v, %v", r, err)
	}

	doc := s.Defs["document"].Relations["viewer"]
	if got := doc.Allowed[1].String(); got != "user with ip_allowed" {
		t.Fatalf("allowed[1] = %s", got)
	}
	if got := doc.Allowed[2].String(); got != "user:* with ip_allowed" {
		t.Fatalf("allowed[2] = %s", got)
	}
	if got := doc.Allowed[3].String(); got != "group#member with ip_allowed" {
		t.Fatalf("allowed[3] = %s", got)
	}
	for _, c := range []struct {
		typ, id, rel, caveat string
		want                 bool
	}{
		{"user", "alice", "", "", true},
		{"user", "alice", "", "ip_allowed", true},
		{"user", "alice", "", "on_shift", false},
		{"user", "*", "", "ip_allowed", true},
		{"user", "*", "", "", false},
		{"group", "eng", "member", "ip_allowed", true},
		{"group", "eng", "member", "", false},
	} {
		if got := doc.AllowsCaveat(c.typ, c.id, c.rel, c.caveat); got != c.want {
			t.Errorf("viewer.AllowsCaveat(%s:%s#%s with %q) = %v", c.typ, c.id, c.rel, c.caveat, got)
		}
	}
	// A subject type listed only with a caveat takes no plain relationship.
	editor := s.Defs["document"].Relations["editor"]
	if editor.Allows("user", "alice", "") || !editor.AllowsCaveat("user", "alice", "", "on_shift") {
		t.Fatal("editor: a caveat-only subject type must require the caveat")
	}
}

func TestCaveatsCanonicalRoundTrip(t *testing.T) {
	s := mustParse(t, caveated)
	out := s.String()
	wantPrefix := "caveat ip_allowed(allowed list<cidr>, client_ip ipaddress) {\n" +
		"  // Any of the allowed ranges.\n" +
		"  allowed.exists(r, r.containsIP(client_ip))\n" +
		"}\n\n" +
		"caveat on_shift(now timestamp, start timestamp, length duration, tags map<string, list<string>>) {\n" +
		"  now >= start &&\n"
	if !strings.HasPrefix(out, wantPrefix) {
		t.Fatalf("canonical form:\n%s", out)
	}
	if !strings.Contains(out, "}\n\ndefinition user {}\n") {
		t.Fatalf("no blank line between caveats and definitions:\n%s", out)
	}
	if !strings.Contains(out, "  relation viewer: user | user with ip_allowed | user:* with ip_allowed | group#member with ip_allowed\n") {
		t.Fatalf("caveated subject types not rendered:\n%s", out)
	}
	s2 := mustParse(t, out)
	if s2.String() != out {
		t.Fatalf("round trip changed the schema:\n%s\n---\n%s", out, s2.String())
	}
	if d := Compare(s, s2); len(d.Changes) != 0 {
		t.Fatalf("round trip changed the meaning: %s", renderChanges(d.Changes))
	}

	// A schema without caveats renders exactly as before.
	plain := mustParse(t, docs).String()
	if strings.HasPrefix(plain, "\n") || strings.Contains(plain, "caveat") {
		t.Fatalf("plain schema rendering changed:\n%s", plain)
	}
}

// The body scanner must find the closing brace whatever the strings in
// the expression hold; each case round-trips and keeps its meaning.
func TestCaveatBodyScanning(t *testing.T) {
	cases := map[string]string{
		"map literal":        `{"a": 1}["a"] == x`,
		"nested maps":        `{"a": {"b": x}}["a"]["b"] == 1`,
		"escaped quote":      `"a\"}" != string(x)`,
		"single quotes":      `'}{' != string(x) && '\'' == "'"`,
		"raw backslash":      `r"\" != string(x)`,
		"raw single":         `R'}\' != string(x)`,
		"triple double":      "\"\"\"line one }\nline two {\"\"\" != string(x)",
		"triple single":      "'''a ' '' }''' != string(x)",
		"escaped triple":     `"""a \""" }""" != string(x)`,
		"comment brace":      "x == 1 // }\n",
		"comment at the end": "x == 1 // the end",
		"division":           "x / 2 == 1",
	}
	for name, body := range cases {
		src := "caveat c(x int) {\n" + body + "\n}\ndefinition user {}"
		s, err := Parse(src)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := s.Caveats["c"].Expr; got != strings.Trim(body, " \n") {
			t.Errorf("%s: Expr = %q, want %q", name, got, body)
		}
		out := s.String()
		s2, err := Parse(out)
		if err != nil {
			t.Errorf("%s: canonical form does not parse: %v\n%s", name, err, out)
			continue
		}
		if s2.String() != out || s2.Caveats["c"].meaning() != s.Caveats["c"].meaning() {
			t.Errorf("%s: round trip changed the caveat:\n%s\n---\n%s", name, out, s2.String())
		}
	}
}

func TestCaveatErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"caveat", "expected name"},
		{"caveat C(x int) { x > 1 }", "invalid caveat name"},
		{"caveat c { x }", "expected '('"},
		{"caveat c() { true }", "expected name"},
		{"caveat c(x) { true }", "expected a type, found ')'"},
		{"caveat c(x int y int) { true }", "expected ',' or ')'"},
		{"caveat c(x int, x int) { true }", `parameter "x" is declared twice`},
		{"caveat c(X int) { true }", "invalid parameter name"},
		{"caveat c(in int) { true }", `parameter name "in" is reserved`},
		{"caveat c(for int) { true }", `parameter name "for" is reserved`},
		{"caveat c(x integer) { true }", `parameter x of caveat "c": type "integer": unknown type "integer"`},
		{"caveat c(x map<list<int>, int>) { true }", "map keys must be"},
		{"caveat c(x list<int, int>) { true }", `type "list<int, int>"`},
		{"caveat c(x list<int) { true }", "expected ',' or '>'"},
		{"caveat c(x list<) { true }", "expected a type, found ')'"},
		{"caveat c(x " + strings.Repeat("list<", 17) + "int" + strings.Repeat(">", 17) + ") { true }", "nested too deeply"},
		{"caveat c(x int) x > 1", "expected '{'"},
		{"caveat c(x int) { x > 1 ", "no closing '}'"},
		{"caveat c(x int) { x == {1: 2}[1] ", "no closing '}'"},
		{"caveat c(x int) { string(x) == \"a }", "no closing quote"},
		{"caveat c(x int) { string(x) == 'a\n' }", "newline in string"},
		{"caveat c(x int) { string(x) == '''a }", "no closing quote"},
		{"caveat c(x int) { x + 1 }", "expression is int, want bool"},
		{"caveat c(x int) { y > 1 }", "undeclared"},
		{"caveat c(x int) { x > 'a' }", `caveat "c"`},
		{"caveat c(x int) { }", `caveat "c"`},
		{"caveat c(x int) { true } caveat c(y int) { true }", `caveat "c" is declared twice`},
		{"caveat c(x int) { true } definition c {}", `caveat "c" is declared twice`},
		{"definition c {} caveat c(x int) { true }", `definition "c" is declared twice`},
		{"definition user {} definition d { relation r: user with nope }", `d#r allows user with nope, but there is no caveat "nope"`},
		{"definition user {} definition d { relation r: user with }", "expected name"},
		{"definition user {} definition d { relation r: user with C }", "invalid caveat name"},
		{"caveat c(x int) { true } definition user {} definition d { relation r: user with c | user with c }", "listed twice"},
		{"policy x {}", `expected "definition" or "caveat", found "policy"`},
	}
	for _, c := range cases {
		_, err := Parse(c.src)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q) error = %v, want it to mention %q", c.src, err, c.want)
		}
	}
}

// CEL errors are reported where they are in the schema, not in the body.
func TestCaveatErrorPositions(t *testing.T) {
	cases := []struct {
		src       string
		line, col int
	}{
		// "y" is undeclared, on the caveat's first line.
		{"definition user {}\ncaveat c(x int) { x > 1 && y }", 2, 28},
		// On a later line of the body the column is the body's own.
		{"caveat c(x int) {\n  x > 1 &&\n    y\n}", 3, 5},
		// The body must be bool: the error is at its root, the '+'.
		{"caveat c(x int) {\n\n  x + 1\n}", 3, 5},
		// A lexical error in the schema keeps its own position.
		{"definition a {\n  relation x: a $\n}", 2, 17},
	}
	for _, c := range cases {
		_, err := Parse(c.src)
		e, ok := err.(*Error)
		if !ok || e.Line != c.line || e.Col != c.col {
			t.Errorf("Parse(%q) = %v, want an error at %d:%d", c.src, err, c.line, c.col)
		}
	}
	_, err := Parse("caveat c(x int) { y > z }")
	if err == nil || !strings.Contains(err.Error(), "(and 1 more)") {
		t.Fatalf("second error not counted: %v", err)
	}
}

func TestCaveatLimits(t *testing.T) {
	var params []string
	for i := 0; i < MaxCaveatParams; i++ {
		params = append(params, "p"+itoa(i)+" int")
	}
	if _, err := Parse("caveat c(" + strings.Join(params, ", ") + ") { p0 > 1 }"); err != nil {
		t.Fatalf("%d parameters rejected: %v", MaxCaveatParams, err)
	}
	params = append(params, "q int")
	if _, err := Parse("caveat c(" + strings.Join(params, ", ") + ") { p0 > 1 }"); err == nil || !strings.Contains(err.Error(), "too many parameters") {
		t.Fatalf("parameter limit not enforced: %v", err)
	}

	var b strings.Builder
	for i := 0; i < MaxCaveats; i++ {
		b.WriteString("caveat c" + itoa(i) + "(x int) { x > 1 }\n")
	}
	if _, err := Parse(b.String()); err != nil {
		t.Fatalf("%d caveats rejected: %v", MaxCaveats, err)
	}
	b.WriteString("caveat z(x int) { x > 1 }\n")
	if _, err := Parse(b.String()); err == nil || !strings.Contains(err.Error(), "too many caveats") {
		t.Fatalf("caveat limit not enforced: %v", err)
	}

	// The CEL limits apply to the body.
	long := "caveat c(x int) { " + strings.Repeat("x > 1 || ", cel.DefaultLimits.MaxSourceBytes/9) + "true }"
	if _, err := Parse(long); err == nil || !strings.Contains(err.Error(), "more than the limit") {
		t.Fatalf("CEL source limit not enforced: %v", err)
	}
}

func TestCaveatValidateContext(t *testing.T) {
	s := mustParse(t, caveated)
	c := s.Caveats["on_shift"]
	var decoded map[string]any
	if err := json.Unmarshal([]byte(`{"start": "2026-11-23T09:00:00Z", "length": "8h", "tags": {"a": ["x"]}}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateContext(decoded); err != nil {
		t.Fatalf("JSON context refused: %v", err)
	}
	if err := c.ValidateContext(map[string]any{"now": time.Now(), "length": time.Hour}); err != nil {
		t.Fatalf("native context refused: %v", err)
	}
	if err := c.ValidateContext(nil); err != nil {
		t.Fatalf("empty context refused: %v", err)
	}
	for ctx, want := range map[string]string{
		`{"start": "yesterday"}`:               `caveat on_shift parameter start`,
		`{"length": 5}`:                        `caveat on_shift parameter length`,
		`{"tags": {"a": [1]}}`:                 `caveat on_shift parameter tags`,
		`{"zone": "UTC", "tags": {}}`:          `caveat on_shift has no parameter "zone"`,
		`{"now": null}`:                        `parameter now is null`,
		`{"allowed": [], "length": "forever"}`: `has no parameter "allowed"`,
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(ctx), &m); err != nil {
			t.Fatal(err)
		}
		if err := c.ValidateContext(m); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateContext(%s) = %v, want it to mention %q", ctx, err, want)
		}
	}
}

func TestCompareCaveats(t *testing.T) {
	const base = `
caveat a(x int) { x > 1 }
caveat b(x int) { x > 2 }
caveat gone(x int) { x > 3 }
definition user {}
definition doc {
  relation viewer: user | user with a
  relation editor: user with b
  relation owner: user
  permission edit = editor + owner
  permission view = viewer + edit
  permission own = owner
}
`
	prev := mustParse(t, base)

	// Spacing, comments and redundant parentheses change nothing.
	same := strings.Replace(base, "caveat a(x int) { x > 1 }", "caveat a(x int) {\n  // one\n  (x) > (1)\n}", 1)
	if d := Compare(prev, mustParse(t, same)); len(d.Changes) != 0 || len(d.Affected) != 0 {
		t.Fatalf("cosmetic caveat change reported: %s %v", renderChanges(d.Changes), d.Affected)
	}

	next := strings.Replace(base, "x > 2", "x > 20", 1)
	next = strings.Replace(next, "caveat gone(x int) { x > 3 }", "caveat added(y string) { y == 'a' }", 1)
	d := Compare(prev, mustParse(t, next))
	want := "changed caveat b: (x int) (x > 2) -> (x int) (x > 20)\n" +
		"added caveat added\n" +
		"removed caveat gone\n"
	if got := renderChanges(d.Changes); got != want {
		t.Fatalf("changes:\n%s\nwant:\n%s", got, want)
	}
	// b guards editor, which edit and view read; own does not reach it.
	if got := strings.Join(d.Affected, ","); got != "doc#edit,doc#view" {
		t.Fatalf("affected = %s", got)
	}

	// A new parameter type is a change too.
	retyped := strings.Replace(base, "caveat a(x int) { x > 1 }", "caveat a(x uint) { x > 1u }", 1)
	d = Compare(prev, mustParse(t, retyped))
	if got := renderChanges(d.Changes); got != "changed caveat a: (x int) (x > 1) -> (x uint) (x > 1u)\n" {
		t.Fatalf("retyped: %s", got)
	}
	if got := strings.Join(d.Affected, ","); got != "doc#view" {
		t.Fatalf("retyped affected = %s", got)
	}

	// Putting a caveat on a subject type changes the relation itself.
	moved := strings.Replace(base, "relation owner: user\n", "relation owner: user with a\n", 1)
	d = Compare(prev, mustParse(t, moved))
	if got := renderChanges(d.Changes); got != "changed relation doc#owner: user -> user with a\n" {
		t.Fatalf("moved: %s", got)
	}
	if got := strings.Join(d.Affected, ","); got != "doc#edit,doc#view,doc#own" {
		t.Fatalf("moved affected = %s", got)
	}

	// From nothing, every caveat is added.
	d = Compare(nil, prev)
	if got := renderChanges(d.Changes); !strings.HasSuffix(got, "added caveat a\nadded caveat b\nadded caveat gone\n") {
		t.Fatalf("from nothing:\n%s", got)
	}
}
