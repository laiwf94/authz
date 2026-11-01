package schema

import (
	"strings"
	"testing"
)

const docs = `
// A small document-sharing model.
definition user {}

definition group {
  relation member: user | group#member
}

definition folder {
  relation parent: folder
  relation viewer: user | user:* | group#member
  permission view = viewer + parent->view
}

definition document {
  relation parent: folder
  relation owner: user
  relation editor: user | group#member
  relation viewer: user | group#member
  relation banned: user
  permission edit = owner + editor
  permission view = (viewer + edit + parent->view) - banned
}
`

func TestParseValid(t *testing.T) {
	s, err := Parse(docs)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(s.Order, ","), "user,group,folder,document"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	d := s.Defs["document"]
	if !d.IsRelation("viewer") || !d.IsPermission("view") || d.Has("nope") {
		t.Fatal("relation/permission lookup is wrong")
	}
	if got := d.Permissions["view"].Expr.String(); got != "(((viewer + edit) + parent->view) - banned)" {
		t.Fatalf("view expr = %s", got)
	}
	f := s.Defs["folder"].Relations["viewer"]
	if !f.Allows("user", "alice", "") || !f.Allows("user", "*", "") || !f.Allows("group", "eng", "member") {
		t.Fatal("allowed subject types missing")
	}
	if f.Allows("group", "eng", "") || f.Allows("group", "*", "") || f.Allows("folder", "x", "") || f.Allows("user", "*", "member") {
		t.Fatal("disallowed subject type accepted")
	}
	if s.Defs["user"].Has("x") {
		t.Fatal("empty definition should have no names")
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	s, err := Parse(docs)
	if err != nil {
		t.Fatal(err)
	}
	out := s.String()
	s2, err := Parse(out)
	if err != nil {
		t.Fatalf("canonical form does not parse: %v\n%s", err, out)
	}
	if s2.String() != out {
		t.Fatalf("round trip changed the schema:\n%s\n---\n%s", out, s2.String())
	}
	if !strings.Contains(out, "permission view = ((viewer + edit) + parent->view) - banned") {
		t.Fatalf("unexpected canonical output:\n%s", out)
	}
	if !strings.Contains(out, "definition user {}") {
		t.Fatalf("empty definition not rendered:\n%s", out)
	}
}

func TestPrecedence(t *testing.T) {
	cases := map[string]string{
		"a + b & c":   "(a + (b & c))",
		"a - b + c":   "(a - (b + c))",
		"a & b - c":   "((a & b) - c)",
		"(a - b) + c": "((a - b) + c)",
		"a - b - c":   "((a - b) - c)",
		"a + b + c":   "((a + b) + c)",
		"p->x & a":    "(p->x & a)",
	}
	for src, want := range cases {
		s, err := Parse("definition t { relation a: t\n relation b: t\n relation c: t\n relation p: t\n permission x = a\n permission z = " + src + " }")
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got := s.Defs["t"].Permissions["z"].Expr.String(); got != want {
			t.Errorf("%s parsed as %s, want %s", src, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"definition", "expected name"},
		{"foo user {}", `expected "definition"`},
		{"definition User {}", "invalid definition name"},
		{"definition a {} definition a {}", "declared twice"},
		{"definition a { relation x: a relation x: a }", "declared twice"},
		{"definition a { relation x: a permission x = x }", "declared twice"},
		{"definition a { relation x: b }", `unknown type "b"`},
		{"definition a { permission p = r->x\n relation r: b }", `a#r allows unknown type "b"`},
		{"definition a { relation x: a#nope }", `has no relation or permission "nope"`},
		{"definition a { relation x: a | a }", "listed twice"},
		{"definition a { permission p = q }", `refers to "q"`},
		{"definition a { permission p = q->r }", "is not a relation"},
		{"definition a { relation x: a\n permission p = x\n permission q = p->x }", "must be a relation, not a permission"},
		{"definition a { relation x: a#x\n permission p = x->x }", "arrows need plain object types"},
		{"definition a { relation x: a:*\n permission p = x->x }", "arrows need plain object types"},
		{"definition b {} definition a { relation x: b\n permission p = x->y }", `has no relation or permission "y"`},
		{"definition a { permission p = q\n permission q = p }", "depend on themselves"},
		{"definition a { relation x: a\n permission p = x + p }", "depend on themselves"},
		{"definition a { relation x: a\n permission p = (x }", "expected ')'"},
		{"definition a { relation x: a\n permission p = }", "expected name"},
		{"definition a { relation x: a:y }", "expected '*'"},
		{"definition a { relation x }", "expected ':'"},
		{"definition a { relation x: a; }", "unexpected character"},
		{"definition a { thing x }", `expected "relation"`},
		{"definition a { relation x: a#", "expected name"},
		{"definition a { relation x: a#B }", "invalid relation name"},
		{"definition a { relation x: a permission p = x -> Y }", "invalid permission name"},
		{"definition a", "expected '{'"},
		{"definition a { relation x: a permission p ", "expected '='"},
	}
	for _, c := range cases {
		_, err := Parse(c.src)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q) error = %v, want it to mention %q", c.src, err, c.want)
		}
	}
}

func TestErrorPositions(t *testing.T) {
	_, err := Parse("definition a {\n  relation x: a\n  bogus\n}")
	e, ok := err.(*Error)
	if !ok || e.Line != 3 || e.Col != 3 {
		t.Fatalf("error = %#v, want line 3 col 3", err)
	}
	if !strings.HasPrefix(e.Error(), "schema:3:3:") {
		t.Fatalf("message = %q", e.Error())
	}
	if (&Error{Msg: "x"}).Error() != "schema: x" {
		t.Fatal("position-less error format changed")
	}
}

func TestLimits(t *testing.T) {
	if _, err := Parse(strings.Repeat(" ", MaxSchemaBytes+1)); err == nil {
		t.Fatal("oversized schema accepted")
	}
	var b strings.Builder
	for i := 0; i <= MaxDefinitions; i++ {
		b.WriteString("definition d")
		b.WriteString(strings.Repeat("a", i%50+1))
		b.WriteString(itoa(i))
		b.WriteString(" {}\n")
	}
	if _, err := Parse(b.String()); err == nil || !strings.Contains(err.Error(), "too many definitions") {
		t.Fatalf("definition limit not enforced: %v", err)
	}
	deep := "definition a { relation x: a\n permission p = " + strings.Repeat("(", MaxExprDepth+2) + "x" + strings.Repeat(")", MaxExprDepth+2) + " }"
	if _, err := Parse(deep); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatalf("depth limit not enforced: %v", err)
	}
	var r strings.Builder
	r.WriteString("definition a { relation x: a")
	for i := 0; i < MaxNamesPerDef; i++ {
		r.WriteString("\n relation r" + itoa(i) + ": a")
	}
	r.WriteString(" }")
	if _, err := Parse(r.String()); err == nil || !strings.Contains(err.Error(), "too many relations") {
		t.Fatalf("name limit not enforced: %v", err)
	}
	var defs, types strings.Builder
	for i := 0; i <= MaxAllowedTypes; i++ {
		defs.WriteString("definition t" + itoa(i) + " {}\n")
		if i > 0 {
			types.WriteString(" | ")
		}
		types.WriteString("t" + itoa(i))
	}
	if _, err := Parse(defs.String() + "definition z { relation x: " + types.String() + " }"); err == nil || !strings.Contains(err.Error(), "too many subject types") {
		t.Fatalf("subject type limit not enforced: %v", err)
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}

func TestValidIdent(t *testing.T) {
	for _, ok := range []string{"a", "user", "a_b1", strings.Repeat("a", 64)} {
		if !ValidIdent(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "A", "1a", "_a", "a-b", strings.Repeat("a", 65)} {
		if ValidIdent(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestTrimParens(t *testing.T) {
	cases := map[string]string{"(a)": "a", "(a) + (b)": "(a) + (b)", "a": "a", "((a))": "(a)", "": ""}
	for in, want := range cases {
		if got := trimParens(in); got != want {
			t.Errorf("trimParens(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(docs)
	f.Add("definition a { relation x: a#x | a:* \n permission p = (x - x) & x->x }")
	f.Fuzz(func(t *testing.T, src string) {
		s, err := Parse(src)
		if err != nil {
			return
		}
		// Anything that parses must round-trip through its canonical form.
		out := s.String()
		s2, err := Parse(out)
		if err != nil {
			t.Fatalf("canonical form of %q does not parse: %v\n%s", src, err, out)
		}
		if s2.String() != out {
			t.Fatalf("canonical form is not stable for %q", src)
		}
	})
}
