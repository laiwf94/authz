package cel

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseRenders(t *testing.T) {
	cases := []struct{ src, want string }{
		// Literals.
		{"1", "1"},
		{"0x1F", "31"},
		{"017", "17"},
		{"42u", "42u"},
		{"0x10U", "16u"},
		{"1.5", "1.5"},
		{".5", "0.5"},
		{"1e3", "1000.0"},
		{"2.5E-3", "0.0025"},
		{"1e+2", "100.0"},
		{"-1.5", "-1.5"},
		{"-0.0", "-0.0"},
		{"9223372036854775807", "9223372036854775807"},
		{"-9223372036854775808", "-9223372036854775808"},
		{"18446744073709551615u", "18446744073709551615u"},
		{"true", "true"},
		{"false", "false"},
		{"null", "null"},
		{`"a"`, `"a"`},
		{`'a"b'`, `"a\"b"`},
		{`"it's"`, `"it's"`},
		{`'''a'b''c'''`, `"a'b''c"`},
		{`"""two
lines"""`, `"two\nlines"`},
		{`r"a\nb"`, `"a\\nb"`},
		{`R'\d+'`, `"\\d+"`},
		{`r'''x\'''`, `"x\\"`},
		{`"\a\b\f\n\r\t\v\\\'\"\` + "`" + `\?"`, `"\a\b\f\n\r\t\v\\'\"` + "`" + `?"`},
		{`"\x41\X42\101é\U0001F600"`, `"ABAé😀"`},
		{`"\xff"`, `"ÿ"`},
		{`"héllo"`, `"héllo"`},
		// Operators and precedence.
		{"a + b * c", "(a + (b * c))"},
		{"(a + b) * c", "((a + b) * c)"},
		{"a - b - c", "((a - b) - c)"},
		{"a / b % c", "((a / b) % c)"},
		{"a < b == c > d", "(((a < b) == c) > d)"},
		{"a <= b != c >= d", "(((a <= b) != c) >= d)"},
		{"x in [1, 2]", "(x in [1, 2])"},
		{"a && b || c && d", "((a && b) || (c && d))"},
		{"a || b || c", "(a || (b || c))"},
		{"a || b || c || d", "((a || b) || (c || d))"},
		{"a ? b : c ? d : e", "(a ? b : (c ? d : e))"},
		{"a || b ? c : d", "((a || b) ? c : d)"},
		{"!a", "!(a)"},
		{"!!a", "!(!(a))"},
		{"-a", "-(a)"},
		{"--a", "-(-(a))"},
		{"--5", "-(-5)"},
		{"-(5)", "-(5)"},
		{"-5.size()", "-(5.size())"},
		{"-x[0]", "-(x[0])"},
		{"(-1).a", "(-1).a"},
		{"(-1.5)[0]", "(-1.5)[0]"},
		{"(-0.0).f()", "(-0.0).f()"},
		{"(-1).all(x, x)", "(-1).all(x, x)"},
		{"has((-1).a)", "has((-1).a)"},
		{"(1).a", "1.a"},
		{"5u - 1u", "(5u - 1u)"},
		{"-1u", "-(1u)"},
		// Members, calls and indexing.
		{"a.b.c", "a.b.c"},
		{"a.b(c, d)", "a.b(c, d)"},
		{"f()", "f()"},
		{"f(a, b)", "f(a, b)"},
		{"a[0][1]", "a[0][1]"},
		{"a.b[c].d", "a.b[c].d"},
		{"(a + b).size()", "(a + b).size()"},
		{"has(a.b)", "has(a.b)"},
		{"has(a.b.c)", "has(a.b.c)"},
		// Lists and maps, with trailing commas.
		{"[]", "[]"},
		{"[1, 2,]", "[1, 2]"},
		{"{}", "{}"},
		{"{'a': 1, 'b': [2],}", `{"a": 1, "b": [2]}`},
		// Macros.
		{"l.all(x, x > 0)", "l.all(x, (x > 0))"},
		{"l.exists(x, x)", "l.exists(x, x)"},
		{"l.exists_one(x, x)", "l.exists_one(x, x)"},
		{"l.filter(x, x)", "l.filter(x, x)"},
		{"l.map(x, x * 2)", "l.map(x, (x * 2))"},
		{"l.map(x, x > 1, x * 2)", "l.map(x, (x > 1), (x * 2))"},
		{"l.all(x)", "l.all(x)"}, // wrong arity: an ordinary call
		{"l.map(x, y, z, w)", "l.map(x, y, z, w)"},
		// Comments and space.
		{"a // the a\n+ b // and b", "(a + b)"},
		{" \t\r\n\fa", "a"},
	}
	for _, c := range cases {
		a, err := Parse(c.src)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.src, err)
			continue
		}
		if got := a.String(); got != c.want {
			t.Errorf("Parse(%q) = %s, want %s", c.src, got, c.want)
			continue
		}
		// The rendering is source for the same tree.
		b, err := Parse(a.String())
		if err != nil || b.String() != c.want {
			t.Errorf("reparse of %q: %v, %v", c.want, b, err)
		}
	}
}

func TestParseLiteralValues(t *testing.T) {
	cases := []struct {
		src  string
		want any
	}{
		{"-9223372036854775808", int64(math.MinInt64)},
		{"0xFFFFFFFFFFFFFFFFu", uint64(math.MaxUint64)},
		{"1.0", 1.0},
		{"'x'", "x"},
		{"null", nil},
		{"true", true},
	}
	for _, c := range cases {
		a, err := Parse(c.src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.src, err)
		}
		if a.Root.Kind != NodeLiteral || a.Root.Value != c.want {
			t.Errorf("Parse(%q) = %#v, want literal %#v", c.src, a.Root.Value, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"", "1:1: unexpected end of expression"},
		{"a +", "1:4: unexpected end of expression"},
		{"a b", "1:3: unexpected 'b'"},
		{"(a", "1:3: expected ')' to close '(', found end of expression"},
		{"a[1", "1:4: expected ']' to end the index"},
		{"[1 2]", "1:4: expected ']' to end the list, found integer"},
		{"{1: 2 3}", "1:7: expected '}' to end the map"},
		{"{1 2}", "1:4: expected ':' after a map key"},
		{"f(a,)", "1:5: unexpected ')' after ','"},
		{"f(a b)", "1:5: expected ')' to end the arguments"},
		{"[,]", "1:2: unexpected ','"},
		{"a ? b", "1:6: expected ':' in a conditional"},
		{"a.", "1:3: expected identifier after '.'"},
		{"a.1", "1:2: unexpected number"},
		{"a = b", `1:3: unexpected '='; did you mean "=="?`},
		{"a & b", `1:3: unexpected '&'; did you mean "&&"?`},
		{"a | b", `1:3: unexpected '|'; did you mean "||"?`},
		{"a # b", "1:3: unexpected character '#'"},
		{"a\n  ~", "2:3: unexpected character '~'"},
		{"é", "1:1: unexpected character 'é'"},
		{"9223372036854775808", "1:1: integer 9223372036854775808 is out of range"},
		{"-9223372036854775809", "1:2: integer -9223372036854775809 is out of range"},
		{"99999999999999999999", "out of range"},
		{"18446744073709551616u", "1:1: unsigned integer 18446744073709551616u is out of range"},
		{"1e999", "1:1: number 1e999 is out of range"},
		{"0x", "1:1: hexadecimal literal has no digits"},
		{"1e", "1:2: exponent has no digits"},
		{"1e+", "1:2: exponent has no digits"},
		{"12abc", "1:3: unexpected 'a' after number"},
		{"1.5x", "1:4: unexpected 'x' after number"},
		{"1u2", "1:3: unexpected '2' after number"},
		{"1.2.3", "1:4: unexpected '.' after number"},
		{`"abc`, "1:1: string is not terminated"},
		{`'''abc''`, "1:1: string is not terminated"},
		{"'a\nb'", "1:3: newline in string; use a triple-quoted string"},
		{`"\q"`, `1:2: unknown escape \q`},
		{`"\x4"`, "1:2: escape needs 2 hexadecimal digits"},
		{`"\xzz"`, "1:2: escape needs 2 hexadecimal digits"},
		{`"\u12"`, "escape needs 4 hexadecimal digits"},
		{`"\UFFFFFFFF"`, "1:2: escape is not a valid code point"},
		{`"\uD800"`, "1:2: escape is not a valid code point"},
		{`"\18"`, "1:2: octal escape needs three digits"},
		{`"\1"`, "1:2: octal escape needs three digits"},
		{`"\`, "1:2: string ends inside an escape"},
		{"\"\xff\"", "1:2: string is not valid UTF-8"},
		{`b"abc"`, "1:1: bytes literals are not supported"},
		{`rb'abc'`, "1:1: bytes literals are not supported"},
		{`b'\q'`, "unknown escape"},
		{".a", "1:1: names starting with '.' are not supported"},
		{"if", "1:1: 'if' is a reserved word"},
		{"a.while", "1:3: 'while' is a reserved word"},
		{"has(a)", "1:1: has() takes one field selection, such as has(m.key)"},
		{"has(a.b, c.d)", "has() takes one field selection"},
		{"l.all(1, true)", "1:7: the first argument of all() must be a variable name"},
		{"l.map(x.y, 1)", "1:9: the first argument of map() must be a variable name"},
	}
	for _, c := range cases {
		_, err := Parse(c.src)
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want error %q", c.src, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q) error = %q, want %q", c.src, err, c.want)
		}
		var es Errors
		if !errors.As(err, &es) || len(es) != 1 {
			t.Errorf("Parse(%q) error %T is not one Errors entry", c.src, err)
		}
	}
}

func TestParseLimits(t *testing.T) {
	lim := Limits{MaxSourceBytes: 64, MaxDepth: 5, MaxNodes: 9}
	cases := []struct {
		src, want string
	}{
		{strings.Repeat("a", 65), "1:1: expression is 65 bytes, more than the limit of 64"},
		{"((((((a))))))", "1:6: expression is nested more than 5 deep"},
		{"a.b.c.d.e.f", "1:11: expression is nested more than 5 deep"},
		{"!!!!!a", "1:1: expression is nested more than 5 deep"},
		{"[1, 2, 3, 4, 5, 6, 7, 8, 9]", "expression has more than 9 nodes"},
		{strings.Repeat("a+", 20) + "a", "expression has more than 9 nodes"},
	}
	for _, c := range cases {
		_, err := parse(c.src, lim)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("parse(%q) error = %v, want %q", c.src, err, c.want)
		}
	}
	// Within the limits.
	for _, src := range []string{"(((a)))", "a.b.c.d", "[1, 2, 3, 4, 5, 6, 7, 8]"} {
		if _, err := parse(src, lim); err != nil {
			t.Errorf("parse(%q): %v", src, err)
		}
	}
}

// A long || chain is balanced, so it fits a depth limit that a left-deep
// tree of the same chain would not.
func TestParseBalancesChains(t *testing.T) {
	terms := make([]string, 1000)
	for i := range terms {
		terms[i] = "a"
	}
	a, err := Parse(strings.Join(terms, " || "))
	if err != nil {
		t.Fatal(err)
	}
	if d := a.Root.depth; d > 11 {
		t.Errorf("depth of a 1000-term chain = %d, want at most 11", d)
	}
	if a.Nodes() != 1999 {
		t.Errorf("Nodes() = %d, want 1999", a.Nodes())
	}
	// A left-deep chain of + is refused by depth, not by recursion.
	_, err = Parse(strings.Repeat("a + ", 200) + "a")
	if err == nil || !strings.Contains(err.Error(), "nested more than 100 deep") {
		t.Errorf("200 additions: %v", err)
	}
	// Deep parentheses are refused before they deepen the Go stack.
	_, err = Parse(strings.Repeat("(", 2000) + "a" + strings.Repeat(")", 2000))
	if err == nil || !strings.Contains(err.Error(), "nested more than 100 deep") {
		t.Errorf("2000 parentheses: %v", err)
	}
	// A flat flood of nodes is refused by the node limit.
	_, err = Parse("[" + strings.Repeat("a,", 8000) + "]")
	if err == nil || !strings.Contains(err.Error(), "more than 4096 nodes") {
		t.Errorf("8000 identifiers: %v", err)
	}
}

func TestNodeIDs(t *testing.T) {
	a, err := Parse("f(a, [b, {c: d}], e.all(x, x))")
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]bool, a.Nodes())
	var walk func(n *Node)
	walk = func(n *Node) {
		if n.ID < 0 || n.ID >= a.Nodes() || seen[n.ID] {
			t.Fatalf("node %s has ID %d", n, n.ID)
		}
		seen[n.ID] = true
		if n.Target != nil {
			walk(n.Target)
		}
		for _, c := range n.Args {
			walk(c)
		}
	}
	walk(a.Root)
	if a.Root.ID != a.Nodes()-1 {
		t.Errorf("root ID = %d, want the last, %d", a.Root.ID, a.Nodes()-1)
	}
}

func TestErrorPositions(t *testing.T) {
	_, err := Parse("a &&\n\tb +\n  ~")
	var es Errors
	if !errors.As(err, &es) {
		t.Fatalf("error %T", err)
	}
	e := es[0]
	if e.Pos != 12 || e.Line != 3 || e.Column != 3 {
		t.Errorf("error at %d (%d:%d), want 12 (3:3)", e.Pos, e.Line, e.Column)
	}
	// Columns count characters, not bytes.
	_, err = Parse("'é' + ~")
	if err == nil || !strings.HasPrefix(err.Error(), "1:7:") {
		t.Errorf("error = %v, want column 7", err)
	}
}

func TestMacroString(t *testing.T) {
	for name, m := range macroNames {
		if m.String() != name {
			t.Errorf("%d.String() = %q, want %q", m, m.String(), name)
		}
	}
	if s := Macro(99).String(); s != "macro(99)" {
		t.Errorf("Macro(99).String() = %q", s)
	}
}

func TestRenderNonFiniteDouble(t *testing.T) {
	// Not reachable from source; rendered as a call that still parses.
	n := &Node{Kind: NodeLiteral, Value: math.Inf(1)}
	if got := n.String(); got != `double("+Inf")` {
		t.Errorf("render +Inf = %s", got)
	}
	if _, err := Parse(n.String()); err != nil {
		t.Error(err)
	}
}
