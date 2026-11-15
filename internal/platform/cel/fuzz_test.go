package cel

import (
	"errors"
	"testing"
)

var fuzzSeeds = []string{
	"1", "-9223372036854775808", "0x1Fu", "1.5e-3", ".5", `"a\n\x41é"`, `r'\d+'`,
	`'''multi
line'''`, "null", "true && !false", "a + b * c - d / e % f",
	"a < b && c <= d || e > f && g >= h", "x == 1u || x != 1.0", "1 in [1, 2, 3]",
	"m.a.b[0]", "has(m.k)", "c ? 1 : 2", "l.all(e, e > 0)", "l.exists_one(e, e)",
	"l.map(e, e > 1, e * 2)", "l.filter(e, e)", "{'a': [1, {'b': null}],}",
	"s.matches('^[a-z]+$')", "t.getHours('Europe/Berlin') < 17",
	"timestamp('2026-11-23T09:00:00Z') + duration('1h30m')",
	"ip('10.0.0.1').in_cidr('10.0.0.0/8')", "cidr('::/0').containsIP(ip)",
	"size(s) + s.size()", "int(u) + int('1')", "--a", "!!b", "-(5)",
	"a // comment\n+ b", "f(a, b,)", "((((a))))", "a.while", "b'x'", "{1: 2, 1: 3}",
}

// FuzzParse checks that the parser never panics or exceeds its limits, that
// errors carry a position, and that a parsed expression renders to source
// that parses to the same tree.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		a, err := Parse(src)
		if err != nil {
			var es Errors
			if !errors.As(err, &es) || len(es) != 1 || es[0].Line < 1 || es[0].Column < 1 {
				t.Fatalf("Parse(%q) error %#v has no position", src, err)
			}
			return
		}
		if a.Nodes() > DefaultLimits.MaxNodes || a.Root.depth > DefaultLimits.MaxDepth {
			t.Fatalf("Parse(%q): %d nodes, depth %d, beyond the limits", src, a.Nodes(), a.Root.depth)
		}
		r := a.String()
		b, err := parse(r, renderLimits)
		if err != nil {
			t.Fatalf("rendering %q of %q does not parse: %v", r, src, err)
		}
		if b.String() != r {
			t.Fatalf("rendering of %q is not stable:\n%s\n%s", src, r, b.String())
		}
	})
}

// renderLimits admit a rendering of anything Parse accepts: the rendering
// adds parentheses, which lengthen the source and nest the parser deeper
// without adding nodes.
var renderLimits = Limits{
	MaxSourceBytes: 1 << 20,
	MaxDepth:       2*DefaultLimits.MaxDepth + 2,
	MaxNodes:       DefaultLimits.MaxNodes,
}

// FuzzCheck checks that the checker never panics, gives every node it
// reached a type, and gives a rendering the same type as the source.
func FuzzCheck(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	for _, s := range []string{
		"i + 1 > 2 && ms.k == 'v' || ls.exists(e, e.startsWith('a'))",
		"t - t < dur && ip.in_cidr(net) && x.y.z", "li.map(e, [e]).filter(l, size(l) > 0)",
		"md.k ? mi[1] : b", "u == d && i < u", "{x: li, 'a': []}",
	} {
		f.Add(s)
	}
	env := testEnv(f)
	f.Fuzz(func(t *testing.T, src string) {
		a, err := env.Parse(src)
		if err != nil {
			return
		}
		c, err := env.Check(a)
		if err != nil {
			var es Errors
			if !errors.As(err, &es) || len(es) == 0 || len(es) > maxErrors {
				t.Fatalf("Check(%q) error %#v", src, err)
			}
			return
		}
		var walk func(n *Node)
		walk = func(n *Node) {
			if c.TypeOf(n) == nil {
				t.Fatalf("Check(%q): node %s has no type", src, n)
			}
			if n.Kind == NodeCall && len(c.Overloads(n)) == 0 {
				t.Fatalf("Check(%q): call %s has no overload", src, n)
			}
			if hasParam(c.TypeOf(n)) {
				t.Fatalf("Check(%q): node %s has type %s", src, n, c.TypeOf(n))
			}
			if n.Target != nil {
				walk(n.Target)
			}
			for _, x := range n.Args {
				walk(x)
			}
		}
		walk(a.Root)
		b, err := parse(a.String(), renderLimits)
		if err != nil {
			t.Fatalf("rendering of %q does not parse: %v", src, err)
		}
		c2, err := env.Check(b)
		if err != nil {
			t.Fatalf("rendering %s of %q does not check: %v", b, src, err)
		}
		if !c2.Type().Equal(c.Type()) {
			t.Fatalf("rendering of %q has type %s, the source %s", src, c2.Type(), c.Type())
		}
	})
}

// FuzzParseType checks that ParseType never panics and that a type renders
// to text that reads back as the same type.
func FuzzParseType(f *testing.F) {
	for _, s := range []string{"int", "any", "list<map<string, list<int>>>", "map<int>", "map<bool, dyn>", "list<", "map<double, int>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		typ, err := ParseType(s)
		if err != nil {
			return
		}
		again, err := ParseType(typ.String())
		if err != nil || !again.Equal(typ) {
			t.Fatalf("ParseType(%q) = %s, which reads back as %v, %v", s, typ, again, err)
		}
	})
}
