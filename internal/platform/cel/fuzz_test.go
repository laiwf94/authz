package cel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
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

// evalSeeds are expressions over testEnv that reach the evaluator's
// three-valued logic, comprehensions, conversions and runtime errors.
var evalSeeds = []string{
	"i + 1 > 2 && s == 'a' || b", "i / 0 == 1 || b", "b && i * i > d", "!b ? i : -i",
	"li.all(e, e < i)", "li.exists(e, e == i || b)", "ls.exists_one(e, e == s)",
	"li.map(e, e > 1, e * i)", "ms.filter(k, ms[k] == s)", "ll.map(l, l.map(e, e + i))",
	"md.n + d", "has(md.s) && md.s == s", "mm.a.x == i", "mi[i]", "li[i]",
	"string(i) + s", "int(s) + i", "uint(d) > u", "double(s) < d", "bool(s)",
	"timestamp(s) < t", "duration(s) > dur", "t + duration(s) > t", "t.getHours(s)",
	"ip(s).in_cidr(net)", "cidr(s).containsIP(ip)", "s.matches(s)", "s.matches('^a+$')",
	"size(s) == i", "x == i || x == s", "[i, s, d].size()", "{s: i}[s] == i",
	"t - timestamp(i) > dur", "dyn(i) < dyn(d)", "x.map(e, e)", "x[i]", "x.all(k, x[k] == i)",
}

// fuzzVars builds a full activation for testEnv around the fuzzed scalars.
func fuzzVars(i int64, s string, d float64) map[string]any {
	return map[string]any{
		"i": i, "u": uint64(i) >> 1, "d": d, "s": s, "b": i%2 == 0,
		"t": time.Unix(1795422615, 0).UTC(), "dur": 90 * time.Minute,
		"ip": netip.MustParseAddr("10.1.2.3"), "net": netip.MustParsePrefix("10.0.0.0/8"),
		"x": []any{i, s, d}, "li": []any{i, int64(1), int64(2)}, "ls": []string{s, "a"},
		"ll": [][]int64{{i}, {1, 2}}, "ms": map[string]string{s: "v", "a": s},
		"md": map[string]any{"n": d, "s": s}, "mi": map[int64]bool{i: true, 1: false},
		"mm": map[string]map[string]int64{"a": {"x": i}},
	}
}

// FuzzEval checks that evaluation never panics and stays within its cost
// limit, that runtime errors carry a position, that a known value has the
// checked type, that a result is the same every time, and the three-valued
// logic: an unknown names only absent variables the expression uses, and a
// value known with some variables absent is the value with all of them.
func FuzzEval(f *testing.F) {
	for k, src := range append(evalSeeds, fuzzSeeds...) {
		f.Add(src, int64(k), "a", 1.5, uint32(k*2654435761))
	}
	env := testEnv(f)
	names := slices.Sorted(maps.Keys(fuzzVars(0, "", 0)))
	f.Fuzz(func(t *testing.T, src string, i int64, s string, d float64, absent uint32) {
		c, err := env.Compile(src)
		if err != nil {
			return
		}
		const limit = 20000
		p := c.Program(limit)
		full := fuzzVars(i, s, d)
		partial := fuzzVars(i, s, d)
		for k, name := range names {
			if absent&(1<<k) != 0 {
				delete(partial, name)
			}
		}
		r, err := p.Eval(partial)
		again, err2 := p.Eval(partial)
		if fmt.Sprint(r, err) != fmt.Sprint(again, err2) {
			t.Fatalf("%q: %v, %v then %v, %v", src, r, err, again, err2)
		}
		if errors.Is(err, ErrCostLimit) {
			if r.Cost <= limit {
				t.Fatalf("%q: cost limit error at cost %d", src, r.Cost)
			}
			return
		}
		if r.Cost > limit {
			t.Fatalf("%q: cost %d over the limit without an error", src, r.Cost)
		}
		if err != nil {
			var es Errors
			if !errors.As(err, &es) || len(es) != 1 || es[0].Line < 1 {
				t.Fatalf("%q: error %#v has no position", src, err)
			}
			return
		}
		if !r.Known() {
			if !slices.IsSorted(r.Missing) {
				t.Fatalf("%q: missing %v is not sorted", src, r.Missing)
			}
			for _, m := range r.Missing {
				if _, ok := partial[m]; ok || !slices.Contains(c.Vars(), m) {
					t.Fatalf("%q: missing %q, which is present or unused (uses %v)", src, m, c.Vars())
				}
			}
			return
		}
		if !hasType(r.Value, c.Type()) {
			t.Fatalf("%q = %#v, which is not a %s", src, r.Value, c.Type())
		}
		rf, err := p.Eval(full)
		if errors.Is(err, ErrCostLimit) {
			return
		}
		if err != nil || !rf.Known() || fmt.Sprint(rf.Value) != fmt.Sprint(r.Value) {
			t.Fatalf("%q = %#v with %v absent, but %#v, %v with every variable", src, r.Value, absentNames(names, partial), rf, err)
		}
	})
}

func absentNames(names []string, vars map[string]any) []string {
	var out []string
	for _, n := range names {
		if _, ok := vars[n]; !ok {
			out = append(out, n)
		}
	}
	return out
}

// hasType reports whether an evaluation result is a value of type t.
func hasType(v any, t *Type) bool {
	switch t.kind {
	case KindDyn:
		return true
	case KindNull:
		return v == nil
	case KindList:
		l, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range l {
			if !hasType(x, t.elem) {
				return false
			}
		}
		return true
	case KindMap:
		m, ok := v.(map[any]any)
		if !ok {
			return false
		}
		for k, x := range m {
			if !hasType(k, t.key) || !hasType(x, t.elem) {
				return false
			}
		}
		return true
	}
	var ok bool
	switch t.kind {
	case KindBool:
		_, ok = v.(bool)
	case KindInt:
		_, ok = v.(int64)
	case KindUint:
		_, ok = v.(uint64)
	case KindDouble:
		_, ok = v.(float64)
	case KindString:
		_, ok = v.(string)
	case KindTimestamp:
		_, ok = v.(time.Time)
	case KindDuration:
		_, ok = v.(time.Duration)
	case KindIP:
		_, ok = v.(netip.Addr)
	case KindCIDR:
		_, ok = v.(netip.Prefix)
	}
	return ok
}

// FuzzEvalContext feeds JSON objects, as a caveat's stored or request
// context arrives, to Eval: conversion never panics, a value of the wrong
// type is an error that names the variable, and decoding numbers as
// json.Number gives the same outcome as decoding them as float64 when every
// number is a whole one in the range where float64 is exact, for
// expressions whose variables have no dyn in their types (a dyn variable
// keeps the Go type it is given).
func FuzzEvalContext(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"i": 1, "s": "a", "li": [1, 2], "ms": {"a": "b"}}`, `{"i": 1.5}`, `{"i": "1"}`,
		`{"t": "2026-11-23T09:00:00Z", "dur": "90s", "ip": "10.0.0.1", "net": "10.0.0.0/8"}`,
		`{"x": {"a": [1, {"b": null}]}, "md": {"k": [true, 1e3]}}`, `{"u": -1}`, `{"mi": {"1": true}}`,
		`{"ll": [[1], [], [2, 3]], "mm": {"a": {"x": 9007199254740993}}}`, `{"t": "0000-01-01T00:00:00Z"}`,
	} {
		f.Add([]byte(s))
	}
	env := testEnv(f)
	var programs []*Program
	var typed []bool
	for _, src := range append(evalSeeds, "i == 1", "t < t + dur", "ip.in_cidr(net)", "x == md", "li == ll[0]") {
		c, err := env.Compile(src)
		if err != nil {
			f.Fatal(err)
		}
		programs = append(programs, c.Program(20000))
		noDyn := true
		for _, v := range c.Vars() {
			t, _ := env.Lookup(v)
			noDyn = noDyn && !containsDyn(t)
		}
		typed = append(typed, noDyn)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var plain map[string]any
		if json.Unmarshal(data, &plain) != nil {
			return
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var numbers map[string]any
		if dec.Decode(&numbers) != nil {
			return
		}
		exact := wholeNumbers(numbers)
		for k, p := range programs {
			r1, err1 := p.Eval(plain)
			r2, err2 := p.Eval(numbers)
			for _, err := range []error{err1, err2} {
				var es Errors
				if err != nil && !errors.As(err, &es) && !errors.Is(err, ErrCostLimit) && !strings.HasPrefix(err.Error(), "cel: variable ") {
					t.Fatalf("%s: error %q names no variable", p.Checked().AST().Source, err)
				}
			}
			if exact && typed[k] && fmt.Sprint(r1, err1) != fmt.Sprint(r2, err2) {
				t.Fatalf("%s over %s: %v, %v with float64 but %v, %v with json.Number", p.Checked().AST().Source, data, r1, err1, r2, err2)
			}
		}
	})
}

// wholeNumbers reports whether every number in v is a whole number that
// float64 holds exactly, so float64 and json.Number decode it alike.
func wholeNumbers(v any) bool {
	switch v := v.(type) {
	case json.Number:
		i, err := v.Int64()
		return err == nil && i > -1<<53 && i < 1<<53 && !strings.ContainsAny(string(v), ".eE")
	case []any:
		for _, x := range v {
			if !wholeNumbers(x) {
				return false
			}
		}
	case map[string]any:
		for _, x := range v {
			if !wholeNumbers(x) {
				return false
			}
		}
	}
	return true
}

func containsDyn(t *Type) bool {
	switch t.kind {
	case KindDyn:
		return true
	case KindList:
		return containsDyn(t.elem)
	case KindMap:
		return containsDyn(t.key) || containsDyn(t.elem)
	}
	return false
}
