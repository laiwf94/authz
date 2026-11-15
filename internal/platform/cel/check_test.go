package cel

import (
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func testEnv(t testing.TB) *Env {
	t.Helper()
	env, err := NewEnv([]Var{
		{"i", Int}, {"u", Uint}, {"d", Double}, {"s", String}, {"b", Bool},
		{"t", Timestamp}, {"dur", Duration}, {"ip", IPAddress}, {"net", CIDR},
		{"x", Dyn},
		{"li", ListOf(Int)}, {"ls", ListOf(String)}, {"ll", ListOf(ListOf(Int))},
		{"ms", MapOf(String, String)}, {"md", MapOf(String, Dyn)},
		{"mi", MapOf(Int, Bool)}, {"mm", MapOf(String, MapOf(String, Int))},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestCheckTypes(t *testing.T) {
	env := testEnv(t)
	cases := []struct{ src, want string }{
		{"1", "int"}, {"1u", "uint"}, {"1.0", "double"}, {"'a'", "string"},
		{"true", "bool"}, {"null", "null_type"},
		{"i + 1", "int"}, {"u * 2u", "uint"}, {"d / 2.0", "double"}, {"i % 2", "int"},
		{"u % 2u", "uint"}, {"-i", "int"}, {"-d", "double"}, {"!b", "bool"},
		{"s + 'x'", "string"}, {"li + [1]", "list<int>"}, {"li + []", "list<dyn>"},
		{"t + dur", "timestamp"}, {"dur + t", "timestamp"}, {"dur + dur", "duration"},
		{"t - t", "duration"}, {"t - dur", "timestamp"}, {"dur - dur", "duration"},
		{"i - 1", "int"}, {"u - 1u", "uint"}, {"d - 1.0", "double"},
		{"i == 1", "bool"}, {"i == 1u", "bool"}, {"i != 1.5", "bool"}, {"u == d", "bool"},
		{"s == 'a'", "bool"}, {"li == [1, 2]", "bool"}, {"ip == ip('::1')", "bool"},
		{"x == null", "bool"}, {"null == null", "bool"}, {"md == {}", "bool"},
		{"i < 2", "bool"}, {"i <= 2.5", "bool"}, {"u > 1", "bool"}, {"d >= 1u", "bool"},
		{"s < 'b'", "bool"}, {"b < true", "bool"}, {"t < t", "bool"}, {"dur > dur", "bool"},
		{"1 in li", "bool"}, {"'k' in ms", "bool"}, {"x in li", "bool"}, {"1 in x", "bool"},
		{"b && b", "bool"}, {"b || x", "bool"}, {"b ? 1 : 2", "int"}, {"b ? li : []", "list<dyn>"},
		{"b ? 1 : x", "dyn"}, {"x ? 's' : 't'", "string"},
		{"li[0]", "int"}, {"ll[0]", "list<int>"}, {"ll[0][1]", "int"}, {"ms['k']", "string"},
		{"mi[1]", "bool"}, {"mm['a']['b']", "int"}, {"x[0]", "dyn"}, {"li[x]", "int"},
		{"ms.k", "string"}, {"mm.a.b", "int"}, {"md.k", "dyn"}, {"md.k.l", "dyn"}, {"x.y", "dyn"},
		{"has(ms.k)", "bool"}, {"has(md.k.l)", "bool"}, {"has(x.y)", "bool"},
		{"[1, 2]", "list<int>"}, {"[1, 'a']", "list<dyn>"}, {"[]", "list<dyn>"},
		{"[[1], [2]]", "list<list<int>>"}, {"[[1], ['a']]", "list<list<dyn>>"},
		{"{'a': 1}", "map<string, int>"}, {"{'a': 1, 'b': 's'}", "map<string, dyn>"},
		{"{1: 'a', 'b': 'c'}", "map<dyn, string>"}, {"{}", "map<dyn, dyn>"},
		{"{'a': {'b': 1}, 'c': {'d': 's'}}", "map<string, map<string, dyn>>"},
		{"{x: 1}", "map<dyn, int>"}, {"{true: 1, 2u: 2}", "map<dyn, int>"},
		{"size(s)", "int"}, {"size(li)", "int"}, {"size(ms)", "int"}, {"s.size()", "int"},
		{"li.size()", "int"}, {"ms.size()", "int"}, {"size(x)", "int"},
		{"s.contains('a')", "bool"}, {"s.startsWith('a')", "bool"}, {"s.endsWith('a')", "bool"},
		{"s.matches('^a+$')", "bool"}, {"matches(s, 'a')", "bool"}, {"s.matches(s)", "bool"},
		{"int(u)", "int"}, {"int(d)", "int"}, {"int(s)", "int"}, {"int(t)", "int"}, {"int(i)", "int"},
		{"uint(i)", "uint"}, {"uint(d)", "uint"}, {"uint(s)", "uint"}, {"uint(u)", "uint"},
		{"double(i)", "double"}, {"double(u)", "double"}, {"double(s)", "double"}, {"double(d)", "double"},
		{"string(i)", "string"}, {"string(u)", "string"}, {"string(d)", "string"}, {"string(b)", "string"},
		{"string(t)", "string"}, {"string(dur)", "string"}, {"string(ip)", "string"},
		{"string(net)", "string"}, {"string(s)", "string"},
		{"bool(s)", "bool"}, {"bool(b)", "bool"}, {"dyn(1)", "dyn"}, {"int(x)", "int"},
		{"timestamp('2026-11-23T09:00:00Z')", "timestamp"}, {"timestamp(t)", "timestamp"},
		{"timestamp(0)", "timestamp"}, {"duration('1h30m')", "duration"}, {"duration(dur)", "duration"},
		{"t.getFullYear()", "int"}, {"t.getMonth('UTC')", "int"}, {"t.getDayOfYear()", "int"},
		{"t.getDayOfMonth()", "int"}, {"t.getDate('+05:30')", "int"}, {"t.getDayOfWeek('-08:00')", "int"},
		{"t.getHours('America/New_York')", "int"}, {"t.getMinutes()", "int"},
		{"t.getSeconds()", "int"}, {"t.getMilliseconds(s)", "int"},
		{"dur.getHours()", "int"}, {"dur.getMinutes()", "int"}, {"dur.getSeconds()", "int"},
		{"dur.getMilliseconds()", "int"}, {"x.getHours()", "int"},
		{"ip('10.0.0.1')", "ipaddress"}, {"cidr('10.0.0.0/8')", "cidr"}, {"isIP(s)", "bool"},
		{"isCIDR(s)", "bool"}, {"ip.family()", "int"}, {"ip.isLoopback()", "bool"},
		{"ip.isPrivate()", "bool"}, {"ip.isUnspecified()", "bool"},
		{"ip.in_cidr('192.168.0.0/16')", "bool"}, {"ip.in_cidr(net)", "bool"}, {"ip.in_cidr(s)", "bool"},
		{"net.containsIP(ip)", "bool"}, {"net.containsIP('10.1.2.3')", "bool"},
		{"net.containsCIDR(net)", "bool"}, {"net.containsCIDR('10.1.0.0/16')", "bool"},
		{"net.ip()", "ipaddress"}, {"net.prefixLength()", "int"}, {"net.masked()", "cidr"},
		{"li.all(e, e > 0)", "bool"}, {"li.exists(e, e > 0)", "bool"}, {"li.exists_one(e, e > 0)", "bool"},
		{"li.filter(e, e > 0)", "list<int>"}, {"ms.filter(k, k != '')", "list<string>"},
		{"li.map(e, string(e))", "list<string>"}, {"li.map(e, e > 0, e * 2)", "list<int>"},
		{"ms.all(k, ms[k] != '')", "bool"}, {"mi.exists(k, k > 1)", "bool"},
		{"x.all(e, e)", "bool"}, {"x.map(e, e)", "list<dyn>"}, {"x.filter(e, true)", "list<dyn>"},
		{"ll.all(l, l.all(e, e > 0))", "bool"},
		{"li.exists(i, i == 1) && i > 0", "bool"}, // the iteration variable shadows i
		{"[1, 2].map(e, [e])", "list<list<int>>"},
	}
	for _, c := range cases {
		ch, err := env.Compile(c.src)
		if err != nil {
			t.Errorf("Compile(%q): %v", c.src, err)
			continue
		}
		if got := ch.Type().String(); got != c.want {
			t.Errorf("Compile(%q) type = %s, want %s", c.src, got, c.want)
		}
	}
}

func TestCheckErrors(t *testing.T) {
	env := testEnv(t)
	cases := []struct{ src, want string }{
		{"y", "1:1: undeclared reference to 'y'"},
		{"foo(1)", "1:1: undeclared function 'foo'"},
		{"s.foo()", "1:3: undeclared function 'foo'"},
		{"i + 'a'", "1:3: no matching overload for '+' applied to (int, string)"},
		{"i + 1u", "no matching overload for '+' applied to (int, uint)"},
		{"i + 1.0", "no matching overload for '+' applied to (int, double)"},
		{"-u", "1:1: no matching overload for '-' applied to (uint)"},
		{"!i", "1:1: no matching overload for '!' applied to (int)"},
		{"d % 2.0", "no matching overload for '%' applied to (double, double)"},
		{"t + t", "no matching overload for '+' applied to (timestamp, timestamp)"},
		{"dur - t", "no matching overload for '-' applied to (duration, timestamp)"},
		{"li + ls", "no matching overload for '+' applied to (list<int>, list<string>)"},
		{"ms + ms", "no matching overload for '+' applied to (map<string, string>, map<string, string>)"},
		{"i == 's'", "no matching overload for '==' applied to (int, string)"},
		{"i == null", "no matching overload for '==' applied to (int, null_type)"},
		{"li == ls", "no matching overload for '==' applied to (list<int>, list<string>)"},
		{"s < 1", "no matching overload for '<' applied to (string, int)"},
		{"li < li", "no matching overload for '<' applied to (list<int>, list<int>)"},
		{"ip < ip", "no matching overload for '<' applied to (ipaddress, ipaddress)"},
		{"'a' in li", "no matching overload for 'in' applied to (string, list<int>)"},
		{"1 in ms", "no matching overload for 'in' applied to (int, map<string, string>)"},
		{"1 in s", "no matching overload for 'in' applied to (int, string)"},
		{"i && b", "no matching overload for '&&' applied to (int, bool)"},
		{"b || 's'", "no matching overload for '||' applied to (bool, string)"},
		{"i ? 1 : 2", "1:3: the condition of '?:' must be bool, not int"},
		{"b ? 1 : 's'", "1:3: the branches of '?:' have different types, int and string"},
		{"li['a']", "no matching overload for '[]' applied to (list<int>, string)"},
		{"ms[1]", "no matching overload for '[]' applied to (map<string, string>, int)"},
		{"s[0]", "no matching overload for '[]' applied to (string, int)"},
		{"i.f", "1:3: 'f' selects a field of int, but only maps with string keys have fields"},
		{"mi.f", "'f' selects a field of map<int, bool>"},
		{"li.f", "'f' selects a field of list<int>"},
		{"has(i.f)", "'f' selects a field of int"},
		{"size(1)", "no matching overload for size(int)"},
		{"i.size()", "no matching overload for int.size()"},
		{"s.contains(1)", "no matching overload for string.contains(int)"},
		{"contains(s, 'a')", "no matching overload for contains(string, string)"},
		{"int(b)", "no matching overload for int(bool)"},
		{"int(1, 2)", "no matching overload for int(int, int)"},
		{"dur.getFullYear()", "no matching overload for duration.getFullYear()"},
		{"{li: 1}", "1:2: map keys must be bool, int, uint or string, not list<int>"},
		{"{1.5: 1}", "map keys must be bool, int, uint or string, not double"},
		{"{'a': 1, 'a': 2}", "1:10: map key \"a\" appears twice"},
		{"{1: 1, 1: 2}", "map key 1 appears twice"},
		{"i.all(e, true)", "1:3: all() needs a list or a map, not int"},
		{"li.all(e, e)", "1:11: the predicate of all() must be bool, not int"},
		{"li.exists_one(e, 's')", "the predicate of exists_one() must be bool, not string"},
		{"li.filter(e, e)", "the predicate of filter() must be bool, not int"},
		{"li.map(e, e, e)", "the filter of map() must be bool, not int"},
		{"li.all(e, e > 0) && e > 0", "1:21: undeclared reference to 'e'"},
		// Literal arguments are parsed when the expression is checked.
		{"s.matches('(')", "1:11: pattern \"(\": error parsing regexp"},
		{"matches(s, '[')", "pattern \"[\""},
		{"timestamp('yesterday')", "1:11: timestamp \"yesterday\" is not an RFC 3339 time"},
		{"timestamp('0000-01-01T00:00:00Z')", "is out of range"},
		{"duration('1 hour')", "duration \"1 hour\": want a number and a unit"},
		{"t.getHours('Nowhere/City')", "unknown time zone \"Nowhere/City\""},
		{"t.getHours('Local')", "time zone \"Local\": name an IANA zone"},
		{"t.getHours('')", "time zone \"\": name an IANA zone"},
		{"t.getHours('+25:00')", "time zone offset \"+25:00\": want ±HH:MM"},
		{"t.getHours('+05:60')", "want ±HH:MM"},
		{"t.getHours('+0a:00')", "want ±HH:MM"},
		{"ip('10.0.0.256')", "\"10.0.0.256\" is not an IP address"},
		{"ip('fe80::1%eth0')", "IP address \"fe80::1%eth0\" has a zone"},
		{"cidr('10.0.0.0')", "\"10.0.0.0\" is not an address range"},
		{"ip.in_cidr('10.0.0.0/33')", "is not an address range"},
		{"net.containsIP('x')", "\"x\" is not an IP address"},
		{"net.containsCIDR('x')", "\"x\" is not an address range"},
	}
	for _, c := range cases {
		_, err := env.Compile(c.src)
		if err == nil {
			t.Errorf("Compile(%q) succeeded, want %q", c.src, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("Compile(%q) error = %q, want %q", c.src, err, c.want)
		}
	}
}

func TestCheckCollectsErrors(t *testing.T) {
	env := testEnv(t)
	_, err := env.Compile("q + r == c(z) || i.f")
	var es Errors
	if !errors.As(err, &es) {
		t.Fatalf("error %T: %v", err, err)
	}
	want := []string{
		"1:1: undeclared reference to 'q'",
		"1:5: undeclared reference to 'r'",
		"1:10: undeclared function 'c'",
		"1:12: undeclared reference to 'z'",
		"1:20: 'f' selects a field of int, but only maps with string keys have fields",
	}
	var got []string
	for _, e := range es {
		got = append(got, e.Error())
	}
	if !slices.Equal(got, want) {
		t.Errorf("errors:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if err.Error() != strings.Join(want, "; ") {
		t.Errorf("Error() = %q", err)
	}
	// At most maxErrors are kept.
	_, err = env.Compile(strings.Repeat("q + ", 30) + "q")
	if !errors.As(err, &es) || len(es) != maxErrors {
		t.Errorf("30 errors kept as %d", len(es))
	}
}

func TestCheckedFacts(t *testing.T) {
	env := testEnv(t)
	c, err := env.Compile(`s.matches("^a") && t < timestamp("2026-01-01T00:00:00Z") &&
		dur > duration("90s") && ip.in_cidr("10.0.0.0/8") && t.getHours("Europe/Berlin") > 1 &&
		net.containsIP("10.0.0.1") && net.containsCIDR("10.0.0.0/16") && cidr("::/0") == net &&
		ip("::1") == ip && li.exists(i, i > 0) && x + 1 > 0`)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dur", "ip", "li", "net", "s", "t", "x"}; !slices.Equal(c.Vars(), want) {
		t.Errorf("Vars() = %v, want %v (the comprehension's i is not the declared i)", c.Vars(), want)
	}
	consts := map[string]any{}
	var calls []*Node
	var walk func(n *Node)
	walk = func(n *Node) {
		if v, ok := c.Constant(n); ok {
			consts[n.Value.(string)] = v
		}
		if n.Kind == NodeCall {
			calls = append(calls, n)
		}
		if n.Target != nil {
			walk(n.Target)
		}
		for _, a := range n.Args {
			walk(a)
		}
	}
	walk(c.AST().Root)
	berlin, _ := time.LoadLocation("Europe/Berlin")
	want := map[string]any{
		"^a":                   regexp.MustCompile("^a"),
		"2026-01-01T00:00:00Z": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		"90s":                  90 * time.Second,
		"10.0.0.0/8":           netip.MustParsePrefix("10.0.0.0/8"),
		"Europe/Berlin":        berlin,
		"10.0.0.1":             netip.MustParseAddr("10.0.0.1"),
		"10.0.0.0/16":          netip.MustParsePrefix("10.0.0.0/16"),
		"::/0":                 netip.MustParsePrefix("::/0"),
		"::1":                  netip.MustParseAddr("::1"),
	}
	if len(consts) != len(want) {
		t.Errorf("constants %v, want %v", consts, want)
	}
	for k, w := range want {
		g := consts[k]
		switch w := w.(type) {
		case *regexp.Regexp:
			if re, ok := g.(*regexp.Regexp); !ok || re.String() != w.String() {
				t.Errorf("constant %q = %v", k, g)
			}
		case *time.Location:
			if loc, ok := g.(*time.Location); !ok || loc.String() != w.String() {
				t.Errorf("constant %q = %v", k, g)
			}
		case time.Time:
			if tm, ok := g.(time.Time); !ok || !tm.Equal(w) {
				t.Errorf("constant %q = %v", k, g)
			}
		default:
			if !reflect.DeepEqual(g, w) {
				t.Errorf("constant %q = %#v, want %#v", k, g, w)
			}
		}
	}
	// Every call resolved; the ones with only static arguments to one
	// overload, the one with a dyn argument to all it may need at run time.
	for _, n := range calls {
		ovs := c.Overloads(n)
		if len(ovs) == 0 {
			t.Errorf("call %s has no overloads", n)
		}
		if n.Name == OpAdd && !slices.Equal(ovs, []string{"add_int64"}) {
			t.Errorf("x + 1 resolves to %v, want [add_int64]", ovs)
		}
		if n.Name == "matches" && !slices.Equal(ovs, []string{"matches_string"}) {
			t.Errorf("s.matches resolves to %v", ovs)
		}
	}
	if c.TypeOf(c.AST().Root) != c.Type() {
		t.Error("TypeOf(root) != Type()")
	}
}

func TestOverloadsWithDyn(t *testing.T) {
	env := testEnv(t)
	c, err := env.Compile("x < x")
	if err != nil {
		t.Fatal(err)
	}
	// Every ordering may apply to two dyn values.
	if n := len(c.Overloads(c.AST().Root)); n != 13 {
		t.Errorf("x < x has %d overloads, want 13: %v", n, c.Overloads(c.AST().Root))
	}
	c, err = env.Compile("x + x")
	if err != nil {
		t.Fatal(err)
	}
	if c.Type() != Dyn {
		t.Errorf("x + x is %s, want dyn", c.Type())
	}
}

func TestCompileAs(t *testing.T) {
	env := testEnv(t)
	if _, err := env.CompileAs("i > 1", Bool); err != nil {
		t.Error(err)
	}
	if _, err := env.CompileAs("x", Bool); err != nil {
		t.Errorf("dyn result: %v", err)
	}
	if _, err := env.CompileAs("li", ListOf(Dyn)); err != nil {
		t.Error(err)
	}
	_, err := env.CompileAs("\n  i + 1", Bool)
	if err == nil || err.Error() != "2:5: expression is int, want bool" {
		t.Errorf("CompileAs(int, bool) = %v", err)
	}
	if _, err := env.CompileAs("(", Bool); err == nil {
		t.Error("CompileAs parsed '('")
	}
	if _, err := env.CompileAs("y", Bool); err == nil {
		t.Error("CompileAs checked 'y'")
	}
}

func TestCheckTwice(t *testing.T) {
	env := testEnv(t)
	a, err := env.Parse("i > 1 && s.matches('a')")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewEnv([]Var{{"i", Double}, {"s", String}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*Env{env, other, env} {
		c, err := e.Check(a)
		if err != nil || c.Type() != Bool {
			t.Fatalf("Check: %v, %v", c, err)
		}
	}
	none, _ := NewEnv(nil)
	if _, err := none.Check(a); err == nil {
		t.Error("checked with no variables")
	}
}

func TestNewEnv(t *testing.T) {
	cases := []struct {
		vars []Var
		opts []Option
		want string
	}{
		{[]Var{{"", Int}}, nil, `variable name "" is not an identifier`},
		{[]Var{{"1a", Int}}, nil, `variable name "1a" is not an identifier`},
		{[]Var{{"a.b", Int}}, nil, `variable name "a.b" is not an identifier`},
		{[]Var{{"in", Int}}, nil, `variable name "in" is a reserved word`},
		{[]Var{{"true", Int}}, nil, `variable name "true" is a reserved word`},
		{[]Var{{"while", Int}}, nil, `variable name "while" is a reserved word`},
		{[]Var{{"a", nil}}, nil, `variable "a" has no type`},
		{[]Var{{"a", pA}}, nil, `variable "a" has no type`},
		{[]Var{{"a", ListOf(pA)}}, nil, `variable "a" has no type`},
		{[]Var{{"a", Int}, {"a", String}}, nil, `variable "a" is declared twice`},
		{nil, []Option{WithLimits(Limits{1, 1, 0})}, "limits must be positive"},
		{nil, []Option{WithLimits(Limits{})}, "limits must be positive"},
	}
	for _, c := range cases {
		_, err := NewEnv(c.vars, c.opts...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("NewEnv(%v) = %v, want %q", c.vars, err, c.want)
		}
	}
	env, err := NewEnv([]Var{{"_a1", MapOf(String, MapOf(Int, Dyn))}}, WithLimits(Limits{32, 4, 8}))
	if err != nil {
		t.Fatal(err)
	}
	if typ, ok := env.Lookup("_a1"); !ok || typ.String() != "map<string, map<int, dyn>>" {
		t.Errorf("Lookup = %v, %v", typ, ok)
	}
	if _, ok := env.Lookup("b"); ok {
		t.Error("Lookup found b")
	}
	if _, err := env.Compile("_a1.b.c.d.e"); err == nil || !strings.Contains(err.Error(), "nested more than 4 deep") {
		t.Errorf("limits not applied: %v", err)
	}
}

// Caveats in the shape SpiceDB and OpenFGA examples write them.
func TestCaveatExamples(t *testing.T) {
	env, err := NewEnv([]Var{
		{"now", Timestamp}, {"expires", Timestamp}, {"user_ip", IPAddress},
		{"allowed", ListOf(String)}, {"region", String}, {"budget", Int},
		{"spent", Int}, {"attrs", MapOf(String, Dyn)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{
		`now < expires`,
		`user_ip.in_cidr("10.0.0.0/8") || user_ip.in_cidr("192.168.0.0/16")`,
		`region in allowed`,
		`spent + 100 <= budget`,
		`now.getDayOfWeek("Europe/Berlin") in [1, 2, 3, 4, 5] &&
		 now.getHours("Europe/Berlin") >= 9 && now.getHours("Europe/Berlin") < 17`,
		`has(attrs.department) && attrs.department == "eng"`,
		`now - timestamp("2026-11-23T00:00:00Z") < duration("720h")`,
		`allowed.exists(r, r.startsWith("eu-")) && size(allowed) < 10`,
	} {
		if _, err := env.CompileAs(src, Bool); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
}

func TestParseZoneCache(t *testing.T) {
	a, err := ParseZone("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseZone("Asia/Tokyo")
	if err != nil || a != b {
		t.Errorf("second ParseZone = %p, %v; want the cached %p", b, err, a)
	}
	z, err := ParseZone("-03:30")
	if err != nil {
		t.Fatal(err)
	}
	if _, off := time.Date(2026, 1, 1, 0, 0, 0, 0, z).Zone(); off != -(3*3600 + 30*60) {
		t.Errorf("offset of -03:30 = %d", off)
	}
}
