package cel

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fullVars gives every variable of testEnv a value, in the forms callers
// pass: Go ints, JSON-style strings for times and addresses, Go maps.
func fullVars() map[string]any {
	return map[string]any{
		"i": 7, "u": uint(3), "d": 2.5, "s": "héllo", "b": true,
		"t": "2026-11-23T09:30:15.250+01:00", "dur": "1h30m", "ip": "10.1.2.3", "net": "10.0.0.0/8",
		"x":  int64(5),
		"li": []int{1, 2, 3}, "ls": []string{"a", "bc"}, "ll": [][]int{{1}, {2, 3}},
		"ms": map[string]string{"k": "v", "a": "b"},
		"md": map[string]any{"n": 1.5, "s": "str", "l": []any{1, "two"}, "z": nil},
		"mi": map[int]bool{1: true, 2: false},
		"mm": map[string]map[string]int{"a": {"x": 1}},
	}
}

func eval(t *testing.T, src string, vars map[string]any) (Result, error) {
	t.Helper()
	c, err := testEnv(t).Compile(src)
	if err != nil {
		t.Fatalf("Compile(%q): %v", src, err)
	}
	return c.Program(0).Eval(vars)
}

func TestEvalValues(t *testing.T) {
	cases := []struct {
		src  string
		want any
	}{
		// Literals and arithmetic.
		{"1", int64(1)}, {"1u", uint64(1)}, {"1.5", 1.5}, {"'a'", "a"}, {"null", nil},
		{"true", true}, {"i + 1", int64(8)}, {"i - 10", int64(-3)}, {"i * 3", int64(21)},
		{"i / 2", int64(3)}, {"-i / 2", int64(-3)}, {"i % 4", int64(3)}, {"-i % 4", int64(-3)},
		{"u + 1u", uint64(4)}, {"u - 1u", uint64(2)}, {"u * 2u", uint64(6)}, {"u / 2u", uint64(1)},
		{"u % 2u", uint64(1)}, {"d * 2.0", 5.0}, {"d / 0.0", math.Inf(1)}, {"d - 0.5", 2.0},
		{"-d", -2.5}, {"-i", int64(-7)}, {"!b", false}, {"s + '!'", "héllo!"},
		{"li + [4]", []any{int64(1), int64(2), int64(3), int64(4)}}, {"[] + []", []any{}},
		// Equality and ordering, across the numeric types by value.
		{"i == 7", true}, {"i == 7u", true}, {"i == 7.0", true}, {"i != 7.5", true},
		{"u == 3.0", true}, {"1u == -1", false}, {"0.0 == -0.0", true},
		{"double('NaN') == double('NaN')", false}, {"double('NaN') != double('NaN')", true},
		{"double('NaN') < 1.0", false}, {"1 >= double('NaN')", false},
		{"i < 7.5", true}, {"i > 6.9", true}, {"i <= 7u", true}, {"u > 2.5", true},
		{"-1 < 0u", true}, {"0u > -1", true}, {"9223372036854775807 < 9223372036854775808.0", true},
		{"18446744073709551615u < 18446744073709551616.0", true}, {"1u > -0.5", true},
		{"-9223372036854775808 > -9223372036854777856.0", true}, {"2.5 > 2u", true},
		{"-0.5 < 0", true}, {"0.5 > 0", true}, {"0.5 < 1u", true},
		{"'a' < 'b'", true}, {"'b' <= 'a'", false}, {"false < true", true}, {"true >= true", true},
		{"t < t + dur", true}, {"dur > duration('1h')", true}, {"dur <= dur", true},
		{"li == [1, 2, 3]", true}, {"li == [1, 2]", false}, {"li == [1, 2, 4]", false},
		{"ms == {'a': 'b', 'k': 'v'}", true}, {"ms == {'a': 'b', 'k': 'w'}", false},
		{"ms == {'a': 'b', 'j': 'v'}", false}, {"ms == {'a': 'b'}", false},
		{"mi == {1u: true, 2: false}", true}, {"x == 5", true}, {"x == 'five'", false},
		{"dyn(1) == dyn('1')", false}, {"null == null", true}, {"x == null", false},
		{"md.z == null", true}, {"ip == ip('10.1.2.3')", true}, {"net == cidr('10.0.0.0/8')", true},
		{"t == timestamp('2026-11-23T08:30:15.25Z')", true}, {"dyn(dur) == dyn(t)", false},
		{"dyn(ip) == dyn(net)", false}, {"dyn(net) == dyn(ip)", false}, {"dyn(b) == dyn(1)", false},
		{"dyn(t) == dyn(1)", false}, {"dyn(li) == dyn(ms)", false}, {"dyn(ms) == dyn(li)", false},
		{"dyn(s) == dyn(1)", false}, {"dyn(dur) == dyn(1)", false},
		// Membership, indexing and fields.
		{"2 in li", true}, {"4 in li", false}, {"dyn(2u) in li", true}, {"'k' in ms", true},
		{"'z' in ms", false}, {"dyn(1u) in mi", true}, {"dyn(1.0) in mi", true}, {"3 in mi", false},
		{"li[0]", int64(1)}, {"ll[1][1]", int64(3)}, {"ms['k']", "v"}, {"mi[2]", false},
		{"mi[dyn(2u)]", false}, {"mi[dyn(1.0)]", true}, {"dyn(li)[dyn(1u)]", int64(2)}, {"mm.a.x", int64(1)},
		{"md.l[1]", "two"}, {"has(ms.k)", true}, {"has(ms.q)", false}, {"has(mm.a.x)", true},
		{"{1u: 'a'}[dyn(1)]", "a"}, {"{1: 'a'}[dyn(1u)]", "a"}, {"{-1: 'a'}[dyn(-1.0)]", "a"},
		{"{true: 1}[true]", int64(1)}, {"{1u: 'a'}[dyn(1.0)]", "a"}, {"dyn(1.5) in {1u: 'a'}", false},
		{"dyn(-1) in {1u: 'a'}", false}, {"dyn(1e30) in {1u: 'a'}", false},
		{"1u < double('NaN')", false}, {"1u < 1e20", true}, {"1u == 1.5", false},
		// Logic: && and || decide on either side, ?: evaluates one branch.
		{"b && i > 1", true}, {"b && i > 10", false}, {"!b || i > 1", true}, {"!b || i > 10", false},
		{"1 / 0 == 1 && false", false}, {"false && 1 / 0 == 1", false},
		{"1 / 0 == 1 || true", true}, {"true || 1 / 0 == 1", true},
		{"dyn(1) && false", false}, {"b ? 'y' : string(1 / 0)", "y"}, {"!b ? string(1 / 0) : 'n'", "n"},
		// Comprehensions.
		{"li.all(e, e > 0)", true}, {"li.all(e, e > 1)", false}, {"li.exists(e, e == 2)", true},
		{"li.exists(e, e == 9)", false}, {"li.exists_one(e, e > 2)", true},
		{"li.exists_one(e, e > 1)", false}, {"li.filter(e, e % 2 == 1)", []any{int64(1), int64(3)}},
		{"li.filter(e, e > 9)", []any{}}, {"li.map(e, e * e)", []any{int64(1), int64(4), int64(9)}},
		{"li.map(e, e > 1, e * 10)", []any{int64(20), int64(30)}},
		{"ms.map(k, k + ms[k])", []any{"ab", "kv"}}, {"mi.filter(k, mi[k])", []any{int64(1)}},
		{"ll.map(l, l.map(e, e + size(l)))", []any{[]any{int64(2)}, []any{int64(4), int64(5)}}},
		{"li.all(e, li.exists(f, f == e))", true}, {"li.map(i, i).all(e, e < i + 10)", true},
		{"li.exists(e, e == 2 || 1 / 0 == 1)", true}, {"li.all(e, e == 2 && 1 / 0 == 1)", false},
		{"[[1, 2], [3]].map(l, l.exists(e, e > 2))", []any{false, true}},
		{"{'b': 1, 'a': 2}.map(k, k)", []any{"b", "a"}},
		// Strings.
		{"size(s)", int64(5)}, {"s.size()", int64(5)}, {"size(li)", int64(3)}, {"ms.size()", int64(2)},
		{"s.contains('ll')", true}, {"s.startsWith('hé')", true}, {"s.endsWith('lo')", true},
		{"s.endsWith('x')", false}, {"s.matches('^h.llo$')", true}, {"matches(s, 'x')", false},
		{"s.matches(ms.k)", false}, {"'v'.matches(ms['k'])", true},
		// Conversions.
		{"int(u)", int64(3)}, {"int(d)", int64(2)}, {"int(-2.9)", int64(-2)}, {"int('-42')", int64(-42)},
		{"int(t)", int64(1795422615)}, {"int(i)", int64(7)}, {"uint(i)", uint64(7)}, {"uint(d)", uint64(2)},
		{"uint('42')", uint64(42)}, {"uint(u)", uint64(3)}, {"double(i)", 7.0}, {"double(u)", 3.0},
		{"double('1e3')", 1000.0}, {"double(d)", 2.5}, {"string(i)", "7"}, {"string(u)", "3"},
		{"string(d)", "2.5"}, {"string(1e100)", "1e+100"}, {"string(b)", "true"}, {"string(s)", "héllo"},
		{"string(t)", "2026-11-23T08:30:15.25Z"}, {"string(dur)", "5400s"},
		{"string(duration('1.5s'))", "1.5s"}, {"string(duration('-1ns'))", "-0.000000001s"},
		{"string(ip)", "10.1.2.3"}, {"string(net)", "10.0.0.0/8"}, {"bool('true')", true},
		{"bool('F')", false}, {"bool(b)", true}, {"string(timestamp(0))", "1970-01-01T00:00:00Z"},
		{"string(timestamp(t))", "2026-11-23T08:30:15.25Z"},
		{"duration(dur) == dur", true}, {"dyn(s)", "héllo"},
		// Timestamps and durations.
		{"string(t + dur)", "2026-11-23T10:00:15.25Z"}, {"string(dur + t)", "2026-11-23T10:00:15.25Z"},
		{"string(t - dur)", "2026-11-23T07:00:15.25Z"}, {"string(t - timestamp('2026-11-23T00:00:00Z'))", "30615.25s"},
		{"string(dur + dur)", "10800s"}, {"string(dur - duration('30m'))", "3600s"},
		{"t.getFullYear()", int64(2026)}, {"t.getMonth()", int64(10)}, {"t.getDayOfYear()", int64(326)},
		{"t.getDayOfMonth()", int64(22)}, {"t.getDate()", int64(23)}, {"t.getDayOfWeek()", int64(1)},
		{"t.getHours()", int64(8)}, {"t.getMinutes()", int64(30)}, {"t.getSeconds()", int64(15)},
		{"t.getMilliseconds()", int64(250)}, {"t.getHours('Europe/Berlin')", int64(9)},
		{"t.getHours('+05:30')", int64(14)}, {"t.getMinutes('+05:30')", int64(0)},
		{"t.getHours(ms.a == 'b' ? 'Asia/Tokyo' : 'UTC')", int64(17)},
		{"timestamp('2026-12-31T23:00:00Z').getFullYear('Asia/Tokyo')", int64(2027)},
		{"dur.getHours()", int64(1)}, {"dur.getMinutes()", int64(90)}, {"dur.getSeconds()", int64(5400)},
		{"duration('1.5s').getMilliseconds()", int64(1500)}, {"duration('-90m').getHours()", int64(-1)},
		// Addresses and ranges.
		{"ip.in_cidr('10.0.0.0/8')", true}, {"ip.in_cidr(net)", true}, {"ip.in_cidr('192.168.0.0/16')", false},
		{"ip('::1').in_cidr('10.0.0.0/8')", false}, {"net.containsIP(ip)", true},
		{"net.containsIP('11.0.0.1')", false}, {"net.containsCIDR('10.2.0.0/16')", true},
		{"net.containsCIDR(cidr('0.0.0.0/0'))", false}, {"cidr('10.1.2.3/8').containsCIDR('10.9.0.0/16')", true},
		{"ip.family()", int64(4)}, {"ip('2001:db8::1').family()", int64(6)}, {"ip('::ffff:10.0.0.1').family()", int64(6)},
		{"ip('127.0.0.1').isLoopback()", true}, {"ip.isPrivate()", true}, {"ip('8.8.8.8').isPrivate()", false},
		{"ip('::').isUnspecified()", true}, {"isIP('1.2.3.4')", true}, {"isIP('1.2.3')", false},
		{"isIP(ms.k)", false}, {"isCIDR('::/0')", true}, {"isCIDR('::')", false}, {"string(net.ip())", "10.0.0.0"},
		{"net.prefixLength()", int64(8)}, {"string(cidr('10.1.2.3/8').masked())", "10.0.0.0/8"},
		{"string(ip(ms.a == 'b' ? '::1' : 'x'))", "::1"}, {"string(cidr(s.size() > 0 ? '::/1' : ''))", "::/1"},
		{"ip(ms.a == 'b' ? '::1' : 'x').in_cidr(ms.a == 'b' ? '::/64' : '')", true},
		{"net.containsIP(ms.a == 'b' ? '10.0.0.1' : '')", true},
	}
	for _, c := range cases {
		vars := fullVars()
		r, err := eval(t, c.src, vars)
		if err != nil {
			t.Errorf("%s: %v", c.src, err)
			continue
		}
		if !r.Known() {
			t.Errorf("%s: unknown, missing %v", c.src, r.Missing)
			continue
		}
		if !reflect.DeepEqual(r.Value, c.want) {
			t.Errorf("%s = %#v, want %#v", c.src, r.Value, c.want)
		}
	}
}

func TestEvalErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"9223372036854775807 + i", "1:21: integer overflow"},
		{"-9223372036854775808 - i", "integer overflow"},
		{"9223372036854775807 * i", "integer overflow"},
		{"-9223372036854775808 * -1", "integer overflow"},
		{"-1 * -9223372036854775808", "integer overflow"},
		{"-9223372036854775808 / -1", "integer overflow"},
		{"-9223372036854775808 % -1", "integer overflow"},
		{"-(i - 9223372036854775807 - 8)", "integer overflow"},
		{"18446744073709551615u + u", "integer overflow"},
		{"u - 4u", "integer overflow"}, {"18446744073709551615u * u", "integer overflow"},
		{"i / 0", "division by zero"}, {"u / 0u", "division by zero"},
		{"i % 0", "modulus by zero"}, {"u % 0u", "modulus by zero"},
		{"li[3]", "1:3: index 3 out of range for a list of 3"}, {"li[-1]", "index -1 out of range"},
		{"dyn(li)[dyn(18446744073709551615u)]", "out of range"},
		{"ms['q']", "no such key: 'q'"}, {"ms.q", "1:4: no such key: 'q'"}, {"mi[3]", "no such key: 3"},
		{"md.n.q", "no field 'q' on a double"}, {"has(md.n.q)", "no field 'q' on a double"},
		{"md.n + 1", "no matching overload for '+' applied to (double, int)"},
		{"dyn(1) && dyn(2)", "no matching overload for '&&' applied to a int"},
		{"true && dyn('a')", "applied to a string"}, {"dyn('a') || false", "applied to a string"},
		{"1 / 0 == 1 && true", "division by zero"}, {"true && 1 / 0 == 1", "division by zero"},
		{"1 / 0 == 1 && 2 / 0 == 1", "1:3: division by zero"},
		{"dyn(1) ? 1 : 2", "the condition of '?:' is a int"},
		{"dyn(1).all(e, e)", "all() needs a list or a map, not a int"},
		{"[1, 'a'].all(e, e)", "the predicate of all() is a int"},
		{"li.exists_one(e, 1 / 0 == e)", "division by zero"}, {"li.filter(e, e / 0 == 1)", "division by zero"},
		{"li.map(e, e / 0)", "division by zero"}, {"li.map(e, e / 0 == 1, e)", "division by zero"},
		{"[1, 2 / 0]", "division by zero"}, {"{'a': 1 / 0}", "division by zero"},
		{"{dyn(1.5): 1}", "a map key cannot be a double"}, {"{dyn(1): 1, dyn(1u): 2}", "map key 1 appears twice"},
		{"int(18446744073709551615u)", "integer overflow"}, {"int(1e19)", "out of the range of int"},
		{"int(double('NaN'))", "out of the range"}, {"int('1.5')", `cannot convert "1.5" to int`},
		{"uint(-1)", "out of the range of uint"}, {"uint(-0.5)", "out of the range of uint"},
		{"uint('x')", "cannot convert"}, {"double('x')", "cannot convert"}, {"bool('yes')", "cannot convert"},
		{"timestamp(ms.k)", "is not an RFC 3339 time"}, {"timestamp(253402300800)", "timestamp out of range"},
		{"timestamp('9999-12-31T23:59:59Z') + duration('1s')", "timestamp out of range"},
		{"timestamp('0001-01-01T00:00:00Z') - duration('1s')", "timestamp out of range"},
		{"t - duration(ms.k)", "duration \"v\""}, {"duration(ms.a + 's')", "duration \"bs\""},
		{"timestamp('9999-12-31T23:59:59Z') - timestamp('0001-01-01T00:00:00Z')", "duration overflow"},
		{"t - (duration('-2562047h') - duration('47m16.854775808s'))", "duration overflow"},
		{"duration('2562047h') + duration('2562047h')", "duration overflow"},
		{"duration('-2562047h') - duration('2562047h')", "duration overflow"},
		{"t.getHours(ms.k)", `unknown time zone "v"`}, {"s.matches(ms.k + '(')", "pattern \"v(\""},
		{"ip(ms.k)", `"v" is not an IP address`}, {"cidr(ms.k)", "is not an address range"},
		{"ip.in_cidr(ms.k)", "is not an address range"}, {"net.containsIP(ms.k)", "is not an IP address"},
		{"net.containsCIDR(ms.k)", "is not an address range"},
		{"dyn(1).size()", "no matching overload for 'size' applied to (int)"},
		{"dyn(t).getHours(dyn(null))", "no matching overload for 'getHours' applied to (timestamp, null_type)"},
		{"dyn(dur).getHours('UTC')", "no matching overload"}, {"dyn(1) + dyn(1u)", "no matching overload"},
		{"dyn(1) < dyn('a')", "no matching overload for '<'"}, {"dyn(li) in dyn(1)", "no matching overload"},
		{"-dyn('a')", "no matching overload for '-'"}, {"!dyn(1)", "no matching overload for '!'"},
		{"dyn(1)[0]", "no matching overload for '[]'"}, {"dyn(li)['a']", "no matching overload"},
		{"dyn(ms)[dyn(li)]", "no matching overload"}, {"dyn(1).contains('a')", "no matching overload"},
		{"dyn(1).matches('a')", "no matching overload"}, {"'a'.matches(dyn(1))", "no matching overload"},
		{"dyn(1).in_cidr('::/0')", "no matching overload"}, {"ip.in_cidr(dyn(1))", "no matching overload"},
		{"dyn(1).containsIP(ip)", "no matching overload"}, {"net.containsIP(dyn(1))", "no matching overload"},
		{"dyn(1).containsCIDR(net)", "no matching overload"}, {"net.containsCIDR(dyn(1))", "no matching overload"},
		{"dyn(1).getHours()", "no matching overload"}, {"dyn(1).getHours('UTC')", "no matching overload"},
		{"dyn(dur).getDate()", "no matching overload"}, {"dyn(1) - dyn(1u)", "no matching overload"},
		{"dyn(1) * dyn(1u)", "no matching overload"}, {"dyn(1) / dyn(1u)", "no matching overload"},
		{"dyn(1) % dyn(1u)", "no matching overload"}, {"dyn(1.0) % dyn(1.0)", "no matching overload"},
		{"dyn(t) + dyn(t)", "no matching overload"}, {"dyn(dur) + dyn(1)", "no matching overload"},
		{"dyn(t) - dyn(1)", "no matching overload"}, {"dyn(dur) - dyn(1)", "no matching overload"},
		{"dyn(1u) + dyn(1)", "no matching overload"}, {"dyn(1u) - dyn(1)", "no matching overload"},
		{"dyn(1u) * dyn(1)", "no matching overload"}, {"dyn(1u) / dyn(1)", "no matching overload"},
		{"dyn(1u) % dyn(1)", "no matching overload"}, {"dyn(1.0) + dyn(1)", "no matching overload"},
		{"dyn(1.0) - dyn(1)", "no matching overload"}, {"dyn(1.0) * dyn(1)", "no matching overload"},
		{"dyn(1.0) / dyn(1)", "no matching overload"}, {"dyn('a') + dyn(1)", "no matching overload"},
		{"dyn(li) + dyn(1)", "no matching overload"}, {"dyn(true) < dyn(1)", "no matching overload"},
		{"dyn('a') < dyn(1)", "no matching overload"}, {"dyn(t) < dyn(1)", "no matching overload"},
		{"dyn(dur) < dyn(1)", "no matching overload"}, {"int(dyn(ip))", "no matching overload"},
		{"uint(dyn(ip))", "no matching overload"}, {"double(dyn(ip))", "no matching overload"},
		{"string(dyn(li))", "no matching overload"}, {"bool(dyn(1))", "no matching overload"},
		{"timestamp(dyn(1.5))", "no matching overload"}, {"duration(dyn(1))", "no matching overload"},
		{"ip(dyn(1))", "no matching overload"}, {"cidr(dyn(1))", "no matching overload"},
		{"isIP(dyn(1))", "no matching overload"}, {"isCIDR(dyn(1))", "no matching overload"},
		{"dyn(1).family()", "no matching overload"}, {"dyn(1).isLoopback()", "no matching overload"},
		{"dyn(1).isPrivate()", "no matching overload"}, {"dyn(1).isUnspecified()", "no matching overload"},
		{"dyn(1).prefixLength()", "no matching overload"}, {"dyn(1).masked()", "no matching overload"},
	}
	for _, c := range cases {
		r, err := eval(t, c.src, fullVars())
		var es Errors
		if !errors.As(err, &es) || len(es) != 1 {
			t.Errorf("%s = %#v, %v; want error %q", c.src, r, err, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want %q", c.src, err, c.want)
		}
		if r.Cost == 0 {
			t.Errorf("%s: error with no cost", c.src)
		}
	}
}

// TestEvalUnknown checks the three-valued results: an expression that
// depends on an absent variable is unknown with that variable's name, and
// one whose value no absent variable could change is known.
func TestEvalUnknown(t *testing.T) {
	cases := []struct {
		src     string
		absent  []string
		want    any      // when missing is nil
		missing []string // sorted
	}{
		{"i + 1", []string{"i"}, nil, []string{"i"}},
		{"i + 1 > 2 && s == 'a'", []string{"i", "s"}, nil, []string{"i", "s"}},
		{"b && false", []string{"b"}, false, nil},
		{"false && b", []string{"b"}, false, nil},
		{"b && true", []string{"b"}, nil, []string{"b"}},
		{"b || true", []string{"b"}, true, nil},
		{"true || b", []string{"b"}, true, nil},
		{"b || i > 100", []string{"b"}, nil, []string{"b"}},
		{"b || i > 100", []string{"b", "i"}, nil, []string{"b", "i"}},
		{"b || i > 1", []string{"b"}, true, nil},
		// An unknown wins over an error: once the variable is supplied the
		// error may not matter.
		{"b && 1 / 0 == 1", []string{"b"}, nil, []string{"b"}},
		{"1 / 0 == 1 || b", []string{"b"}, nil, []string{"b"}},
		{"i / 0 + s.size()", []string{"s"}, nil, []string{"s"}},
		{"!b", []string{"b"}, nil, []string{"b"}},
		{"b ? 1 : 2", []string{"b"}, nil, []string{"b"}},
		{"true ? 1 : i", []string{"i"}, int64(1), nil},
		{"false ? i : 2", []string{"i"}, int64(2), nil},
		{"has(ms.k)", []string{"ms"}, nil, []string{"ms"}},
		{"ms.k", []string{"ms"}, nil, []string{"ms"}},
		{"[i, s, i]", []string{"s", "i"}, nil, []string{"i", "s"}},
		{"{'a': i, s: 1}", []string{"i", "s"}, nil, []string{"i", "s"}},
		{"li.all(e, e > 0)", []string{"li"}, nil, []string{"li"}},
		{"li.all(e, e > i)", []string{"i"}, nil, []string{"i"}},
		{"li.all(e, e > 1 && e > i)", []string{"i"}, false, nil},
		{"li.exists(e, e == 2 || b)", []string{"b"}, true, nil},
		{"li.exists(e, e == 9 || b)", []string{"b"}, nil, []string{"b"}},
		{"li.exists(e, b) || li.exists(e, i > e)", []string{"b", "i"}, nil, []string{"b", "i"}},
		{"li.exists_one(e, e == i)", []string{"i"}, nil, []string{"i"}},
		{"li.filter(e, e == i)", []string{"i"}, nil, []string{"i"}},
		{"li.map(e, e + i)", []string{"i"}, nil, []string{"i"}},
		{"li.map(e, e > i, e)", []string{"i"}, nil, []string{"i"}},
		{"li.map(e, e > 1, e + i)", []string{"i"}, nil, []string{"i"}},
		{"ip.in_cidr(net) && t.getHours('UTC') < 18", []string{"ip", "net", "t"}, nil, []string{"ip", "net", "t"}},
		{"ip.in_cidr(net) && t.getHours('UTC') < 18", []string{"ip"}, nil, []string{"ip"}},
		{"ip.in_cidr(net) && t.getHours('UTC') > 18", []string{"ip"}, false, nil},
	}
	for _, c := range cases {
		vars := fullVars()
		for _, name := range c.absent {
			delete(vars, name)
		}
		r, err := eval(t, c.src, vars)
		if err != nil {
			t.Errorf("%s without %v: %v", c.src, c.absent, err)
			continue
		}
		if !slices.Equal(r.Missing, c.missing) {
			t.Errorf("%s without %v: missing %v, want %v", c.src, c.absent, r.Missing, c.missing)
			continue
		}
		if r.Known() != (c.missing == nil) || !reflect.DeepEqual(r.Value, c.want) {
			t.Errorf("%s without %v = %#v, want %#v", c.src, c.absent, r, c.want)
		}
	}
}

func TestEvalCostLimit(t *testing.T) {
	env := testEnv(t)
	compile := func(src string) *Checked {
		c, err := env.Compile(src)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	big := make([]int, 1000)
	vars := map[string]any{"li": big, "s": strings.Repeat("a", 1<<16), "ls": []string{"a"}}

	// Each node costs one: 1 + 2 is three nodes.
	r, err := compile("1 + 2").Program(0).Eval(nil)
	if err != nil || r.Cost != 3 {
		t.Fatalf("1 + 2: %+v, %v; want cost 3", r, err)
	}
	if _, err := compile("1 + 2").Program(2).Eval(nil); !errors.Is(err, ErrCostLimit) {
		t.Fatalf("1 + 2 with a limit of 2: %v, want ErrCostLimit", err)
	}
	if r, err := compile("1 + 2").Program(3).Eval(nil); err != nil || r.Value != int64(3) {
		t.Fatalf("1 + 2 with a limit of 3: %+v, %v", r, err)
	}

	// A comprehension costs its body per element; nested ones multiply.
	r, err = compile("li.all(e, e == 0)").Program(0).Eval(vars)
	if err != nil || r.Cost < 3000 || r.Cost > 3100 {
		t.Fatalf("all over 1000: %+v, %v; want a cost of about 3000", r, err)
	}
	r, err = compile("li.map(a, li.map(b, a + b)).size()").Program(0).Eval(vars)
	if !errors.Is(err, ErrCostLimit) || r.Cost <= DefaultMaxCost {
		t.Fatalf("a million additions: %+v, %v; want ErrCostLimit", r, err)
	}
	if !strings.Contains(err.Error(), "more than 100000 units") {
		t.Errorf("error %q does not give the limit", err)
	}
	// A runtime error keeps the cost spent before it.
	vars["s"] = strings.Repeat("a", 1<<16)
	r, err = compile("timestamp(s) == timestamp(0)").Program(0).Eval(vars)
	if err == nil || r.Cost < 4096 {
		t.Errorf("failing timestamp(s): %+v, %v; want an error after a cost of 4096", r, err)
	}
	// The limit is not absorbed by || as runtime errors are.
	if _, err := compile("true || li.map(a, li.map(b, a)).size() > 0").Program(0).Eval(vars); err != nil {
		t.Fatalf("short circuit: %v", err)
	}
	if _, err := compile("li.map(a, li.map(b, a)).size() > 0 || true").Program(0).Eval(vars); !errors.Is(err, ErrCostLimit) {
		t.Fatalf("cost limit under ||: %v", err)
	}
	// Membership and equality cost per element, strings per 16 bytes.
	for _, c := range []struct {
		src      string
		min, max uint64
	}{
		{"1 in li", 1000, 1010},
		{"li == li", 1000, 1010},
		{"li + li == li + li", 6000, 6020},
		{"s.contains('b')", 4096, 4106},
		{"s + s == s", 12288, 12300},
		{"s < s", 4096, 4106},
		{"size(s) > 0", 4096, 4106},
		{"s.matches('b')", 4097, 4110},
		{"s.matches(ls[0])", 4097, 4110},
		{"ms == ms", 2, 12},
		{"string(s) == s", 4096, 4110},
		{"int(ls[0] == 'a' ? '1' : s) == 1", 8, 20},
	} {
		vars := map[string]any{"li": big, "s": strings.Repeat("a", 1<<16), "ls": []string{"a"},
			"ms": map[string]string{"a": "b", "c": "d"}}
		r, err := compile(c.src).Program(1 << 20).Eval(vars)
		if err != nil || r.Cost < c.min || r.Cost > c.max {
			t.Errorf("%s: cost %d, %v; want %d to %d", c.src, r.Cost, err, c.min, c.max)
		}
	}
}

func TestEvalInputs(t *testing.T) {
	env, err := NewEnv([]Var{
		{"i", Int}, {"u", Uint}, {"d", Double}, {"s", String}, {"b", Bool},
		{"t", Timestamp}, {"dur", Duration}, {"ip", IPAddress}, {"net", CIDR},
		{"x", Dyn}, {"li", ListOf(Int)}, {"mi", MapOf(Int, String)}, {"md", MapOf(String, Dyn)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ok := []struct {
		name string
		v    any
		src  string // true for the value
	}{
		{"i", int8(-3), "i == -3"}, {"i", int16(-3), "i == -3"}, {"i", int32(-3), "i == -3"},
		{"i", int64(-3), "i == -3"}, {"i", uint8(3), "i == 3"}, {"i", uint64(3), "i == 3"},
		{"i", 3.0, "i == 3"}, {"i", json.Number("-3"), "i == -3"}, {"i", uintptr(3), "i == 3"},
		{"u", uint16(3), "u == 3u"}, {"u", uint32(3), "u == 3u"}, {"u", uint8(3), "u == 3u"},
		{"u", 3, "u == 3u"}, {"u", 3.0, "u == 3u"}, {"u", json.Number("18446744073709551615"), "u == 18446744073709551615u"},
		{"d", float32(1.5), "d == 1.5"}, {"d", 2, "d == 2.0"}, {"d", uint(2), "d == 2.0"},
		{"d", json.Number("1.5"), "d == 1.5"}, {"s", "a", "s == 'a'"}, {"b", true, "b"},
		{"t", time.Date(2026, 1, 1, 1, 0, 0, 0, time.FixedZone("x", 3600)), "string(t) == '2026-01-01T00:00:00Z'"},
		{"t", "2026-01-01T00:00:00Z", "t.getFullYear() == 2026"}, {"dur", time.Second, "dur == duration('1s')"},
		{"dur", "1s", "dur == duration('1s')"}, {"ip", netip.MustParseAddr("::1"), "ip.isLoopback()"},
		{"net", netip.MustParsePrefix("::/0"), "net.prefixLength() == 0"},
		{"x", nil, "x == null"}, {"x", int8(1), "x == 1"}, {"x", uint8(1), "x == 1u"},
		{"x", float32(0.5), "x == 0.5"}, {"x", json.Number("1"), "x == 1"}, {"x", json.Number("1.5"), "x == 1.5"},
		{"x", time.Unix(0, 0), "x == timestamp(0)"}, {"x", time.Second, "x == duration('1s')"},
		{"x", netip.MustParseAddr("::1"), "x == ip('::1')"}, {"x", netip.MustParsePrefix("::/0"), "x == cidr('::/0')"},
		{"x", []string{"a"}, "x == ['a']"}, {"x", [2]int{1, 2}, "x == [1, 2]"},
		{"x", map[string]int{"b": 1, "a": 2}, "x.map(k, k) == ['a', 'b']"},
		{"x", map[any]any{true: 1, 2: 3, "s": 4, false: 0, -1: 0, uint(1): 0}, "x.map(k, string(k)) == ['false', 'true', '-1', '1', '2', 's']"},
		{"li", []any{1, 2.0}, "li == [1, 2]"}, {"li", []int64{}, "li == []"},
		{"mi", map[int]string{2: "b", 1: "a"}, "mi.map(k, mi[k]) == ['a', 'b']"},
		{"md", map[string]any{"l": []any{1, "a"}, "m": map[string]any{}}, "md.l == [1, 'a'] && md.m == {}"},
		{"md", map[string]any{"k": []any{"a", 1.5, nil, true}}, "md.k[1] == 1.5"},
	}
	for _, c := range ok {
		comp, err := env.CompileAs(c.src, Bool)
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		r, err := comp.Program(0).Eval(map[string]any{c.name: c.v})
		if err != nil || r.Value != true {
			t.Errorf("%s with %s = %#v: %+v, %v", c.src, c.name, c.v, r, err)
		}
	}
	type opaque struct{}
	deep := any(1)
	for range 70 {
		deep = []any{deep}
	}
	bad := []struct {
		name string
		v    any
		want string
	}{
		{"i", "1", "variable i is a string, want int"}, {"i", 1.5, "the number 1.5, want int"},
		{"s", 1e6, "is the number 1000000, want string"}, {"s", 1e21, "is the number 1e+21, want string"},
		{"s", float32(0.5), "is the number 0.5, want string"}, {"s", math.Copysign(0, -1), "is the number 0, want string"},
		{"i", uint64(1 << 63), "want int"}, {"i", 1e19, "want int"}, {"i", json.Number("1.5"), "want int"},
		{"i", nil, "variable i is null, want int"}, {"u", -1, "want uint"}, {"u", -1.0, "want uint"},
		{"u", 0.5, "want uint"}, {"u", json.Number("-1"), "want uint"}, {"d", "1", "want double"},
		{"d", json.Number("x"), "want double"}, {"s", 1, "want string"}, {"b", "true", "is a string, want bool"},
		{"t", "yesterday", "not an RFC 3339 time"}, {"t", time.Time{}.Add(-time.Hour), "out of range"},
		{"t", 1, "want timestamp"}, {"dur", "1 day", "duration \"1 day\""}, {"dur", 1, "want duration"},
		{"ip", "1.2.3", "not an IP address"}, {"ip", netip.Addr{}, "not an IP address without a zone"},
		{"ip", netip.MustParseAddr("fe80::1%eth0"), "without a zone"}, {"ip", 1, "want ipaddress"},
		{"net", "1.2.3.4", "not an address range"}, {"net", netip.Prefix{}, "not an address range"},
		{"net", 1, "want cidr"}, {"x", opaque{}, "unsupported type cel.opaque"},
		{"x", json.Number("1e999"), "number \"1e999\""}, {"x", deep, "nested deeper than 64"},
		{"x", map[float64]int{1.5: 1}, "maps are keyed by bool, int, uint or string"},
		{"x", map[any]int{1: 1, uint(1): 2}, "appears twice"}, {"x", map[string]any{"a": opaque{}}, "[a] has unsupported type"},
		{"x", map[opaque]int{{}: 1}, "key {}: has unsupported type"},
		{"li", "1", "want list<int>"}, {"li", []any{1, "2"}, "[1] is a string, want int"},
		{"mi", map[string]string{"a": "b"}, "key a: is a string, want int"}, {"mi", []int{}, "want map<int, string>"},
		{"md", map[string]any{"k": map[string]any{"a": []any{opaque{}}}}, "[k] [a] [0] has unsupported type"},
	}
	for _, c := range bad {
		src := c.name + " == " + c.name
		comp, err := env.Compile(src)
		if err != nil {
			t.Fatal(err)
		}
		_, err = comp.Program(0).Eval(map[string]any{c.name: c.v})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s = %#v: error %v, want %q", c.name, c.v, err, c.want)
		}
	}
	// A variable the expression does not use is not converted.
	comp, _ := env.Compile("i == 1")
	if r, err := comp.Program(0).Eval(map[string]any{"i": 1, "s": 2}); err != nil || r.Value != true {
		t.Errorf("unused variable of the wrong type: %+v, %v", r, err)
	}
}

func TestEvalExportsValues(t *testing.T) {
	r, err := eval(t, "{'l': [1, {2: 'b'}], 'm': ms}", fullVars())
	if err != nil {
		t.Fatal(err)
	}
	want := map[any]any{"l": []any{int64(1), map[any]any{int64(2): "b"}}, "m": map[any]any{"a": "b", "k": "v"}}
	if !reflect.DeepEqual(r.Value, want) {
		t.Errorf("got %#v, want %#v", r.Value, want)
	}
	r, err = eval(t, "[t, dur, ip, net]", fullVars())
	if err != nil {
		t.Fatal(err)
	}
	l := r.Value.([]any)
	if tm := l[0].(time.Time); tm.Location() != time.UTC || l[1] != 90*time.Minute ||
		l[2] != netip.MustParseAddr("10.1.2.3") || l[3] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("got %#v", l)
	}
}

// TestEvalConcurrent runs one Program from many goroutines, under the race
// detector in CI: each Eval keeps its own state.
func TestEvalConcurrent(t *testing.T) {
	c, err := testEnv(t).Compile("li.map(e, e * i).exists(e, e == 14) && ll.all(l, l.all(e, e > 0))")
	if err != nil {
		t.Fatal(err)
	}
	p := c.Program(0)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for n := range 200 {
				vars := fullVars()
				vars["i"] = g + n
				r, err := p.Eval(vars)
				if err != nil || r.Value != (g+n == 7 || g+n == 14) {
					t.Errorf("i=%d: %+v, %v", g+n, r, err)
					return
				}
			}
		})
	}
	wg.Wait()
	if p.Checked() != c {
		t.Error("Program.Checked does not return its expression")
	}
}

func TestUnknownMerge(t *testing.T) {
	u := func(names ...string) *unknown { return &unknown{names: names} }
	cases := []struct{ a, b, want *unknown }{
		{nil, u("a"), u("a")}, {u("a"), nil, u("a")}, {u("a"), u("a"), u("a")},
		{u("a", "c"), u("b"), u("a", "b", "c")}, {u("b"), u("a", "c"), u("a", "b", "c")},
		{u("a", "b"), u("b", "c"), u("a", "b", "c")}, {u("c"), u("a", "b"), u("a", "b", "c")},
	}
	for _, c := range cases {
		if got := c.a.merge(c.b); !slices.Equal(got.names, c.want.names) {
			t.Errorf("%v merge %v = %v, want %v", c.a, c.b, got.names, c.want.names)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0s", time.Nanosecond: "0.000000001s", 1500 * time.Millisecond: "1.5s",
		-90 * time.Second: "-90s", math.MinInt64: "-9223372036.854775808s",
		math.MaxInt64: "9223372036.854775807s",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%d) = %q, want %q", d, got, want)
		}
	}
}
