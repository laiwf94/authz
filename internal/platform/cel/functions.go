package cel

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// overload is one signature of a function. A member overload is called as
// params[0].name(params[1:]...).
type overload struct {
	id     string
	member bool
	params []*Type
	result *Type
}

var (
	pA = param("A")
	pB = param("B")
)

// functions maps each function name to its overloads, member and global.
var functions = map[string][]overload{}

func def(name string, ovs ...overload) {
	functions[name] = append(functions[name], ovs...)
}

func global(id string, result *Type, params ...*Type) overload {
	return overload{id: id, params: params, result: result}
}

func member(id string, result *Type, params ...*Type) overload {
	return overload{id: id, member: true, params: params, result: result}
}

// numeric kinds as overload ID suffixes, for the mixed comparisons.
var numerics = []struct {
	name string
	t    *Type
}{{"int64", Int}, {"uint64", Uint}, {"double", Double}}

func init() {
	def(OpAdd,
		global("add_int64", Int, Int, Int),
		global("add_uint64", Uint, Uint, Uint),
		global("add_double", Double, Double, Double),
		global("add_string", String, String, String),
		global("add_list", ListOf(pA), ListOf(pA), ListOf(pA)),
		global("add_timestamp_duration", Timestamp, Timestamp, Duration),
		global("add_duration_timestamp", Timestamp, Duration, Timestamp),
		global("add_duration_duration", Duration, Duration, Duration))
	def(OpSub,
		global("subtract_int64", Int, Int, Int),
		global("subtract_uint64", Uint, Uint, Uint),
		global("subtract_double", Double, Double, Double),
		global("subtract_timestamp_timestamp", Duration, Timestamp, Timestamp),
		global("subtract_timestamp_duration", Timestamp, Timestamp, Duration),
		global("subtract_duration_duration", Duration, Duration, Duration))
	for _, op := range []struct{ fn, id string }{{OpMul, "multiply"}, {OpDiv, "divide"}} {
		def(op.fn,
			global(op.id+"_int64", Int, Int, Int),
			global(op.id+"_uint64", Uint, Uint, Uint),
			global(op.id+"_double", Double, Double, Double))
	}
	def(OpMod,
		global("modulo_int64", Int, Int, Int),
		global("modulo_uint64", Uint, Uint, Uint))
	def(OpNeg,
		global("negate_int64", Int, Int),
		global("negate_double", Double, Double))
	def(OpNot, global("logical_not", Bool, Bool))
	def(OpAnd, global("logical_and", Bool, Bool, Bool))
	def(OpOr, global("logical_or", Bool, Bool, Bool))
	def(OpConditional, global("conditional", pA, Bool, pA, pA))

	// Equality is defined for any two values of one type, and across the
	// numeric types, which compare by value: 1 == 1u == 1.0.
	def(OpEq, global("equals", Bool, pA, pA))
	def(OpNe, global("not_equals", Bool, pA, pA))
	for _, a := range numerics {
		for _, b := range numerics {
			if a.t != b.t {
				suffix := "_" + a.name + "_" + b.name
				def(OpEq, global("equals"+suffix, Bool, a.t, b.t))
				def(OpNe, global("not_equals"+suffix, Bool, a.t, b.t))
			}
		}
	}
	ordered := []struct {
		name string
		t    *Type
	}{{"bool", Bool}, {"int64", Int}, {"uint64", Uint}, {"double", Double},
		{"string", String}, {"timestamp", Timestamp}, {"duration", Duration}}
	for _, op := range []struct{ fn, id string }{
		{OpLess, "less"}, {OpLessEq, "less_equals"},
		{OpGreater, "greater"}, {OpGreaterEq, "greater_equals"},
	} {
		for _, o := range ordered {
			def(op.fn, global(op.id+"_"+o.name, Bool, o.t, o.t))
		}
		for _, a := range numerics {
			for _, b := range numerics {
				if a.t != b.t {
					def(op.fn, global(op.id+"_"+a.name+"_"+b.name, Bool, a.t, b.t))
				}
			}
		}
	}
	def(OpIn,
		global("in_list", Bool, pA, ListOf(pA)),
		global("in_map", Bool, pA, MapOf(pA, pB)))
	def(OpIndex,
		global("index_list", pA, ListOf(pA), Int),
		global("index_map", pB, MapOf(pA, pB), pA))

	def("size",
		global("size_string", Int, String),
		global("size_list", Int, ListOf(pA)),
		global("size_map", Int, MapOf(pA, pB)),
		member("string_size", Int, String),
		member("list_size", Int, ListOf(pA)),
		member("map_size", Int, MapOf(pA, pB)))
	def("contains", member("contains_string", Bool, String, String))
	def("startsWith", member("starts_with_string", Bool, String, String))
	def("endsWith", member("ends_with_string", Bool, String, String))
	def("matches",
		global("matches", Bool, String, String),
		member("matches_string", Bool, String, String))

	def("int",
		global("int64_to_int64", Int, Int),
		global("uint64_to_int64", Int, Uint),
		global("double_to_int64", Int, Double),
		global("string_to_int64", Int, String),
		global("timestamp_to_int64", Int, Timestamp))
	def("uint",
		global("int64_to_uint64", Uint, Int),
		global("uint64_to_uint64", Uint, Uint),
		global("double_to_uint64", Uint, Double),
		global("string_to_uint64", Uint, String))
	def("double",
		global("int64_to_double", Double, Int),
		global("uint64_to_double", Double, Uint),
		global("double_to_double", Double, Double),
		global("string_to_double", Double, String))
	def("string",
		global("int64_to_string", String, Int),
		global("uint64_to_string", String, Uint),
		global("double_to_string", String, Double),
		global("string_to_string", String, String),
		global("bool_to_string", String, Bool),
		global("timestamp_to_string", String, Timestamp),
		global("duration_to_string", String, Duration),
		global("ip_to_string", String, IPAddress),
		global("cidr_to_string", String, CIDR))
	def("bool",
		global("bool_to_bool", Bool, Bool),
		global("string_to_bool", Bool, String))
	def("timestamp",
		global("string_to_timestamp", Timestamp, String),
		global("timestamp_to_timestamp", Timestamp, Timestamp),
		global("int64_to_timestamp", Timestamp, Int))
	def("duration",
		global("string_to_duration", Duration, String),
		global("duration_to_duration", Duration, Duration))
	def("dyn", global("to_dyn", Dyn, pA))

	for _, name := range []string{
		"getFullYear", "getMonth", "getDayOfYear", "getDayOfMonth", "getDate",
		"getDayOfWeek", "getHours", "getMinutes", "getSeconds", "getMilliseconds",
	} {
		def(name,
			member("timestamp_to_"+name, Int, Timestamp),
			member("timestamp_to_"+name+"_with_tz", Int, Timestamp, String))
	}
	for _, name := range []string{"getHours", "getMinutes", "getSeconds", "getMilliseconds"} {
		def(name, member("duration_to_"+name, Int, Duration))
	}

	def("ip", global("string_to_ip", IPAddress, String))
	def("cidr", global("string_to_cidr", CIDR, String))
	def("isIP", global("is_ip", Bool, String))
	def("isCIDR", global("is_cidr", Bool, String))
	def("family", member("ip_family", Int, IPAddress))
	def("isLoopback", member("ip_is_loopback", Bool, IPAddress))
	def("isPrivate", member("ip_is_private", Bool, IPAddress))
	def("isUnspecified", member("ip_is_unspecified", Bool, IPAddress))
	def("in_cidr",
		member("ip_in_cidr_string", Bool, IPAddress, String),
		member("ip_in_cidr", Bool, IPAddress, CIDR))
	def("containsIP",
		member("cidr_contains_ip", Bool, CIDR, IPAddress),
		member("cidr_contains_ip_string", Bool, CIDR, String))
	def("containsCIDR",
		member("cidr_contains_cidr", Bool, CIDR, CIDR),
		member("cidr_contains_cidr_string", Bool, CIDR, String))
	def("ip", member("cidr_ip", IPAddress, CIDR))
	def("prefixLength", member("cidr_prefix_length", Int, CIDR))
	def("masked", member("cidr_masked", CIDR, CIDR))

	for _, name := range []string{
		"getFullYear", "getMonth", "getDayOfYear", "getDayOfMonth", "getDate",
		"getDayOfWeek", "getHours", "getMinutes", "getSeconds", "getMilliseconds",
	} {
		constantArgs["timestamp_to_"+name+"_with_tz"] = constantArg{1, func(s string) (any, error) { return ParseZone(s) }}
	}
}

// constantArg is an argument that, when it is a string literal, is parsed
// once when the expression is checked: a bad pattern, time, zone or address
// is an error then rather than on every evaluation.
type constantArg struct {
	index int // into the receiver followed by the arguments
	parse func(string) (any, error)
}

var constantArgs = map[string]constantArg{
	"string_to_timestamp":       {0, func(s string) (any, error) { return ParseTimestamp(s) }},
	"string_to_duration":        {0, func(s string) (any, error) { return ParseDuration(s) }},
	"matches":                   {1, func(s string) (any, error) { return compileRegexp(s) }},
	"matches_string":            {1, func(s string) (any, error) { return compileRegexp(s) }},
	"string_to_ip":              {0, func(s string) (any, error) { return ParseIP(s) }},
	"string_to_cidr":            {0, func(s string) (any, error) { return ParseCIDR(s) }},
	"ip_in_cidr_string":         {1, func(s string) (any, error) { return ParseCIDR(s) }},
	"cidr_contains_ip_string":   {1, func(s string) (any, error) { return ParseIP(s) }},
	"cidr_contains_cidr_string": {1, func(s string) (any, error) { return ParseCIDR(s) }},
}

// The range of timestamps CEL defines: years 1 to 9999, in UTC.
var (
	minTimestamp = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	maxTimestamp = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
)

// ParseTimestamp reads an RFC 3339 time, such as 2026-11-23T09:00:00Z or
// 2026-11-23T09:00:00.5+01:00, in the range of years 1 to 9999.
func ParseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q is not an RFC 3339 time", s)
	}
	if t.Before(minTimestamp) || t.After(maxTimestamp) {
		return time.Time{}, fmt.Errorf("timestamp %q is out of range", s)
	}
	return t, nil
}

// ParseDuration reads a duration such as 90s, 1h30m or -1.5h: a sequence of
// decimal numbers, each with a unit of h, m, s, ms, us or ns.
func ParseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("duration %q: want a number and a unit, such as 90s or 1h30m", s)
	}
	return d, nil
}

// ParseIP reads an IPv4 or IPv6 address without a zone.
func ParseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("IP address %q has a zone, which is not supported", s)
	}
	return a, nil
}

// ParseCIDR reads an address range such as 10.0.0.0/8 or 2001:db8::/32.
// Bits below the prefix may be set (10.1.2.3/8 is the range 10.0.0.0/8, as
// written).
func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an address range such as 10.0.0.0/8", s)
	}
	return p, nil
}

func compileRegexp(s string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %v", s, err)
	}
	return re, nil
}

var zones sync.Map // name -> *time.Location

// ParseZone reads a time zone: an IANA name such as Europe/Berlin or UTC,
// or a fixed offset such as +05:30 or -08:00. The machine's local zone is
// refused, so an expression means the same everywhere.
func ParseZone(s string) (*time.Location, error) {
	if loc, ok := zones.Load(s); ok {
		return loc.(*time.Location), nil
	}
	loc, err := loadZone(s)
	if err != nil {
		return nil, err
	}
	zones.Store(s, loc)
	return loc, nil
}

func loadZone(s string) (*time.Location, error) {
	if len(s) == 6 && (s[0] == '+' || s[0] == '-') && s[3] == ':' {
		h, err1 := strconv.Atoi(s[1:3])
		m, err2 := strconv.Atoi(s[4:6])
		if err1 != nil || err2 != nil || !isDigit(s[1]) || !isDigit(s[4]) || h > 23 || m > 59 {
			return nil, fmt.Errorf("time zone offset %q: want ±HH:MM", s)
		}
		off := h*3600 + m*60
		if s[0] == '-' {
			off = -off
		}
		return time.FixedZone(s, off), nil
	}
	if s == "" || s == "Local" {
		return nil, fmt.Errorf("time zone %q: name an IANA zone such as UTC or Europe/Berlin", s)
	}
	loc, err := time.LoadLocation(s)
	if err != nil {
		return nil, fmt.Errorf("unknown time zone %q", s)
	}
	return loc, nil
}
