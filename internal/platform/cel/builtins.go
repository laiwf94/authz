package cel

import (
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// unary applies a function of one operand (a global call's argument or a
// method's receiver). ok is false when no overload takes the operand.
func (e *evaluator) unary(name string, a any) (any, bool) {
	switch name {
	case OpNeg:
		switch a := a.(type) {
		case int64:
			if a == math.MinInt64 {
				return fail(errOverflow), true
			}
			return -a, true
		case float64:
			return -a, true
		}
	case OpNot:
		if b, ok := a.(bool); ok {
			return !b, true
		}
	case "size":
		switch a := a.(type) {
		case string:
			e.chargeBytes(len(a))
			return int64(utf8.RuneCountInString(a)), true
		case []any:
			return int64(len(a)), true
		case *mapValue:
			return int64(len(a.keys)), true
		}
	case "int":
		return e.toIntValue(a)
	case "uint":
		return e.toUintValue(a)
	case "double":
		return e.toDoubleValue(a)
	case "string":
		return toStringValue(a)
	case "bool":
		switch a := a.(type) {
		case bool:
			return a, true
		case string:
			b, err := strconv.ParseBool(a)
			if err != nil {
				return fail("cannot convert %q to bool", a), true
			}
			return b, true
		}
	case "timestamp":
		switch a := a.(type) {
		case time.Time:
			return a, true
		case string:
			e.chargeBytes(len(a))
			t, err := ParseTimestamp(a)
			if err != nil {
				return fail("%v", err), true
			}
			return t.UTC(), true
		case int64:
			// Seconds since 1970 in the range of years 1 to 9999.
			if a < minTimestamp.Unix() || a > maxTimestamp.Unix() {
				return fail(errRange), true
			}
			return time.Unix(a, 0).UTC(), true
		}
	case "duration":
		switch a := a.(type) {
		case time.Duration:
			return a, true
		case string:
			e.chargeBytes(len(a))
			d, err := ParseDuration(a)
			if err != nil {
				return fail("%v", err), true
			}
			return d, true
		}
	case "dyn":
		return a, true
	case "ip":
		switch a := a.(type) {
		case netip.Addr:
			return a, true
		case netip.Prefix:
			return a.Addr(), true
		case string:
			ip, err := ParseIP(a)
			if err != nil {
				return fail("%v", err), true
			}
			return ip, true
		}
	case "cidr":
		switch a := a.(type) {
		case netip.Prefix:
			return a, true
		case string:
			p, err := ParseCIDR(a)
			if err != nil {
				return fail("%v", err), true
			}
			return p, true
		}
	case "isIP":
		if s, ok := a.(string); ok {
			_, err := ParseIP(s)
			return err == nil, true
		}
	case "isCIDR":
		if s, ok := a.(string); ok {
			_, err := ParseCIDR(s)
			return err == nil, true
		}
	case "family":
		if ip, ok := a.(netip.Addr); ok {
			if ip.Is4() {
				return int64(4), true
			}
			return int64(6), true
		}
	case "isLoopback":
		if ip, ok := a.(netip.Addr); ok {
			return ip.IsLoopback(), true
		}
	case "isPrivate":
		if ip, ok := a.(netip.Addr); ok {
			return ip.IsPrivate(), true
		}
	case "isUnspecified":
		if ip, ok := a.(netip.Addr); ok {
			return ip.IsUnspecified(), true
		}
	case "prefixLength":
		if p, ok := a.(netip.Prefix); ok {
			return int64(p.Bits()), true
		}
	case "masked":
		if p, ok := a.(netip.Prefix); ok {
			return p.Masked(), true
		}
	default:
		if strings.HasPrefix(name, "get") {
			return timePart(name, a, nil)
		}
	}
	return nil, false
}

func (e *evaluator) toIntValue(a any) (any, bool) {
	switch a := a.(type) {
	case int64:
		return a, true
	case uint64:
		if a > math.MaxInt64 {
			return fail(errOverflow), true
		}
		return int64(a), true
	case float64:
		if math.IsNaN(a) || a < -0x1p63 || a >= 0x1p63 {
			return fail("double %v out of the range of int", a), true
		}
		return int64(a), true
	case string:
		e.chargeBytes(len(a))
		i, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return fail("cannot convert %q to int", a), true
		}
		return i, true
	case time.Time:
		return a.Unix(), true
	}
	return nil, false
}

func (e *evaluator) toUintValue(a any) (any, bool) {
	switch a := a.(type) {
	case uint64:
		return a, true
	case int64:
		if a < 0 {
			return fail("int %d out of the range of uint", a), true
		}
		return uint64(a), true
	case float64:
		if math.IsNaN(a) || a < 0 || a >= 0x1p64 {
			return fail("double %v out of the range of uint", a), true
		}
		return uint64(a), true
	case string:
		e.chargeBytes(len(a))
		u, err := strconv.ParseUint(a, 10, 64)
		if err != nil {
			return fail("cannot convert %q to uint", a), true
		}
		return u, true
	}
	return nil, false
}

func (e *evaluator) toDoubleValue(a any) (any, bool) {
	switch a := a.(type) {
	case float64:
		return a, true
	case int64:
		return float64(a), true
	case uint64:
		return float64(a), true
	case string:
		e.chargeBytes(len(a))
		f, err := strconv.ParseFloat(a, 64)
		if err != nil {
			return fail("cannot convert %q to double", a), true
		}
		return f, true
	}
	return nil, false
}

func toStringValue(a any) (any, bool) {
	switch a := a.(type) {
	case string:
		return a, true
	case int64:
		return strconv.FormatInt(a, 10), true
	case uint64:
		return strconv.FormatUint(a, 10), true
	case float64:
		return strconv.FormatFloat(a, 'g', -1, 64), true
	case bool:
		return strconv.FormatBool(a), true
	case time.Time:
		return a.UTC().Format(time.RFC3339Nano), true
	case time.Duration:
		return formatDuration(a), true
	case netip.Addr:
		return a.String(), true
	case netip.Prefix:
		return a.String(), true
	}
	return nil, false
}

// formatDuration writes a duration as CEL does: seconds with as many
// decimals as it needs, such as 90s, 1.5s or -0.000000001s.
func formatDuration(d time.Duration) string {
	var b []byte
	u := uint64(d)
	if d < 0 {
		b = append(b, '-')
		u = -u
	}
	b = strconv.AppendUint(b, u/1e9, 10)
	if frac := u % 1e9; frac != 0 {
		f := strconv.FormatUint(frac+1e9, 10)[1:] // nine digits
		b = append(b, '.')
		b = append(b, strings.TrimRight(f, "0")...)
	}
	return string(append(b, 's'))
}

func (e *evaluator) matches(a, b any) (any, bool) {
	s, ok := a.(string)
	if !ok {
		return nil, false
	}
	var re *regexp.Regexp
	switch p := b.(type) {
	case *regexp.Regexp:
		re = p
	case string:
		e.chargeBytes(len(p) * 4)
		var err error
		if re, err = compileRegexp(p); err != nil {
			return fail("%v", err), true
		}
	default:
		return nil, false
	}
	// RE2 runs in time linear in the input for a given pattern, with a
	// factor that grows with the pattern.
	e.charge(uint64(len(s)/16+1) * uint64(len(re.String())/16+1))
	return re.MatchString(s), true
}

func ipBinary(name string, a, b any) (any, bool) {
	switch name {
	case "in_cidr":
		ip, ok := a.(netip.Addr)
		if !ok {
			return nil, false
		}
		p, v, ok := prefixArg(b)
		if !ok || v != nil {
			return v, ok
		}
		return p.Contains(ip), true
	case "containsIP":
		p, ok := a.(netip.Prefix)
		if !ok {
			return nil, false
		}
		var ip netip.Addr
		switch b := b.(type) {
		case netip.Addr:
			ip = b
		case string:
			var err error
			if ip, err = ParseIP(b); err != nil {
				return fail("%v", err), true
			}
		default:
			return nil, false
		}
		return p.Contains(ip), true
	}
	// containsCIDR
	p, ok := a.(netip.Prefix)
	if !ok {
		return nil, false
	}
	q, v, ok := prefixArg(b)
	if !ok || v != nil {
		return v, ok
	}
	return q.Bits() >= p.Bits() && p.Contains(q.Addr()), true
}

// prefixArg reads a range given as a cidr or a string; v is the error of a
// string that is not one.
func prefixArg(b any) (p netip.Prefix, v any, ok bool) {
	switch b := b.(type) {
	case netip.Prefix:
		return b, nil, true
	case string:
		p, err := ParseCIDR(b)
		if err != nil {
			return p, fail("%v", err), true
		}
		return p, nil, true
	}
	return p, nil, false
}

// timePart reads a part of a timestamp, in UTC or the zone tz (a string
// or a parsed *time.Location), or of a duration when tz is nil.
func timePart(name string, a, tz any) (any, bool) {
	switch a := a.(type) {
	case time.Duration:
		if tz != nil {
			return nil, false
		}
		var unit time.Duration
		switch name {
		case "getHours":
			unit = time.Hour
		case "getMinutes":
			unit = time.Minute
		case "getSeconds":
			unit = time.Second
		case "getMilliseconds":
			unit = time.Millisecond
		default:
			return nil, false
		}
		return int64(a / unit), true
	case time.Time:
		loc := time.UTC
		switch z := tz.(type) {
		case nil:
		case *time.Location:
			loc = z
		case string:
			var err error
			if loc, err = ParseZone(z); err != nil {
				return fail("%v", err), true
			}
		default:
			return nil, false
		}
		t := a.In(loc)
		var v int
		switch name {
		case "getFullYear":
			v = t.Year()
		case "getMonth":
			v = int(t.Month()) - 1
		case "getDayOfYear":
			v = t.YearDay() - 1
		case "getDayOfMonth":
			v = t.Day() - 1
		case "getDate":
			v = t.Day()
		case "getDayOfWeek":
			v = int(t.Weekday())
		case "getHours":
			v = t.Hour()
		case "getMinutes":
			v = t.Minute()
		case "getSeconds":
			v = t.Second()
		case "getMilliseconds":
			v = t.Nanosecond() / 1e6
		default:
			return nil, false
		}
		return int64(v), true
	}
	return nil, false
}
