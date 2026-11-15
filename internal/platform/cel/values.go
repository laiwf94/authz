package cel

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Values while an expression runs:
//
//	null       nil
//	bool       bool
//	int        int64
//	uint       uint64
//	double     float64
//	string     string
//	timestamp  time.Time, in UTC
//	duration   time.Duration
//	ipaddress  netip.Addr
//	cidr       netip.Prefix
//	list       []any
//	map        *mapValue
//
// and, never inside a list or a map, *unknown for a result that depends on
// absent variables and *evalErr for a runtime error.

// mapValue is a map with its keys in a fixed order: the order of a literal,
// or sorted for a map converted from Go, so that comprehensions over a map
// give the same result every time.
type mapValue struct {
	keys []any
	vals map[any]any
}

func newMap(n int) *mapValue {
	return &mapValue{keys: make([]any, 0, n), vals: make(map[any]any, n)}
}

// put adds a key, reporting false when an equal key is already present.
func (m *mapValue) put(k, v any) bool {
	if _, dup := m.get(k); dup {
		return false
	}
	m.keys = append(m.keys, k)
	m.vals[k] = v
	return true
}

// get looks a key up. Numeric keys equal by value find each other: m[1u]
// finds the key 1, and m[1.0] finds 1 or 1u.
func (m *mapValue) get(k any) (any, bool) {
	if v, ok := m.vals[k]; ok {
		return v, true
	}
	switch k := k.(type) {
	case int64:
		if k >= 0 {
			v, ok := m.vals[uint64(k)]
			return v, ok
		}
	case uint64:
		if k <= math.MaxInt64 {
			v, ok := m.vals[int64(k)]
			return v, ok
		}
	case float64:
		if k == math.Trunc(k) && k >= -0x1p63 && k < 0x1p63 {
			if v, ok := m.vals[int64(k)]; ok {
				return v, true
			}
		}
		if k == math.Trunc(k) && k >= 0 && k < 0x1p64 {
			v, ok := m.vals[uint64(k)]
			return v, ok
		}
	}
	return nil, false
}

// isKey reports whether v can be a map key.
func isKey(v any) bool {
	switch v.(type) {
	case bool, int64, uint64, string:
		return true
	}
	return false
}

// equal is CEL equality: numbers compare by value across int, uint and
// double, lists and maps element by element, and values of different types
// are not equal. NaN equals nothing. It charges e for the elements and bytes
// it compares.
func (e *evaluator) equal(a, b any) bool {
	switch a := a.(type) {
	case nil:
		return b == nil
	case bool:
		b, ok := b.(bool)
		return ok && a == b
	case int64, uint64, float64:
		c, ok := compareNumbers(a, b)
		return ok && c == 0
	case string:
		b, ok := b.(string)
		if ok {
			e.charge(uint64(min(len(a), len(b))) / 16)
		}
		return ok && a == b
	case time.Time:
		b, ok := b.(time.Time)
		return ok && a.Equal(b)
	case time.Duration:
		b, ok := b.(time.Duration)
		return ok && a == b
	case netip.Addr:
		b, ok := b.(netip.Addr)
		return ok && a == b
	case netip.Prefix:
		b, ok := b.(netip.Prefix)
		return ok && a == b
	case []any:
		b, ok := b.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			e.charge(1)
			if !e.equal(a[i], b[i]) {
				return false
			}
		}
		return true
	case *mapValue:
		b, ok := b.(*mapValue)
		if !ok || len(a.keys) != len(b.keys) {
			return false
		}
		for _, k := range a.keys {
			e.charge(1)
			bv, found := b.get(k)
			if !found || !e.equal(a.vals[k], bv) {
				return false
			}
		}
		return true
	}
	return false
}

// compareNumbers orders two numbers of any of the numeric types by value.
// It reports false when either is not a number or is NaN.
func compareNumbers(a, b any) (int, bool) {
	switch a := a.(type) {
	case int64:
		switch b := b.(type) {
		case int64:
			return cmp3(a < b, a > b), true
		case uint64:
			if a < 0 {
				return -1, true
			}
			return cmp3(uint64(a) < b, uint64(a) > b), true
		case float64:
			return compareIntDouble(a, b)
		}
	case uint64:
		switch b := b.(type) {
		case uint64:
			return cmp3(a < b, a > b), true
		case int64:
			c, ok := compareNumbers(b, a)
			return -c, ok
		case float64:
			return compareUintDouble(a, b)
		}
	case float64:
		switch b := b.(type) {
		case float64:
			if math.IsNaN(a) || math.IsNaN(b) {
				return 0, false
			}
			return cmp3(a < b, a > b), true
		case int64, uint64:
			c, ok := compareNumbers(b, a)
			return -c, ok
		}
	}
	return 0, false
}

func cmp3(less, greater bool) int {
	switch {
	case less:
		return -1
	case greater:
		return 1
	}
	return 0
}

// compareIntDouble compares exactly, without rounding i to a double.
func compareIntDouble(i int64, d float64) (int, bool) {
	switch {
	case math.IsNaN(d):
		return 0, false
	case d >= 0x1p63:
		return -1, true
	case d < -0x1p63:
		return 1, true
	}
	t := math.Trunc(d)
	if c := cmp3(i < int64(t), i > int64(t)); c != 0 {
		return c, true
	}
	return cmp3(t < d, t > d), true
}

func compareUintDouble(u uint64, d float64) (int, bool) {
	switch {
	case math.IsNaN(d):
		return 0, false
	case d >= 0x1p64:
		return -1, true
	case d < 0:
		return 1, true
	}
	t := math.Trunc(d)
	if c := cmp3(u < uint64(t), u > uint64(t)); c != 0 {
		return c, true
	}
	return cmp3(t < d, t > d), true
}

// convertInput turns a Go value given for a variable of type t into the
// value the evaluator works on. It accepts the native types above, Go's
// other integer and float types, json.Number, and what encoding/json
// decodes into any: a whole float64 for an int or a uint, and RFC 3339
// times, durations such as "90s", addresses and ranges as strings. Slices
// and arrays become lists and Go maps become maps.
func convertInput(t *Type, v any, depth int) (any, error) {
	if depth > maxInputDepth {
		return nil, fmt.Errorf("nested deeper than %d", maxInputDepth)
	}
	if v == nil {
		if t.kind == KindDyn {
			return nil, nil
		}
		return nil, fmt.Errorf("is null, want %s", t)
	}
	switch t.kind {
	case KindDyn:
		return convertDyn(v, depth)
	case KindBool:
		if b, ok := v.(bool); ok {
			return b, nil
		}
	case KindInt:
		if i, ok := toInt(v); ok {
			return i, nil
		}
	case KindUint:
		if u, ok := toUint(v); ok {
			return u, nil
		}
	case KindDouble:
		if d, ok := toDouble(v); ok {
			return d, nil
		}
	case KindString:
		if s, ok := v.(string); ok {
			return s, nil
		}
	case KindTimestamp:
		switch v := v.(type) {
		case time.Time:
			if v.Before(minTimestamp) || v.After(maxTimestamp) {
				return nil, fmt.Errorf("timestamp %s is out of range", v.Format(time.RFC3339Nano))
			}
			return v.UTC(), nil
		case string:
			ts, err := ParseTimestamp(v)
			if err != nil {
				return nil, err
			}
			return ts.UTC(), nil
		}
	case KindDuration:
		switch v := v.(type) {
		case time.Duration:
			return v, nil
		case string:
			return ParseDuration(v)
		}
	case KindIP:
		switch v := v.(type) {
		case netip.Addr:
			if !v.IsValid() || v.Zone() != "" {
				return nil, fmt.Errorf("%v is not an IP address without a zone", v)
			}
			return v, nil
		case string:
			return ParseIP(v)
		}
	case KindCIDR:
		switch v := v.(type) {
		case netip.Prefix:
			if !v.IsValid() {
				return nil, fmt.Errorf("%v is not an address range", v)
			}
			return v, nil
		case string:
			return ParseCIDR(v)
		}
	case KindList:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
			break
		}
		if l, ok := v.([]any); ok && t.elem.kind == KindDyn && plainList(l) {
			return l, nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			x, err := convertInput(t.elem, rv.Index(i).Interface(), depth+1)
			if err != nil {
				return nil, fmt.Errorf("[%d] %v", i, err)
			}
			out[i] = x
		}
		return out, nil
	case KindMap:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Map {
			if m, ok := v.(*mapValue); ok {
				return m, nil
			}
			break
		}
		m := newMap(rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			k, err := convertInput(t.key, iter.Key().Interface(), depth+1)
			if err != nil {
				return nil, fmt.Errorf("key %v: %v", iter.Key(), err)
			}
			if !isKey(k) {
				return nil, fmt.Errorf("key %v: maps are keyed by bool, int, uint or string", iter.Key())
			}
			x, err := convertInput(t.elem, iter.Value().Interface(), depth+1)
			if err != nil {
				return nil, fmt.Errorf("[%v] %v", iter.Key(), err)
			}
			if !m.put(k, x) {
				return nil, fmt.Errorf("key %v appears twice", iter.Key())
			}
		}
		slices.SortFunc(m.keys, compareKeys)
		return m, nil
	}
	return nil, fmt.Errorf("is %s, want %s", describeGo(v), t)
}

// maxInputDepth bounds the nesting of a variable's value.
const maxInputDepth = 64

// plainList reports whether l holds only scalar evaluator values, so a
// list<dyn> given as []any can be used without copying.
func plainList(l []any) bool {
	for _, x := range l {
		switch x.(type) {
		case nil, bool, int64, uint64, float64, string, time.Duration, netip.Addr, netip.Prefix:
		default:
			return false
		}
	}
	return true
}

// convertDyn converts a value of a dyn variable by its Go type.
func convertDyn(v any, depth int) (any, error) {
	switch v := v.(type) {
	case bool, string, int64, uint64, float64:
		return v, nil
	case int, int8, int16, int32:
		i, _ := toInt(v)
		return i, nil
	case uint, uint8, uint16, uint32, uintptr:
		u, _ := toUint(v)
		return u, nil
	case float32:
		return float64(v), nil
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, nil
		}
		f, err := v.Float64()
		if err != nil {
			return nil, fmt.Errorf("number %q: %v", v, err)
		}
		return f, nil
	case time.Time:
		return convertInput(Timestamp, v, depth)
	case time.Duration:
		return v, nil
	case netip.Addr:
		return convertInput(IPAddress, v, depth)
	case netip.Prefix:
		return convertInput(CIDR, v, depth)
	case *mapValue:
		return v, nil
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Slice, reflect.Array:
		return convertInput(ListOf(Dyn), v, depth)
	case reflect.Map:
		return convertInput(&Type{kind: KindMap, key: Dyn, elem: Dyn}, v, depth)
	}
	return nil, fmt.Errorf("has unsupported type %T", v)
}

func toInt(v any) (int64, bool) {
	switch v := v.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int16:
		return int64(v), true
	case int8:
		return int64(v), true
	case uint64, uint, uint32, uint16, uint8, uintptr:
		u, _ := toUint(v)
		if u > math.MaxInt64 {
			return 0, false
		}
		return int64(u), true
	case float64:
		if v != math.Trunc(v) || v < -0x1p63 || v >= 0x1p63 {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		i, err := v.Int64()
		return i, err == nil
	}
	return 0, false
}

func toUint(v any) (uint64, bool) {
	switch v := v.(type) {
	case uint64:
		return v, true
	case uint:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case uintptr:
		return uint64(v), true
	case int64, int, int32, int16, int8:
		i, _ := toInt(v)
		if i < 0 {
			return 0, false
		}
		return uint64(i), true
	case float64:
		if v != math.Trunc(v) || v < 0 || v >= 0x1p64 {
			return 0, false
		}
		return uint64(v), true
	case json.Number:
		u, err := strconv.ParseUint(string(v), 10, 64)
		return u, err == nil
	}
	return 0, false
}

func toDouble(v any) (float64, bool) {
	switch v := v.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	if i, ok := toInt(v); ok {
		return float64(i), true
	}
	if u, ok := toUint(v); ok {
		return float64(u), true
	}
	return 0, false
}

// compareKeys orders map keys: bools, then numbers by value, then strings.
func compareKeys(a, b any) int {
	rank := func(v any) int {
		switch v.(type) {
		case bool:
			return 0
		case int64, uint64:
			return 1
		}
		return 2
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return ra - rb
	}
	switch a := a.(type) {
	case bool:
		return cmp3(!a && b.(bool), a && !b.(bool))
	case string:
		return strings.Compare(a, b.(string))
	}
	c, _ := compareNumbers(a, b)
	return c
}

// exportValue turns an evaluator value into the Go value Result carries:
// lists as []any and maps as map[any]any.
func exportValue(v any) any {
	switch v := v.(type) {
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = exportValue(x)
		}
		return out
	case *mapValue:
		out := make(map[any]any, len(v.keys))
		for _, k := range v.keys {
			out[k] = exportValue(v.vals[k])
		}
		return out
	}
	return v
}

// describeGo names the type of a Go value in an error.
func describeGo(v any) string {
	switch v := v.(type) {
	case string:
		return "a string"
	case bool:
		return "a bool"
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return fmt.Sprintf("the number %v", v)
	}
	return fmt.Sprintf("%T", v)
}

// typeName names the CEL type of an evaluator value, for errors.
func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null_type"
	case bool:
		return "bool"
	case int64:
		return "int"
	case uint64:
		return "uint"
	case float64:
		return "double"
	case string:
		return "string"
	case time.Time:
		return "timestamp"
	case time.Duration:
		return "duration"
	case netip.Addr:
		return "ipaddress"
	case netip.Prefix:
		return "cidr"
	case []any:
		return "list"
	case *mapValue:
		return "map"
	}
	return fmt.Sprintf("%T", v)
}
