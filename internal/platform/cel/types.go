package cel

import (
	"fmt"
	"strings"
)

// Kind is the kind of a Type.
type Kind uint8

// The kinds of the subset. KindDyn is a value whose type is known only when
// the expression runs; KindParam is a type parameter of a function overload
// and never the type of an expression.
const (
	KindDyn Kind = iota
	KindNull
	KindBool
	KindInt
	KindUint
	KindDouble
	KindString
	KindTimestamp
	KindDuration
	KindIP
	KindCIDR
	KindList
	KindMap
	KindParam
)

// Type is the static type of a variable or an expression. Types are
// compared with Equal, not ==, because list and map types are built on
// demand.
type Type struct {
	kind  Kind
	elem  *Type  // list element, map value
	key   *Type  // map key
	param string // type parameter name
}

// The scalar types. They are shared values and must not be changed.
var (
	Dyn       = &Type{kind: KindDyn}
	Null      = &Type{kind: KindNull}
	Bool      = &Type{kind: KindBool}
	Int       = &Type{kind: KindInt}
	Uint      = &Type{kind: KindUint}
	Double    = &Type{kind: KindDouble}
	String    = &Type{kind: KindString}
	Timestamp = &Type{kind: KindTimestamp}
	Duration  = &Type{kind: KindDuration}
	IPAddress = &Type{kind: KindIP}
	CIDR      = &Type{kind: KindCIDR}
)

// ListOf returns the type of lists whose elements have type elem.
func ListOf(elem *Type) *Type { return &Type{kind: KindList, elem: elem} }

// MapOf returns the type of maps from key to value. Map keys are bool, int,
// uint or string (or dyn); MapOf panics on any other key type, as declaring
// one is a programming error. ParseType reports it as an error instead.
func MapOf(key, value *Type) *Type {
	if !validKey(key) {
		panic("cel: invalid map key type " + key.String())
	}
	return &Type{kind: KindMap, key: key, elem: value}
}

func param(name string) *Type { return &Type{kind: KindParam, param: name} }

func validKey(t *Type) bool {
	switch t.kind {
	case KindBool, KindInt, KindUint, KindString, KindDyn, KindParam:
		return true
	}
	return false
}

// Kind returns the kind of t.
func (t *Type) Kind() Kind { return t.kind }

// Elem returns the element type of a list or the value type of a map, and
// nil for any other type.
func (t *Type) Elem() *Type { return t.elem }

// Key returns the key type of a map and nil for any other type.
func (t *Type) Key() *Type { return t.key }

// Equal reports whether t and u are the same type.
func (t *Type) Equal(u *Type) bool {
	if t == u {
		return true
	}
	if t == nil || u == nil || t.kind != u.kind {
		return false
	}
	switch t.kind {
	case KindList:
		return t.elem.Equal(u.elem)
	case KindMap:
		return t.key.Equal(u.key) && t.elem.Equal(u.elem)
	case KindParam:
		return t.param == u.param
	}
	return true
}

// String returns the type as ParseType reads it: "int", "list<string>",
// "map<string, dyn>".
func (t *Type) String() string {
	var b strings.Builder
	t.write(&b)
	return b.String()
}

func (t *Type) write(b *strings.Builder) {
	switch t.kind {
	case KindList:
		b.WriteString("list<")
		t.elem.write(b)
		b.WriteString(">")
	case KindMap:
		b.WriteString("map<")
		t.key.write(b)
		b.WriteString(", ")
		t.elem.write(b)
		b.WriteString(">")
	case KindParam:
		b.WriteString(t.param)
	default:
		b.WriteString(kindNames[t.kind])
	}
}

var kindNames = [...]string{
	KindDyn:       "dyn",
	KindNull:      "null_type",
	KindBool:      "bool",
	KindInt:       "int",
	KindUint:      "uint",
	KindDouble:    "double",
	KindString:    "string",
	KindTimestamp: "timestamp",
	KindDuration:  "duration",
	KindIP:        "ipaddress",
	KindCIDR:      "cidr",
	KindList:      "list",
	KindMap:       "map",
}

var scalarNames = map[string]*Type{
	"dyn":       Dyn,
	"any":       Dyn,
	"bool":      Bool,
	"int":       Int,
	"uint":      Uint,
	"double":    Double,
	"string":    String,
	"timestamp": Timestamp,
	"duration":  Duration,
	"ipaddress": IPAddress,
	"cidr":      CIDR,
}

// ParseType reads a type written the way schemas declare caveat parameters:
// a scalar name (bool, int, uint, double, string, timestamp, duration,
// ipaddress, cidr, dyn, or any for dyn), list<T>, map<V> for a map with
// string keys, or map<K, V>. Spaces around names and punctuation are
// ignored.
func ParseType(s string) (*Type, error) {
	p := typeParser{s: s}
	t, err := p.parse(0)
	if err != nil {
		return nil, fmt.Errorf("type %q: %v", s, err)
	}
	p.space()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("type %q: unexpected %q", s, p.s[p.i:])
	}
	return t, nil
}

type typeParser struct {
	s string
	i int
}

// maxTypeDepth bounds nesting such as list<list<list<...>>>.
const maxTypeDepth = 16

func (p *typeParser) space() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *typeParser) expect(c byte) error {
	p.space()
	if p.i >= len(p.s) || p.s[p.i] != c {
		return fmt.Errorf("expected %q at offset %d", c, p.i)
	}
	p.i++
	return nil
}

func (p *typeParser) parse(depth int) (*Type, error) {
	if depth > maxTypeDepth {
		return nil, fmt.Errorf("nested deeper than %d", maxTypeDepth)
	}
	p.space()
	start := p.i
	for p.i < len(p.s) && isIdentByte(p.s[p.i]) {
		p.i++
	}
	name := p.s[start:p.i]
	switch name {
	case "":
		return nil, fmt.Errorf("expected a type name at offset %d", start)
	case "list":
		if err := p.expect('<'); err != nil {
			return nil, err
		}
		elem, err := p.parse(depth + 1)
		if err != nil {
			return nil, err
		}
		if err := p.expect('>'); err != nil {
			return nil, err
		}
		return ListOf(elem), nil
	case "map":
		if err := p.expect('<'); err != nil {
			return nil, err
		}
		first, err := p.parse(depth + 1)
		if err != nil {
			return nil, err
		}
		p.space()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			value, err := p.parse(depth + 1)
			if err != nil {
				return nil, err
			}
			if err := p.expect('>'); err != nil {
				return nil, err
			}
			if !validKey(first) {
				return nil, fmt.Errorf("map keys must be bool, int, uint or string, not %s", first)
			}
			return MapOf(first, value), nil
		}
		if err := p.expect('>'); err != nil {
			return nil, err
		}
		return MapOf(String, first), nil
	}
	if t, ok := scalarNames[name]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("unknown type %q", name)
}

func isIdentByte(c byte) bool {
	return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// assignable reports whether a value of type from can be used where to is
// expected. Dyn goes either way; null goes only to dyn.
func assignable(to, from *Type) bool {
	if to.kind == KindDyn || from.kind == KindDyn {
		return true
	}
	if to.kind != from.kind {
		return false
	}
	switch to.kind {
	case KindList:
		return assignable(to.elem, from.elem)
	case KindMap:
		return assignable(to.key, from.key) && assignable(to.elem, from.elem)
	}
	return true
}

// join is the type of a list or map literal whose members have types a and
// b: their common type when they agree, dyn otherwise.
func join(a, b *Type) *Type {
	if a == nil {
		return b
	}
	if a.Equal(b) {
		return a
	}
	if a.kind == b.kind {
		switch a.kind {
		case KindList:
			return ListOf(join(a.elem, b.elem))
		case KindMap:
			return &Type{kind: KindMap, key: join(a.key, b.key), elem: join(a.elem, b.elem)}
		}
	}
	return Dyn
}
