package cel

import (
	"strings"
	"testing"
)

func TestParseType(t *testing.T) {
	cases := []struct{ src, want string }{
		{"bool", "bool"}, {"int", "int"}, {"uint", "uint"}, {"double", "double"},
		{"string", "string"}, {"timestamp", "timestamp"}, {"duration", "duration"},
		{"ipaddress", "ipaddress"}, {"cidr", "cidr"}, {"dyn", "dyn"}, {"any", "dyn"},
		{"list<int>", "list<int>"}, {" list < list<string> > ", "list<list<string>>"},
		{"map<int>", "map<string, int>"}, {"map<int, bool>", "map<int, bool>"},
		{"map<string,list<any>>", "map<string, list<dyn>>"}, {"map<uint, map<bool, cidr>>", "map<uint, map<bool, cidr>>"},
		{"map<dyn, int>", "map<dyn, int>"},
	}
	for _, c := range cases {
		typ, err := ParseType(c.src)
		if err != nil {
			t.Errorf("ParseType(%q): %v", c.src, err)
			continue
		}
		if typ.String() != c.want {
			t.Errorf("ParseType(%q) = %s, want %s", c.src, typ, c.want)
		}
		again, err := ParseType(typ.String())
		if err != nil || !again.Equal(typ) {
			t.Errorf("ParseType(%q) = %v, %v; want %s", typ.String(), again, err, typ)
		}
	}
	errs := []struct{ src, want string }{
		{"", "expected a type name at offset 0"},
		{"float", `unknown type "float"`},
		{"list", `expected '<' at offset 4`},
		{"list<int", `expected '>' at offset 8`},
		{"list<>", "expected a type name at offset 5"},
		{"map<int,>", "expected a type name"},
		{"map<double, int>", "map keys must be bool, int, uint or string, not double"},
		{"map<list<int>, int>", "map keys must be bool, int, uint or string, not list<int>"},
		{"int int", `unexpected "int"`},
		{"map<int, int", "expected '>'"},
		{"map", "expected '<'"},
		{"map<int", "expected '>'"},
		{"map<,", "expected a type name"},
		{strings.Repeat("list<", 20) + "int" + strings.Repeat(">", 20), "nested deeper than 16"},
	}
	for _, c := range errs {
		_, err := ParseType(c.src)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseType(%q) = %v, want %q", c.src, err, c.want)
		}
	}
}

func TestTypeAccessors(t *testing.T) {
	m := MapOf(String, ListOf(Int))
	if m.Kind() != KindMap || m.Key() != String || m.Elem().Kind() != KindList || m.Elem().Elem() != Int {
		t.Errorf("accessors of %s", m)
	}
	if Int.Elem() != nil || Int.Key() != nil {
		t.Error("int has an element type")
	}
	if !ListOf(Int).Equal(ListOf(Int)) || ListOf(Int).Equal(ListOf(Uint)) || ListOf(Int).Equal(Int) {
		t.Error("list equality")
	}
	if !MapOf(Int, Bool).Equal(MapOf(Int, Bool)) || MapOf(Int, Bool).Equal(MapOf(String, Bool)) {
		t.Error("map equality")
	}
	if !pA.Equal(param("A")) || pA.Equal(pB) || pA.String() != "A" {
		t.Error("type parameters")
	}
	var nilType *Type
	if nilType.Equal(Int) || Int.Equal(nil) {
		t.Error("nil type equality")
	}
	defer func() {
		if recover() == nil {
			t.Error("MapOf(double, int) did not panic")
		}
	}()
	MapOf(Double, Int)
}

func TestJoinAndAssignable(t *testing.T) {
	cases := []struct {
		a, b *Type
		want string
	}{
		{Int, Int, "int"},
		{Int, String, "dyn"},
		{ListOf(Int), ListOf(String), "list<dyn>"},
		{MapOf(String, Int), MapOf(Int, Int), "map<dyn, int>"},
		{ListOf(Int), MapOf(Int, Int), "dyn"},
	}
	for _, c := range cases {
		if got := join(c.a, c.b).String(); got != c.want {
			t.Errorf("join(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
	if !assignable(ListOf(Dyn), ListOf(Int)) || !assignable(ListOf(Int), Dyn) || assignable(ListOf(Int), ListOf(String)) {
		t.Error("list assignability")
	}
	if !assignable(MapOf(String, Dyn), MapOf(String, Int)) || assignable(MapOf(String, Int), MapOf(Int, Int)) {
		t.Error("map assignability")
	}
	if assignable(Int, Null) || !assignable(Dyn, Null) {
		t.Error("null assignability")
	}
}
