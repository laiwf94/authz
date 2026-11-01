// Package schema parses and validates grantd's authorization schema language.
//
// A schema declares object types ("definitions"), the relations that can be
// stored on them, and permissions computed from those relations:
//
//	definition user {}
//
//	definition group {
//	  relation member: user | group#member
//	}
//
//	definition document {
//	  relation parent: folder
//	  relation owner: user
//	  relation viewer: user | user:* | group#member
//	  relation banned: user
//	  permission edit = owner
//	  permission view = (viewer + edit + parent->view) - banned
//	}
//
// Operators, from tightest to loosest binding: "->" (arrow), "&"
// (intersection), "+" (union), "-" (exclusion). Binary operators are
// left-associative; parentheses group.
package schema

import (
	"fmt"
	"strings"
)

// Schema is a validated set of definitions.
type Schema struct {
	Defs  map[string]*Definition
	Order []string // definition names in source order
}

// Definition is one object type.
type Definition struct {
	Name        string
	Relations   map[string]*Relation
	Permissions map[string]*Permission
	Order       []string // relation and permission names in source order
}

// Relation is a relation that relationships can be written to.
type Relation struct {
	Name    string
	Allowed []SubjectType
}

// SubjectType is one allowed subject for a relation, e.g. "user",
// "user:*" or "group#member".
type SubjectType struct {
	Type     string
	Relation string // set for usersets such as group#member
	Wildcard bool   // set for "user:*"
}

func (t SubjectType) String() string {
	switch {
	case t.Wildcard:
		return t.Type + ":*"
	case t.Relation != "":
		return t.Type + "#" + t.Relation
	default:
		return t.Type
	}
}

// Permission is a name computed from an expression; it cannot be written to.
type Permission struct {
	Name string
	Expr Expr
}

// Expr is a permission expression node.
type Expr interface {
	fmt.Stringer
	isExpr()
}

// Ref refers to a relation or permission on the same object.
type Ref struct{ Name string }

// Arrow follows the objects stored in relation Tupleset and evaluates
// Computed on each of them ("parent->view").
type Arrow struct{ Tupleset, Computed string }

// Union is true when either side is true.
type Union struct{ L, R Expr }

// Intersection is true when both sides are true.
type Intersection struct{ L, R Expr }

// Exclusion is true when L is true and R is false.
type Exclusion struct{ L, R Expr }

func (*Ref) isExpr()          {}
func (*Arrow) isExpr()        {}
func (*Union) isExpr()        {}
func (*Intersection) isExpr() {}
func (*Exclusion) isExpr()    {}

func (e *Ref) String() string          { return e.Name }
func (e *Arrow) String() string        { return e.Tupleset + "->" + e.Computed }
func (e *Union) String() string        { return "(" + e.L.String() + " + " + e.R.String() + ")" }
func (e *Intersection) String() string { return "(" + e.L.String() + " & " + e.R.String() + ")" }
func (e *Exclusion) String() string    { return "(" + e.L.String() + " - " + e.R.String() + ")" }

// IsRelation reports whether name is a writable relation on the definition.
func (d *Definition) IsRelation(name string) bool { _, ok := d.Relations[name]; return ok }

// IsPermission reports whether name is a computed permission on the definition.
func (d *Definition) IsPermission(name string) bool { _, ok := d.Permissions[name]; return ok }

// Has reports whether name is a relation or permission on the definition.
func (d *Definition) Has(name string) bool { return d.IsRelation(name) || d.IsPermission(name) }

// Allows reports whether a relationship with the given subject may be stored
// in relation rel. subjectID "*" is a wildcard.
func (r *Relation) Allows(subjectType, subjectID, subjectRelation string) bool {
	for _, a := range r.Allowed {
		if a.Type != subjectType {
			continue
		}
		if subjectID == "*" {
			if a.Wildcard && subjectRelation == "" {
				return true
			}
			continue
		}
		if !a.Wildcard && a.Relation == subjectRelation {
			return true
		}
	}
	return false
}

// String renders the schema in canonical form. Parsing the output yields an
// equivalent schema.
func (s *Schema) String() string {
	var b strings.Builder
	for i, name := range s.Order {
		if i > 0 {
			b.WriteString("\n")
		}
		d := s.Defs[name]
		if len(d.Order) == 0 {
			fmt.Fprintf(&b, "definition %s {}\n", d.Name)
			continue
		}
		fmt.Fprintf(&b, "definition %s {\n", d.Name)
		for _, n := range d.Order {
			if r, ok := d.Relations[n]; ok {
				parts := make([]string, len(r.Allowed))
				for j, a := range r.Allowed {
					parts[j] = a.String()
				}
				fmt.Fprintf(&b, "  relation %s: %s\n", r.Name, strings.Join(parts, " | "))
				continue
			}
			p := d.Permissions[n]
			fmt.Fprintf(&b, "  permission %s = %s\n", p.Name, trimParens(p.Expr.String()))
		}
		b.WriteString("}\n")
	}
	return b.String()
}

func trimParens(s string) string {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return s
	}
	depth := 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(s)-1 {
				return s // outer parens do not wrap the whole expression
			}
		}
	}
	return s[1 : len(s)-1]
}
