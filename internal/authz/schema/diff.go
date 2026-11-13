package schema

import (
	"sort"
	"strings"
)

// ChangeKind says how a definition, relation or permission differs between
// two schemas.
type ChangeKind string

// The kinds of change Compare reports.
const (
	Added   ChangeKind = "added"
	Removed ChangeKind = "removed"
	Changed ChangeKind = "changed"
)

// Change is one difference between two schemas.
type Change struct {
	Kind ChangeKind `json:"kind"`
	// Object is "definition", "relation" or "permission": what the name is
	// in the new schema, or in the old one for a removal.
	Object string `json:"object"`
	// Name is "doc" for a definition and "doc#viewer" for a relation or
	// permission.
	Name string `json:"name"`
	// Detail shows a change as "before -> after": the allowed subjects of a
	// relation, the expression of a permission, or "relation -> permission"
	// when a name changes what it is.
	Detail string `json:"detail,omitempty"`
}

// Diff is the difference between two schemas.
type Diff struct {
	// Changes lists every difference: definitions, then their relations and
	// permissions in the new schema's order, then what the old schema had
	// and the new one drops.
	Changes []Change `json:"changes"`
	// Affected lists the permissions present in both schemas whose answer
	// can differ under the new one: those whose expression changed and every
	// permission that reaches a changed relation or permission, on its own
	// object, across an arrow or through a userset such as group#member.
	// The list is conservative: a relation that only gains a subject type
	// counts as changed, though no stored relationship uses that type yet.
	// They are in the new schema's order, as "doc#view".
	Affected []string `json:"affected_permissions"`
}

// Compare reports how next differs from prev. A nil prev is the empty
// schema: everything in next is added and nothing is affected.
func Compare(prev, next *Schema) Diff {
	if prev == nil {
		prev = &Schema{Defs: map[string]*Definition{}}
	}
	d := Diff{Changes: []Change{}, Affected: []string{}}
	changed := map[string]bool{} // names in next whose meaning changed
	for _, dn := range next.Order {
		nd := next.Defs[dn]
		od, ok := prev.Defs[dn]
		if !ok {
			d.Changes = append(d.Changes, Change{Kind: Added, Object: "definition", Name: dn})
			continue
		}
		for _, n := range nd.Order {
			name := dn + "#" + n
			switch {
			case !od.Has(n):
				d.Changes = append(d.Changes, Change{Kind: Added, Object: nd.kind(n), Name: name})
			case od.kind(n) != nd.kind(n):
				d.Changes = append(d.Changes, Change{Kind: Changed, Object: nd.kind(n), Name: name, Detail: od.kind(n) + " -> " + nd.kind(n)})
				changed[name] = true
			case od.render(n) != nd.render(n):
				d.Changes = append(d.Changes, Change{Kind: Changed, Object: nd.kind(n), Name: name, Detail: od.render(n) + " -> " + nd.render(n)})
				changed[name] = true
			}
		}
		for _, n := range od.Order {
			if !nd.Has(n) {
				d.Changes = append(d.Changes, Change{Kind: Removed, Object: od.kind(n), Name: dn + "#" + n})
			}
		}
	}
	for _, dn := range prev.Order {
		if _, ok := next.Defs[dn]; !ok {
			d.Changes = append(d.Changes, Change{Kind: Removed, Object: "definition", Name: dn})
		}
	}

	// Walk dependencies backwards from what changed. A removed name needs
	// no seed: next validates, so whatever used it was rewritten and is
	// changed itself.
	users := next.dependents()
	reached := map[string]bool{}
	queue := make([]string, 0, len(changed))
	for n := range changed {
		reached[n] = true
		queue = append(queue, n)
	}
	sort.Strings(queue) // a fixed walk order; the result is sorted below anyway
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, u := range users[n] {
			if !reached[u] {
				reached[u] = true
				queue = append(queue, u)
			}
		}
	}
	for _, dn := range next.Order {
		nd := next.Defs[dn]
		od := prev.Defs[dn]
		for _, n := range nd.Order {
			if reached[dn+"#"+n] && nd.IsPermission(n) && od != nil && od.IsPermission(n) {
				d.Affected = append(d.Affected, dn+"#"+n)
			}
		}
	}
	return d
}

// kind names what n is on the definition.
func (d *Definition) kind(n string) string {
	if d.IsRelation(n) {
		return "relation"
	}
	return "permission"
}

// render is n's right-hand side as the canonical form prints it.
func (d *Definition) render(n string) string {
	if r, ok := d.Relations[n]; ok {
		parts := make([]string, len(r.Allowed))
		for i, a := range r.Allowed {
			parts[i] = a.String()
		}
		sort.Strings(parts) // the order of allowed subjects means nothing
		return strings.Join(parts, " | ")
	}
	return trimParens(d.Permissions[n].Expr.String())
}

// dependents maps each "type#name" to the relations and permissions whose
// answer reads it.
func (s *Schema) dependents() map[string][]string {
	users := map[string][]string{}
	add := func(dep, user string) { users[dep] = append(users[dep], user) }
	for _, dn := range s.Order {
		d := s.Defs[dn]
		for _, n := range d.Order {
			user := dn + "#" + n
			if r, ok := d.Relations[n]; ok {
				for _, a := range r.Allowed {
					if a.Relation != "" {
						add(a.Type+"#"+a.Relation, user)
					}
				}
				continue
			}
			var walk func(Expr)
			walk = func(e Expr) {
				switch e := e.(type) {
				case *Ref:
					add(dn+"#"+e.Name, user)
				case *Arrow:
					add(dn+"#"+e.Tupleset, user)
					for _, a := range d.Relations[e.Tupleset].Allowed {
						add(a.Type+"#"+e.Computed, user)
					}
				case *Union:
					walk(e.L)
					walk(e.R)
				case *Intersection:
					walk(e.L)
					walk(e.R)
				case *Exclusion:
					walk(e.L)
					walk(e.R)
				}
			}
			walk(d.Permissions[n].Expr)
		}
	}
	return users
}
