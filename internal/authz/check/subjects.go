package check

import (
	"context"
	"fmt"
	"sort"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// Wildcard is the ID of the subject that stands for every object of a type.
const Wildcard = "*"

// LookupSubjectsRequest asks which subjects of SubjectType (with
// SubjectRelation, for usersets such as group#member) hold Permission on
// ResourceType:ResourceID.
type LookupSubjectsRequest struct {
	ResourceType    string
	ResourceID      string
	Permission      string // relation or permission name
	SubjectType     string
	SubjectRelation string // "" for plain subjects
	// After is the last subject ID of the previous page ("" to start).
	// The wildcard sorts before every ID.
	After string
	// Limit is the page size: DefaultLookupLimit when <= 0, never more
	// than MaxLookupLimit.
	Limit int
}

// Validate checks the request against the schema.
func (q LookupSubjectsRequest) Validate(sc *schema.Schema) error {
	if sc == nil {
		return store.ErrNoSchema
	}
	d, ok := sc.Defs[q.ResourceType]
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownType, q.ResourceType)
	}
	if !store.ValidID(q.ResourceID) {
		return fmt.Errorf("%w: resource id %q is not valid", store.ErrInvalid, q.ResourceID)
	}
	if !d.Has(q.Permission) {
		return fmt.Errorf("%w: %q has no relation or permission %q", ErrUnknownName, q.ResourceType, q.Permission)
	}
	sd, ok := sc.Defs[q.SubjectType]
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownType, q.SubjectType)
	}
	if q.SubjectRelation != "" && !sd.Has(q.SubjectRelation) {
		return fmt.Errorf("%w: %q has no relation or permission %q", ErrUnknownName, q.SubjectType, q.SubjectRelation)
	}
	if q.After != "" && q.After != Wildcard && !store.ValidID(q.After) {
		return fmt.Errorf("%w: cursor %q is not valid", store.ErrInvalid, q.After)
	}
	return nil
}

// FoundSubject is one subject that holds the permission. ID is Wildcard
// when every object of the subject type holds it except those in Excluded
// (sorted); Excluded is empty for any other ID.
type FoundSubject struct {
	ID       string
	Excluded []string
}

// LookupSubjectsResult is one page of a subject lookup.
type LookupSubjectsResult struct {
	Subjects []FoundSubject
	// Next is the cursor to continue from, or "" when the list is complete.
	Next string
}

// LookupSubjects returns the subjects of the requested type that hold a
// permission at revision rev, in ID order with the wildcard first, after
// the cursor q.After.
//
// It walks the rewrite rules from the resource down to the stored
// relationships and back up as sets of subjects: a relation is the union
// of its stored subjects and of the usersets and arrow targets it names,
// and union, intersection and exclusion combine their operands' sets. A
// set is either a list of IDs or the wildcard minus a list of IDs, so
// "user:* - banned" and "(user:* - banned) & editors" are answered
// exactly. A subject is in the result exactly when Check would grant it
// the permission, including an ID that no relationship names when a
// wildcard grants it.
//
// A cycle in the data (a group inside itself, a folder its own ancestor)
// is solved as a least fixpoint: a node met again on its own path reads
// the previous round's value for it (nothing, in the first round), and
// the walk repeats until no such value changes. Nodes that never met a
// cycle keep their value between rounds. Every node evaluation in every
// round counts against MaxDispatchesPerCheck, so a cycle through the
// subtracted side of an exclusion, which has no least fixpoint, ends in
// ErrTooMuchWork instead of running forever.
//
// Each page walks the whole graph again at the same revision, so pages at
// one revision are consistent with each other; the work per page is that
// of one walk.
func (e *Engine) LookupSubjects(ctx context.Context, sc *schema.Schema, rev store.Revision, q LookupSubjectsRequest) (LookupSubjectsResult, Stats, error) {
	if err := q.Validate(sc); err != nil {
		return LookupSubjectsResult{}, Stats{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLookupLimit
	}
	if limit > MaxLookupLimit {
		limit = MaxLookupLimit
	}
	w := &subjectWalker{e: e, ctx: ctx, sc: sc, rev: rev, typ: q.SubjectType, rel: q.SubjectRelation,
		stable: map[string]subjectSet{}, approx: map[string]subjectSet{}, active: map[string]bool{}}
	var set subjectSet
	for {
		w.round, w.changed = map[string]subjectSet{}, false
		s, tainted, err := w.node(q.ResourceType, q.ResourceID, q.Permission, 0)
		if err != nil {
			return LookupSubjectsResult{}, w.stats, err
		}
		if !tainted || !w.changed {
			set = s
			break
		}
		w.approx = w.round
	}
	return set.page(q.After, limit), w.stats, nil
}

// subjectSet is a set of subject IDs of one type: the IDs in ids or, when
// all is set, every ID except those in ids. The zero value is empty. Sets
// are never changed once built; the operations return new ones.
type subjectSet struct {
	all bool
	ids map[string]struct{}
}

func (s subjectSet) has(id string) bool {
	_, in := s.ids[id]
	return in != s.all
}

func (s subjectSet) equal(t subjectSet) bool {
	if s.all != t.all || len(s.ids) != len(t.ids) {
		return false
	}
	for id := range s.ids {
		if _, ok := t.ids[id]; !ok {
			return false
		}
	}
	return true
}

func setOf(all bool, ids map[string]struct{}) subjectSet {
	if len(ids) == 0 {
		ids = nil
	}
	return subjectSet{all: all, ids: ids}
}

// keep returns the IDs of a for which keepIt is true.
func keep(a map[string]struct{}, keepIt func(string) bool) map[string]struct{} {
	out := make(map[string]struct{}, len(a))
	for id := range a {
		if keepIt(id) {
			out[id] = struct{}{}
		}
	}
	return out
}

func merge(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for id := range a {
		out[id] = struct{}{}
	}
	for id := range b {
		out[id] = struct{}{}
	}
	return out
}

func union(a, b subjectSet) subjectSet {
	switch {
	case len(b.ids) == 0 && !b.all:
		return a
	case len(a.ids) == 0 && !a.all:
		return b
	case a.all && b.all: // everyone but those both exclude
		return setOf(true, keep(a.ids, func(id string) bool { _, in := b.ids[id]; return in }))
	case a.all:
		return setOf(true, keep(a.ids, func(id string) bool { _, in := b.ids[id]; return !in }))
	case b.all:
		return setOf(true, keep(b.ids, func(id string) bool { _, in := a.ids[id]; return !in }))
	}
	return setOf(false, merge(a.ids, b.ids))
}

func intersect(a, b subjectSet) subjectSet {
	switch {
	case a.all && b.all:
		return setOf(true, merge(a.ids, b.ids))
	case a.all:
		return setOf(false, keep(b.ids, a.has))
	}
	return setOf(false, keep(a.ids, b.has))
}

func subtract(a, b subjectSet) subjectSet {
	switch {
	case a.all && b.all: // those b excludes and a does not
		return setOf(false, keep(b.ids, a.has))
	case a.all:
		return setOf(true, merge(a.ids, b.ids))
	}
	return setOf(false, keep(a.ids, func(id string) bool { return !b.has(id) }))
}

// page lists the set in ID order, the wildcard first, after cursor.
func (s subjectSet) page(after string, limit int) LookupSubjectsResult {
	var out LookupSubjectsResult
	if s.all {
		if after == "" {
			ex := make([]string, 0, len(s.ids))
			for id := range s.ids {
				ex = append(ex, id)
			}
			sort.Strings(ex)
			out.Subjects = append(out.Subjects, FoundSubject{ID: Wildcard, Excluded: ex})
		}
		return out
	}
	ids := make([]string, 0, len(s.ids))
	for id := range s.ids {
		if after == "" || after == Wildcard || id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
		out.Next = ids[limit-1]
	}
	for _, id := range ids {
		out.Subjects = append(out.Subjects, FoundSubject{ID: id})
	}
	return out
}

// subjectWalker is the per-request state of LookupSubjects.
type subjectWalker struct {
	e        *Engine
	ctx      context.Context
	sc       *schema.Schema
	rev      store.Revision
	typ, rel string // the subjects looked up
	// stable holds nodes whose value did not depend on a cycle; approx the
	// previous round's values of those that did, and round this round's.
	stable, approx, round map[string]subjectSet
	active                map[string]bool // on the current path
	changed               bool            // a round value differs from approx
	stats                 Stats
}

// node returns the subjects that hold typ:id#rel. tainted reports that the
// value read an approximation of a node on a cycle.
func (w *subjectWalker) node(typ, id, rel string, depth int) (set subjectSet, tainted bool, err error) {
	if err := w.ctx.Err(); err != nil {
		return subjectSet{}, false, err
	}
	if depth > w.e.maxDepth {
		return subjectSet{}, false, ErrDepthExceeded
	}
	k := typ + ":" + id + "#" + rel
	if v, ok := w.stable[k]; ok {
		return v, false, nil
	}
	if v, ok := w.round[k]; ok {
		return v, true, nil
	}
	if w.active[k] {
		return w.approx[k], true, nil
	}
	w.stats.Dispatches++
	if w.stats.Dispatches > MaxDispatchesPerCheck {
		return subjectSet{}, false, ErrTooMuchWork
	}
	w.active[k] = true
	d := w.sc.Defs[typ]
	if d.IsPermission(rel) {
		set, tainted, err = w.expr(typ, id, d.Permissions[rel].Expr, depth)
	} else {
		set, tainted, err = w.direct(typ, id, rel, depth)
	}
	delete(w.active, k)
	if err != nil {
		return subjectSet{}, false, err
	}
	// A userset always holds itself, as in Check.
	if w.rel != "" && typ == w.typ && rel == w.rel && !set.has(id) {
		set = union(set, setOf(false, map[string]struct{}{id: {}}))
	}
	if !tainted {
		w.stable[k] = set
	} else {
		w.round[k] = set
		if !set.equal(w.approx[k]) {
			w.changed = true
		}
	}
	return set, tainted, nil
}

// direct gathers a stored relation's matching subjects and wildcard, and
// the members of every userset it names that the current schema still
// has, exactly as Check follows them.
func (w *subjectWalker) direct(typ, id, rel string, depth int) (subjectSet, bool, error) {
	rels, err := w.e.r.ReadDirect(w.rev, typ, id, rel)
	if err != nil {
		return subjectSet{}, false, err
	}
	var own map[string]struct{}
	all, out, tainted := false, subjectSet{}, false
	for _, r := range rels {
		if r.SubjectRelation == "" {
			if r.SubjectType == w.typ && w.rel == "" {
				if r.SubjectID == Wildcard {
					all = true
				} else {
					if own == nil {
						own = map[string]struct{}{}
					}
					own[r.SubjectID] = struct{}{}
				}
			}
			continue
		}
		if d, known := w.sc.Defs[r.SubjectType]; !known || !d.Has(r.SubjectRelation) {
			continue
		}
		s, t, err := w.node(r.SubjectType, r.SubjectID, r.SubjectRelation, depth+1)
		if err != nil {
			return subjectSet{}, false, err
		}
		out, tainted = union(out, s), tainted || t
	}
	if all { // the wildcard holds everyone the usersets add
		return subjectSet{all: true}, tainted, nil
	}
	return union(out, setOf(false, own)), tainted, nil
}

func (w *subjectWalker) expr(typ, id string, e schema.Expr, depth int) (subjectSet, bool, error) {
	switch e := e.(type) {
	case *schema.Ref:
		return w.node(typ, id, e.Name, depth)
	case *schema.Arrow:
		rels, err := w.e.r.ReadDirect(w.rev, typ, id, e.Tupleset)
		if err != nil {
			return subjectSet{}, false, err
		}
		out, tainted := subjectSet{}, false
		for _, r := range rels {
			if d, ok := w.sc.Defs[r.SubjectType]; !ok || !d.Has(e.Computed) || r.SubjectID == Wildcard {
				continue // as in Check
			}
			s, t, err := w.node(r.SubjectType, r.SubjectID, e.Computed, depth+1)
			if err != nil {
				return subjectSet{}, false, err
			}
			out, tainted = union(out, s), tainted || t
		}
		return out, tainted, nil
	case *schema.Union:
		return w.binary(typ, id, e.L, e.R, depth, union)
	case *schema.Intersection:
		return w.binary(typ, id, e.L, e.R, depth, intersect)
	case *schema.Exclusion:
		return w.binary(typ, id, e.L, e.R, depth, subtract)
	}
	return subjectSet{}, false, fmt.Errorf("unsupported expression %T", e)
}

func (w *subjectWalker) binary(typ, id string, l, r schema.Expr, depth int, op func(a, b subjectSet) subjectSet) (subjectSet, bool, error) {
	a, at, err := w.expr(typ, id, l, depth)
	if err != nil {
		return subjectSet{}, false, err
	}
	b, bt, err := w.expr(typ, id, r, depth)
	if err != nil {
		return subjectSet{}, false, err
	}
	return op(a, b), at || bt, nil
}
