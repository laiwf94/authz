package check

import (
	"context"
	"fmt"
	"slices"
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
	// Context holds caveat parameters, as in CheckResult: merged under
	// each caveated relationship's stored context (stored values win). A
	// subject whose answer depends on a parameter neither supplies is
	// found as conditional.
	Context map[string]any
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

// FoundSubject is one subject that holds the permission, or may.
//
// ID is Wildcard for every object of the subject type except those in
// Excluded (sorted), whose answers differ from the wildcard's: each of
// them is either found as a subject of its own, with its own answer, or
// does not hold the permission. Excluded is empty for any other ID.
//
// Conditional marks a subject that holds the permission only if the
// caveat parameters Missing names (sorted) allow it; other found subjects
// hold it whatever they are.
type FoundSubject struct {
	ID          string
	Excluded    []string
	Conditional bool
	Missing     []string
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
// and union, intersection and exclusion combine their operands' sets.
// A set gives every subject ID an answer, allowed, denied or conditional,
// as Check would: one answer for every ID it does not list (the wildcard's)
// and one for each ID it lists. So "user:* - banned" and
// "(user:* - banned) & editors" are answered exactly, and a subject is
// found exactly when CheckResult with the same context would not deny it,
// including an ID that no relationship names when a wildcard grants it.
//
// A caveated relationship contributes its subjects with its caveat's
// answer: evaluated with its stored context over q.Context, it either
// holds (the relationship counts as if it had no caveat), fails (the
// relationship counts for nothing) or is unknown, and then everything it
// contributes is conditional on the parameters it lacks. The operators
// combine answers subject by subject as CheckResult combines them, so a
// conditional exclusion leaves its subjects conditional, never allowed.
//
// A cycle in the data (a group inside itself, a folder its own ancestor)
// is solved as a least fixpoint: a node met again on its own path reads
// the previous round's value for it (nothing, in the first round), and
// the walk repeats until no such value changes. Nodes that never met a
// cycle keep their value between rounds. Every node evaluation in every
// round counts against MaxDispatchesPerCheck, so a cycle through the
// subtracted side of an exclusion, which has no least fixpoint, ends in
// ErrTooMuchWork instead of running forever. The caveats evaluated share
// MaxCaveatCostPerCheck.
//
// Each page walks the whole graph again at the same revision, so pages at
// one revision are consistent with each other; the work per page is that
// of one walk.
func (e *Engine) LookupSubjects(ctx context.Context, sc *schema.Schema, rev store.Revision, q LookupSubjectsRequest) (LookupSubjectsResult, Stats, error) {
	if err := q.Validate(sc); err != nil {
		return LookupSubjectsResult{}, Stats{}, err
	}
	rc, err := newRequestContext(q.Context)
	if err != nil {
		return LookupSubjectsResult{}, Stats{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLookupLimit
	}
	if limit > MaxLookupLimit {
		limit = MaxLookupLimit
	}
	w := &subjectWalker{e: e, ctx: ctx, sc: sc, rev: rev, typ: q.SubjectType, rel: q.SubjectRelation, reqCtx: rc,
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

// sameResult reports whether two answers are equal, missing names included.
func sameResult(a, b Result) bool {
	return a.Permissionship == b.Permissionship && slices.Equal(a.Missing, b.Missing)
}

// subjectSet gives every subject ID of one type an answer: def for every
// ID it does not list; flip(def) for the IDs in ids; *other[id] for the
// IDs in other. An ID is in at most one of them, and listed answers always
// differ from def, so a set has one form. The zero value denies everyone.
// Sets are never changed once built; the operations return new ones.
//
// A set of definite answers, the common case, has no other: it is the IDs
// in ids, or every ID but those, and is combined as a plain ID set as it
// was before caveats, at the cost of a map key per ID. Conditional answers
// (and, when def is conditional, allowed ones) are in other.
type subjectSet struct {
	def   Result
	ids   map[string]struct{}
	other map[string]*Result
}

var (
	allowedRef = &Result{Permissionship: Allowed}
	deniedRef  = &Result{Permissionship: Denied}
)

// flip is the answer a set gives the IDs in ids: the opposite of a definite
// default, and denied when the default is conditional.
func flip(def Result) Result {
	if def.Permissionship == Denied {
		return allowed
	}
	return denied
}

// definiteSet is every ID but ids when all is set, else the IDs in ids.
func definiteSet(all bool, ids map[string]struct{}) subjectSet {
	if len(ids) == 0 {
		ids = nil
	}
	if all {
		return subjectSet{def: allowed, ids: ids}
	}
	return subjectSet{ids: ids}
}

// cond reports that some answer of the set is conditional.
func (s subjectSet) cond() bool { return s.def.Permissionship == Conditional || len(s.other) > 0 }

func (s subjectSet) get(id string) Result {
	if _, ok := s.ids[id]; ok {
		return flip(s.def)
	}
	if r, ok := s.other[id]; ok {
		return *r
	}
	return s.def
}

func (s subjectSet) allows(id string) bool { return s.get(id).Permissionship == Allowed }

func (s subjectSet) empty() bool {
	return s.def.Permissionship == Denied && len(s.ids) == 0 && len(s.other) == 0
}

func (s subjectSet) equal(t subjectSet) bool {
	if !sameResult(s.def, t.def) || len(s.ids) != len(t.ids) || len(s.other) != len(t.other) {
		return false
	}
	for id := range s.ids {
		if _, ok := t.ids[id]; !ok {
			return false
		}
	}
	for id, r := range s.other {
		if u, ok := t.other[id]; !ok || !sameResult(*r, *u) {
			return false
		}
	}
	return true
}

// with returns s with id answered r, for building sets: r must differ
// from s.def and id must not be listed yet.
func (s *subjectSet) with(id string, r Result, size int) {
	if f := flip(s.def); r.Permissionship == f.Permissionship && f.Permissionship != Conditional {
		if s.ids == nil {
			s.ids = make(map[string]struct{}, size)
		}
		s.ids[id] = struct{}{}
		return
	}
	if s.other == nil {
		s.other = map[string]*Result{}
	}
	switch r.Permissionship {
	case Allowed:
		s.other[id] = allowedRef
	case Denied:
		s.other[id] = deniedRef
	default:
		p := new(Result)
		*p = r
		s.other[id] = p
	}
}

// pointwise combines two sets subject by subject.
func pointwise(a, b subjectSet, op func(x, y Result) Result) subjectSet {
	out := subjectSet{def: op(a.def, b.def)}
	size := len(a.ids) + len(b.ids)
	add := func(id string) {
		if r := op(a.get(id), b.get(id)); !sameResult(r, out.def) {
			out.with(id, r, size)
		}
	}
	listed := func(s subjectSet, id string) bool {
		if _, ok := s.ids[id]; ok {
			return true
		}
		_, ok := s.other[id]
		return ok
	}
	for id := range a.ids {
		add(id)
	}
	for id := range a.other {
		add(id)
	}
	for id := range b.ids {
		if !listed(a, id) {
			add(id)
		}
	}
	for id := range b.other {
		if !listed(a, id) {
			add(id)
		}
	}
	return out
}

func union(a, b subjectSet) subjectSet {
	switch {
	case b.empty():
		return a
	case a.empty():
		return b
	case a.cond() || b.cond():
		return pointwise(a, b, or)
	}
	aAll, bAll := a.def.Allowed(), b.def.Allowed()
	switch {
	case aAll && bAll: // everyone but those both exclude
		return definiteSet(true, keep(a.ids, func(id string) bool { _, in := b.ids[id]; return in }))
	case aAll:
		return definiteSet(true, keep(a.ids, func(id string) bool { _, in := b.ids[id]; return !in }))
	case bAll:
		return definiteSet(true, keep(b.ids, func(id string) bool { _, in := a.ids[id]; return !in }))
	}
	return definiteSet(false, merge(a.ids, b.ids))
}

func intersect(a, b subjectSet) subjectSet {
	switch {
	case a.empty() || b.empty():
		return subjectSet{}
	case a.cond() || b.cond():
		return pointwise(a, b, and)
	}
	aAll, bAll := a.def.Allowed(), b.def.Allowed()
	switch {
	case aAll && bAll:
		return definiteSet(true, merge(a.ids, b.ids))
	case aAll:
		return definiteSet(false, keep(b.ids, a.allows))
	}
	return definiteSet(false, keep(a.ids, b.allows))
}

func andNot(a, b Result) Result { return and(a, not(b)) }

func subtract(a, b subjectSet) subjectSet {
	switch {
	case a.empty() || b.empty():
		return a
	case a.cond() || b.cond():
		return pointwise(a, b, andNot)
	}
	aAll, bAll := a.def.Allowed(), b.def.Allowed()
	switch {
	case aAll && bAll: // those b excludes and a does not
		return definiteSet(false, keep(b.ids, a.allows))
	case aAll:
		return definiteSet(true, merge(a.ids, b.ids))
	}
	return definiteSet(false, keep(a.ids, func(id string) bool { return !b.allows(id) }))
}

// scale is s where c holds: every answer and-ed with c.
func scale(c Result, s subjectSet) subjectSet {
	switch c.Permissionship {
	case Allowed:
		return s
	case Denied:
		return subjectSet{}
	}
	return pointwise(subjectSet{def: c}, s, and)
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

// page lists the subjects the set does not deny in ID order, the wildcard
// first, after cursor.
func (s subjectSet) page(after string, limit int) LookupSubjectsResult {
	var out LookupSubjectsResult
	if s.def.Permissionship != Denied && after == "" {
		ex := make([]string, 0, len(s.ids)+len(s.other))
		for id := range s.ids {
			ex = append(ex, id)
		}
		for id := range s.other {
			ex = append(ex, id)
		}
		sort.Strings(ex)
		out.Subjects = append(out.Subjects, found(Wildcard, s.def, ex))
	}
	ids := make([]string, 0, len(s.ids)+len(s.other))
	keepID := func(id string) bool { return after == "" || after == Wildcard || id > after }
	if s.def.Permissionship == Denied {
		for id := range s.ids {
			if keepID(id) {
				ids = append(ids, id)
			}
		}
	}
	for id, r := range s.other {
		if r.Permissionship != Denied && keepID(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if n := len(out.Subjects) + len(ids); n > limit {
		ids = ids[:limit-len(out.Subjects)]
		if len(ids) > 0 {
			out.Next = ids[len(ids)-1]
		} else {
			out.Next = Wildcard
		}
	}
	for _, id := range ids {
		out.Subjects = append(out.Subjects, found(id, s.get(id), nil))
	}
	return out
}

func found(id string, r Result, excluded []string) FoundSubject {
	f := FoundSubject{ID: id, Excluded: excluded}
	if r.Permissionship == Conditional {
		f.Conditional, f.Missing = true, r.Missing
	}
	return f
}

// subjectWalker is the per-request state of LookupSubjects.
type subjectWalker struct {
	e        *Engine
	ctx      context.Context
	sc       *schema.Schema
	rev      store.Revision
	typ, rel string // the subjects looked up
	reqCtx   requestContext
	// stable holds nodes whose value did not depend on a cycle; approx the
	// previous round's values of those that did, and round this round's.
	stable, approx, round map[string]subjectSet
	active                map[string]bool // on the current path
	changed               bool            // a round value differs from approx
	// caveats holds the answer of each stored caveat evaluated, so a
	// relationship read again in a later fixpoint round is not
	// evaluated (and charged) again. A stored caveat is shared by the
	// store and never changes, so its pointer identifies it.
	caveats map[*store.Caveat]Result
	stats   Stats
}

// caveat is the answer of the caveat r carries, as Check evaluates it.
func (w *subjectWalker) caveat(rel *schema.Relation, r store.Caveated) (Result, error) {
	if r.Caveat == nil {
		return allowed, nil
	}
	if res, ok := w.caveats[r.Caveat]; ok && allowsCaveat(w.sc, rel, r) {
		return res, nil
	}
	res, evaluated, err := evalCaveat(w.sc, w.reqCtx, rel, r, &w.stats)
	if err != nil {
		return denied, err
	}
	if evaluated {
		if w.caveats == nil {
			w.caveats = map[*store.Caveat]Result{}
		}
		w.caveats[r.Caveat] = res
	}
	return res, nil
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
		set, tainted, err = w.direct(typ, id, d.Relations[rel], depth)
	}
	delete(w.active, k)
	if err != nil {
		return subjectSet{}, false, err
	}
	// A userset always holds itself, as in Check.
	if w.rel != "" && typ == w.typ && rel == w.rel && !set.allows(id) {
		set = union(set, definiteSet(false, map[string]struct{}{id: {}}))
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
// has, exactly as Check follows them, each where its relationship's
// caveat holds.
func (w *subjectWalker) direct(typ, id string, rel *schema.Relation, depth int) (subjectSet, bool, error) {
	// own holds the plain subjects granted outright, condOwn those granted
	// on a caveat left open; a subject in both is granted outright.
	var own map[string]struct{}
	var condOwn map[string]Result
	wild, out, tainted := denied, subjectSet{}, false
	err := w.e.eachDirect(w.sc, w.rev, typ, id, rel.Name, func(r store.Caveated) error {
		if r.SubjectRelation == "" {
			if r.SubjectType != w.typ || w.rel != "" {
				return nil
			}
		} else if d, known := w.sc.Defs[r.SubjectType]; !known || !d.Has(r.SubjectRelation) {
			return nil
		}
		c, err := w.caveat(rel, r)
		if err != nil || c.Permissionship == Denied {
			return err
		}
		if r.SubjectRelation == "" {
			switch {
			case r.SubjectID == Wildcard:
				wild = or(wild, c)
			case c.Permissionship == Allowed:
				if own == nil {
					own = map[string]struct{}{}
				}
				own[r.SubjectID] = struct{}{}
			default:
				if condOwn == nil {
					condOwn = map[string]Result{}
				}
				if prev, ok := condOwn[r.SubjectID]; ok {
					c = or(prev, c)
				}
				condOwn[r.SubjectID] = c
			}
			return nil
		}
		s, t, err := w.node(r.SubjectType, r.SubjectID, r.SubjectRelation, depth+1)
		if err != nil {
			return err
		}
		out, tainted = union(out, scale(c, s)), tainted || t
		return nil
	})
	if err != nil {
		return subjectSet{}, false, err
	}
	if wild.Permissionship == Allowed { // the wildcard holds everyone the rest adds
		return subjectSet{def: allowed}, tainted, nil
	}
	if wild.Permissionship == Denied && len(condOwn) == 0 {
		return union(out, definiteSet(false, own)), tainted, nil
	}
	mine := subjectSet{def: wild}
	for sid := range own {
		mine.with(sid, allowed, len(own))
	}
	for sid, c := range condOwn {
		if _, outright := own[sid]; !outright {
			if c = or(wild, c); !sameResult(c, wild) {
				mine.with(sid, c, len(condOwn))
			}
		}
	}
	return union(out, mine), tainted, nil
}

func (w *subjectWalker) expr(typ, id string, e schema.Expr, depth int) (subjectSet, bool, error) {
	switch e := e.(type) {
	case *schema.Ref:
		return w.node(typ, id, e.Name, depth)
	case *schema.Arrow:
		var ts *schema.Relation
		if d, ok := w.sc.Defs[typ]; ok {
			ts = d.Relations[e.Tupleset]
		}
		out, tainted := subjectSet{}, false
		err := w.e.eachDirect(w.sc, w.rev, typ, id, e.Tupleset, func(r store.Caveated) error {
			if d, ok := w.sc.Defs[r.SubjectType]; !ok || !d.Has(e.Computed) || r.SubjectID == Wildcard {
				return nil // as in Check
			}
			c, err := w.caveat(ts, r)
			if err != nil || c.Permissionship == Denied {
				return err
			}
			s, t, err := w.node(r.SubjectType, r.SubjectID, e.Computed, depth+1)
			if err != nil {
				return err
			}
			out, tainted = union(out, scale(c, s)), tainted || t
			return nil
		})
		if err != nil {
			return subjectSet{}, false, err
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
