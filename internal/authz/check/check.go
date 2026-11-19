// Package check answers "does subject S have permission P on object O at
// revision R?" by walking the schema's rewrite rules over stored
// relationships.
package check

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// DefaultMaxDepth bounds how many hops (group in group, folder in folder) a
// single check may follow.
const DefaultMaxDepth = 50

// MaxDispatchesPerCheck bounds the total work of one check, so a single
// request cannot pin a CPU on a pathological graph.
const MaxDispatchesPerCheck = 100_000

// Errors returned by the engine.
var (
	ErrDepthExceeded = errors.New("check exceeded the maximum depth")
	ErrTooMuchWork   = errors.New("check exceeded the maximum amount of work")
	ErrUnknownType   = errors.New("unknown type")
	ErrUnknownName   = errors.New("unknown relation or permission")
)

// Reader is the part of the store the engine needs. ReadDirect returns the
// relationships without a caveat, which is all of them when the schema
// declares no caveats, and Expand and LookupSubjects then read through it;
// ReadDirectCaveated returns every relationship with its caveat.
type Reader interface {
	ReadDirect(rev store.Revision, resourceType, resourceID, relation string) ([]store.Relationship, error)
	ReadDirectCaveated(rev store.Revision, resourceType, resourceID, relation string) ([]store.Caveated, error)
}

// Engine evaluates checks. It is safe for concurrent use.
type Engine struct {
	r        Reader
	cache    *Cache // may be nil
	maxDepth int
}

// New returns an engine. cache may be nil to disable cross-request caching.
func New(r Reader, cache *Cache) *Engine {
	return &Engine{r: r, cache: cache, maxDepth: DefaultMaxDepth}
}

// Request is one permission check.
type Request struct {
	ResourceType string
	ResourceID   string
	Permission   string // relation or permission name
	Subject      store.Subject
}

// Validate checks the request against the schema.
func (q Request) Validate(sc *schema.Schema) error {
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
	if err := q.Subject.Validate(); err != nil {
		return err
	}
	sd, ok := sc.Defs[q.Subject.Type]
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownType, q.Subject.Type)
	}
	if q.Subject.Relation != "" && !sd.Has(q.Subject.Relation) {
		return fmt.Errorf("%w: %q has no relation or permission %q", ErrUnknownName, q.Subject.Type, q.Subject.Relation)
	}
	return nil
}

// Stats describes the work one check did.
type Stats struct {
	Dispatches int // object#relation evaluations
	CacheHits  int
	Caveats    int // caveat evaluations
	CaveatCost int // their total CEL cost
}

// Check reports whether the subject has the permission at revision rev.
// sc must be the schema the request was validated against. Check records no
// trace; Explain answers the same question with one. A conditional answer
// is false: CheckResult tells it apart from a denial.
func (e *Engine) Check(ctx context.Context, sc *schema.Schema, rev store.Revision, q Request) (bool, Stats, error) {
	r, st, err := e.CheckResult(ctx, sc, rev, q, nil)
	return r.Allowed(), st, err
}

// CheckResult is Check with a caveat context and a three-valued answer:
// allowed, denied, or conditional on caveat parameters that neither
// caveatCtx nor the stored contexts supply, with their names. caveatCtx
// holds values for caveat parameters, merged under the context stored with
// each caveated relationship (stored values win); a parameter neither
// supplies makes the answer conditional when the answer depends on it.
func (e *Engine) CheckResult(ctx context.Context, sc *schema.Schema, rev store.Revision, q Request, caveatCtx map[string]any) (Result, Stats, error) {
	if err := q.Validate(sc); err != nil {
		return denied, Stats{}, err
	}
	rc, err := newRequestContext(caveatCtx)
	if err != nil {
		return denied, Stats{}, err
	}
	return e.checkValid(ctx, sc, rev, q, rc)
}

// checkValid is CheckResult for a validated request and context.
func (e *Engine) checkValid(ctx context.Context, sc *schema.Schema, rev store.Revision, q Request, rc requestContext) (Result, Stats, error) {
	// On the stack: one check allocates only its maps.
	st := state{e: e, ctx: ctx, sc: sc, rev: rev, target: q.Subject, reqCtx: rc,
		memo: map[string]uint8{}, active: map[string]bool{}}
	r, _, err := st.check(q.ResourceType, q.ResourceID, q.Permission, 0)
	if err != nil {
		return denied, st.stats, err
	}
	return r, st.stats, nil
}

func (e *Engine) initState(st *state, ctx context.Context, sc *schema.Schema, rev store.Revision, q Request, caveatCtx map[string]any, tr *tracer) error {
	if err := q.Validate(sc); err != nil {
		return err
	}
	rc, err := newRequestContext(caveatCtx)
	if err != nil {
		return err
	}
	*st = state{e: e, ctx: ctx, sc: sc, rev: rev, target: q.Subject, reqCtx: rc,
		memo: map[string]uint8{}, active: map[string]bool{}, tr: tr}
	return nil
}

// state is the per-request evaluation context.
//
// Cycles in the data (group A contains B contains A) are handled by treating a
// node that is already being evaluated as "not reached through this path".
// Results that depended on such a cut (directly, or through an exclusion that
// read one) are marked tainted and are not cached,
// because they can differ depending on where the walk entered the cycle. The
// answer for the root is still correct: membership is the least fixpoint, and
// any real path to the subject avoids repeating a node.
//
// Caveats make a result depend on the check's context. A result whose
// evaluation evaluated no caveat, directly or through a reused result,
// cannot depend on it: the same walk happens whatever the context is. Such
// results are cached under a key without the context, so checks with
// different contexts share them; the others are cached under a key that
// includes a hash of the context.
type state struct {
	e      *Engine
	ctx    context.Context
	sc     *schema.Schema
	rev    store.Revision
	target store.Subject
	reqCtx requestContext
	// memo holds the results kept for the rest of the request, packed
	// (see remember) so a check without caveats keeps one byte per node;
	// missing holds the parameter names of the conditional ones.
	memo    map[string]uint8
	missing map[string][]string
	active  map[string]bool
	stats   Stats
	// caveats counts caveat evaluations and reuses of results that
	// depended on one, so a node knows whether its result did.
	caveats int
	tr      *tracer // nil unless explaining
}

// memoEntry is a result kept for the rest of the request; dep reports that
// it depended on the context.
type memoEntry struct {
	r   Result
	dep bool
}

const memoDep = 1 << 7 // in a packed memo value: the result depended on the context

func (s *state) remember(k string, m memoEntry) {
	v := uint8(m.r.Permissionship)
	if m.dep {
		v |= memoDep
	}
	s.memo[k] = v
	if m.r.Permissionship == Conditional {
		if s.missing == nil {
			s.missing = map[string][]string{}
		}
		s.missing[k] = m.r.Missing
	}
}

func (s *state) recall(k string) (memoEntry, bool) {
	v, ok := s.memo[k]
	if !ok {
		return memoEntry{}, false
	}
	m := memoEntry{r: Result{Permissionship: Permissionship(v &^ memoDep)}, dep: v&memoDep != 0}
	if m.r.Permissionship == Conditional {
		m.r.Missing = s.missing[k]
	}
	return m, true
}

func (s *state) key(typ, id, rel string) string { return typ + ":" + id + "#" + rel }

// cacheKey is the shared cache's key for k at this revision and subject,
// without the context.
func (s *state) cacheKey(k string) string {
	return strconv.FormatUint(uint64(s.rev), 10) + "|" + k + "|" + s.target.String()
}

// contextKey is cacheKey with the context's hash, for results that
// depended on it.
func (s *state) contextKey(k string) string { return s.cacheKey(k) + "|" + s.reqCtx.hash }

// cached looks k up in the shared cache: first without the context, then,
// when the schema has caveats, with it.
func (s *state) cached(k string) (memoEntry, bool) {
	if r, hit := s.e.cache.get(s.cacheKey(k)); hit {
		return memoEntry{r: r}, true
	}
	if len(s.sc.Caveats) > 0 {
		if r, hit := s.e.cache.get(s.contextKey(k)); hit {
			return memoEntry{r: r, dep: true}, true
		}
	}
	return memoEntry{}, false
}

// check evaluates typ:id#rel. tainted reports that the result depended on a
// cycle cut.
func (s *state) check(typ, id, rel string, depth int) (res Result, tainted bool, err error) {
	if err := s.ctx.Err(); err != nil {
		return denied, false, err
	}
	if depth > s.e.maxDepth {
		return denied, false, ErrDepthExceeded
	}
	// A userset always contains itself: group:eng#member "is" group:eng#member.
	if typ == s.target.Type && id == s.target.ID && rel == s.target.Relation {
		if s.tr != nil {
			s.tr.leafResult(TraceNode{Kind: KindSelf, Object: typ + ":" + id, Relation: rel}, allowed, false)
		}
		return allowed, false, nil
	}
	k := s.key(typ, id, rel)
	if m, hit := s.recall(k); hit {
		if m.dep {
			s.caveats++
		}
		if s.tr != nil {
			s.tr.leafResult(TraceNode{Kind: s.traceKind(typ, rel), Object: typ + ":" + id, Relation: rel, Memo: true}, m.r, false)
		}
		return m.r, false, nil
	}
	if s.active[k] {
		if s.tr != nil {
			s.tr.leafResult(TraceNode{Kind: s.traceKind(typ, rel), Object: typ + ":" + id, Relation: rel, Cut: true}, denied, true)
		}
		return denied, true, nil
	}
	if s.e.cache != nil && s.tr == nil {
		if m, hit := s.cached(k); hit {
			s.stats.CacheHits++
			if m.dep {
				s.caveats++
			}
			s.remember(k, m)
			return m.r, false, nil
		}
	}
	s.stats.Dispatches++
	if s.stats.Dispatches > MaxDispatchesPerCheck {
		return denied, false, ErrTooMuchWork
	}
	d, found := s.sc.Defs[typ]
	if !found {
		return denied, false, fmt.Errorf("%w %q", ErrUnknownType, typ)
	}
	s.active[k] = true
	var node, parent *TraceNode
	if s.tr != nil {
		node, parent = s.tr.open(TraceNode{Kind: s.traceKind(typ, rel), Object: typ + ":" + id, Relation: rel})
	}
	before := s.caveats
	switch {
	case d.IsRelation(rel):
		res, tainted, err = s.direct(typ, id, d.Relations[rel], depth)
	case d.IsPermission(rel):
		res, tainted, err = s.expr(typ, id, d.Permissions[rel].Expr, depth)
	default:
		err = fmt.Errorf("%w: %q has no relation or permission %q", ErrUnknownName, typ, rel)
	}
	delete(s.active, k)
	if s.tr != nil {
		s.tr.close(node, parent, res, tainted)
	}
	if err != nil {
		return denied, false, err
	}
	if !tainted {
		dep := s.caveats > before
		s.remember(k, memoEntry{r: res, dep: dep})
		if s.e.cache != nil {
			if dep {
				s.e.cache.put(s.contextKey(k), res)
			} else {
				s.e.cache.put(s.cacheKey(k), res)
			}
		}
	}
	return res, tainted, nil
}

// direct evaluates a stored relation: a matching subject, a matching
// wildcard, or membership in a stored userset, each only where the
// relationship's caveat, if it has one, holds.
func (s *state) direct(typ, id string, rel *schema.Relation, depth int) (Result, bool, error) {
	rels, err := s.e.r.ReadDirectCaveated(s.rev, typ, id, rel.Name)
	if err != nil {
		return denied, false, err
	}
	acc, tainted := denied, false
	for _, r := range rels {
		match := false
		if r.SubjectType != s.target.Type {
			if r.SubjectRelation == "" {
				continue
			}
		} else {
			match = (r.SubjectID == "*" && s.target.Relation == "") ||
				(r.SubjectID == s.target.ID && r.SubjectRelation == s.target.Relation)
		}
		if !match {
			if r.SubjectRelation == "" {
				continue
			}
			if d, known := s.sc.Defs[r.SubjectType]; !known || !d.Has(r.SubjectRelation) {
				// Only possible when reading an old snapshot after a schema change
				// removed the type or relation: it grants nothing under the current schema.
				continue
			}
		}
		c, err := s.caveat(rel, r)
		if err != nil {
			return denied, false, err
		}
		if c.Permissionship == Denied {
			if s.tr != nil && r.Caveat != nil {
				s.tr.leafResult(TraceNode{Kind: KindSubject, Object: typ + ":" + id, Relation: rel.Name, Subject: subjectString(r.Relationship), Caveat: r.Caveat.Name}, denied, false)
			}
			continue
		}
		if match {
			if s.tr != nil {
				s.tr.leafResult(TraceNode{Kind: KindSubject, Object: typ + ":" + id, Relation: rel.Name, Subject: subjectString(r.Relationship), Caveat: caveatName(r)}, c, false)
			}
			if acc = or(acc, c); acc.Permissionship == Allowed {
				return acc, false, nil
			}
			continue
		}
		m, t, err := s.check(r.SubjectType, r.SubjectID, r.SubjectRelation, depth+1)
		if err != nil {
			return denied, false, err
		}
		tainted = tainted || t
		if acc = or(acc, and(c, m)); acc.Permissionship == Allowed {
			return acc, t, nil
		}
	}
	return acc, tainted, nil
}

func caveatName(r store.Caveated) string {
	if r.Caveat == nil {
		return ""
	}
	return r.Caveat.Name
}

func (s *state) expr(typ, id string, e schema.Expr, depth int) (Result, bool, error) {
	if s.tr != nil {
		return s.traceExpr(typ, id, e, depth)
	}
	return s.evalExpr(typ, id, e, depth)
}

func (s *state) evalExpr(typ, id string, e schema.Expr, depth int) (Result, bool, error) {
	switch e := e.(type) {
	case *schema.Ref:
		return s.check(typ, id, e.Name, depth)
	case *schema.Arrow:
		rels, err := s.e.r.ReadDirectCaveated(s.rev, typ, id, e.Tupleset)
		if err != nil {
			return denied, false, err
		}
		var ts *schema.Relation
		if d, ok := s.sc.Defs[typ]; ok {
			ts = d.Relations[e.Tupleset]
		}
		acc, tainted := denied, false
		for _, r := range rels {
			if d, ok := s.sc.Defs[r.SubjectType]; !ok || !d.Has(e.Computed) || r.SubjectID == "*" {
				continue // schema validation prevents this; stay safe if data predates a schema change
			}
			c, err := s.caveat(ts, r)
			if err != nil {
				return denied, false, err
			}
			if c.Permissionship == Denied {
				continue
			}
			m, t, err := s.check(r.SubjectType, r.SubjectID, e.Computed, depth+1)
			if err != nil {
				return denied, false, err
			}
			tainted = tainted || t
			if acc = or(acc, and(c, m)); acc.Permissionship == Allowed {
				return acc, t, nil
			}
		}
		return acc, tainted, nil
	case *schema.Union:
		l, lt, err := s.expr(typ, id, e.L, depth)
		if err != nil || l.Permissionship == Allowed {
			return l, lt, err
		}
		r, rt, err := s.expr(typ, id, e.R, depth)
		if err != nil {
			return denied, false, err
		}
		return or(l, r), lt || rt, nil
	case *schema.Intersection:
		l, lt, err := s.expr(typ, id, e.L, depth)
		if err != nil || l.Permissionship == Denied {
			return denied, lt, err
		}
		r, rt, err := s.expr(typ, id, e.R, depth)
		if err != nil {
			return denied, false, err
		}
		return and(l, r), lt || rt, nil
	case *schema.Exclusion:
		l, lt, err := s.expr(typ, id, e.L, depth)
		if err != nil || l.Permissionship == Denied {
			return denied, lt, err
		}
		r, rt, err := s.expr(typ, id, e.R, depth)
		if err != nil {
			return denied, false, err
		}
		return and(l, not(r)), lt || rt, nil
	}
	return denied, false, fmt.Errorf("unsupported expression %T", e)
}
