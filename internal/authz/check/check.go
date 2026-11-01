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

// Reader is the part of the store the engine needs.
type Reader interface {
	ReadDirect(rev store.Revision, resourceType, resourceID, relation string) ([]store.Relationship, error)
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
}

// Check reports whether the subject has the permission at revision rev.
// sc must be the schema the request was validated against. Check records no
// trace; Explain answers the same question with one.
func (e *Engine) Check(ctx context.Context, sc *schema.Schema, rev store.Revision, q Request) (bool, Stats, error) {
	if err := q.Validate(sc); err != nil {
		return false, Stats{}, err
	}
	st := &state{e: e, ctx: ctx, sc: sc, rev: rev, target: q.Subject,
		memo: map[string]bool{}, active: map[string]bool{}}
	ok, _, err := st.check(q.ResourceType, q.ResourceID, q.Permission, 0)
	return ok, st.stats, err
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
type state struct {
	e      *Engine
	ctx    context.Context
	sc     *schema.Schema
	rev    store.Revision
	target store.Subject
	memo   map[string]bool
	active map[string]bool
	stats  Stats
	tr     *tracer // nil unless explaining
}

func (s *state) key(typ, id, rel string) string { return typ + ":" + id + "#" + rel }

func (s *state) cacheKey(k string) string {
	return strconv.FormatUint(uint64(s.rev), 10) + "|" + k + "|" + s.target.String()
}

// check evaluates typ:id#rel. tainted reports that the result depended on a
// cycle cut.
func (s *state) check(typ, id, rel string, depth int) (ok, tainted bool, err error) {
	if err := s.ctx.Err(); err != nil {
		return false, false, err
	}
	if depth > s.e.maxDepth {
		return false, false, ErrDepthExceeded
	}
	// A userset always contains itself: group:eng#member "is" group:eng#member.
	if typ == s.target.Type && id == s.target.ID && rel == s.target.Relation {
		if s.tr != nil {
			s.tr.leaf(TraceNode{Kind: KindSelf, Object: typ + ":" + id, Relation: rel, Result: true})
		}
		return true, false, nil
	}
	k := s.key(typ, id, rel)
	if v, hit := s.memo[k]; hit {
		if s.tr != nil {
			s.tr.leaf(TraceNode{Kind: s.traceKind(typ, rel), Object: typ + ":" + id, Relation: rel, Result: v, Memo: true})
		}
		return v, false, nil
	}
	if s.active[k] {
		if s.tr != nil {
			s.tr.leaf(TraceNode{Kind: s.traceKind(typ, rel), Object: typ + ":" + id, Relation: rel, Cut: true, Tainted: true})
		}
		return false, true, nil
	}
	if s.e.cache != nil && s.tr == nil {
		if v, hit := s.e.cache.Get(s.cacheKey(k)); hit {
			s.stats.CacheHits++
			s.memo[k] = v
			return v, false, nil
		}
	}
	s.stats.Dispatches++
	if s.stats.Dispatches > MaxDispatchesPerCheck {
		return false, false, ErrTooMuchWork
	}
	d, found := s.sc.Defs[typ]
	if !found {
		return false, false, fmt.Errorf("%w %q", ErrUnknownType, typ)
	}
	s.active[k] = true
	var node, parent *TraceNode
	if s.tr != nil {
		node, parent = s.tr.open(TraceNode{Kind: s.traceKind(typ, rel), Object: typ + ":" + id, Relation: rel})
	}
	switch {
	case d.IsRelation(rel):
		ok, tainted, err = s.direct(typ, id, rel, depth)
	case d.IsPermission(rel):
		ok, tainted, err = s.expr(typ, id, d.Permissions[rel].Expr, depth)
	default:
		err = fmt.Errorf("%w: %q has no relation or permission %q", ErrUnknownName, typ, rel)
	}
	delete(s.active, k)
	if s.tr != nil {
		s.tr.close(node, parent, ok, tainted)
	}
	if err != nil {
		return false, false, err
	}
	if !tainted {
		s.memo[k] = ok
		if s.e.cache != nil {
			s.e.cache.Put(s.cacheKey(k), ok)
		}
	}
	return ok, tainted, nil
}

// direct evaluates a stored relation: a matching subject, a matching
// wildcard, or membership in a stored userset.
func (s *state) direct(typ, id, rel string, depth int) (bool, bool, error) {
	rels, err := s.e.r.ReadDirect(s.rev, typ, id, rel)
	if err != nil {
		return false, false, err
	}
	tainted := false
	for _, r := range rels {
		if r.SubjectType != s.target.Type {
			if r.SubjectRelation == "" {
				continue
			}
		} else {
			if (r.SubjectID == "*" && s.target.Relation == "") ||
				(r.SubjectID == s.target.ID && r.SubjectRelation == s.target.Relation) {
				if s.tr != nil {
					s.tr.leaf(TraceNode{Kind: KindSubject, Object: typ + ":" + id, Relation: rel, Subject: subjectString(r), Result: true})
				}
				return true, false, nil
			}
		}
		if r.SubjectRelation == "" {
			continue
		}
		if d, known := s.sc.Defs[r.SubjectType]; !known || !d.Has(r.SubjectRelation) {
			// Only possible when reading an old snapshot after a schema change
			// removed the type or relation: it grants nothing under the current schema.
			continue
		}
		ok, t, err := s.check(r.SubjectType, r.SubjectID, r.SubjectRelation, depth+1)
		if err != nil {
			return false, false, err
		}
		if ok {
			return true, t, nil
		}
		tainted = tainted || t
	}
	return false, tainted, nil
}

func (s *state) expr(typ, id string, e schema.Expr, depth int) (bool, bool, error) {
	if s.tr != nil {
		return s.traceExpr(typ, id, e, depth)
	}
	return s.evalExpr(typ, id, e, depth)
}

func (s *state) evalExpr(typ, id string, e schema.Expr, depth int) (bool, bool, error) {
	switch e := e.(type) {
	case *schema.Ref:
		return s.check(typ, id, e.Name, depth)
	case *schema.Arrow:
		rels, err := s.e.r.ReadDirect(s.rev, typ, id, e.Tupleset)
		if err != nil {
			return false, false, err
		}
		tainted := false
		for _, r := range rels {
			if d, ok := s.sc.Defs[r.SubjectType]; !ok || !d.Has(e.Computed) || r.SubjectID == "*" {
				continue // schema validation prevents this; stay safe if data predates a schema change
			}
			ok, t, err := s.check(r.SubjectType, r.SubjectID, e.Computed, depth+1)
			if err != nil {
				return false, false, err
			}
			if ok {
				return true, t, nil
			}
			tainted = tainted || t
		}
		return false, tainted, nil
	case *schema.Union:
		l, lt, err := s.expr(typ, id, e.L, depth)
		if err != nil || l {
			return l, lt, err
		}
		r, rt, err := s.expr(typ, id, e.R, depth)
		if err != nil {
			return false, false, err
		}
		return r, lt || rt, nil
	case *schema.Intersection:
		l, lt, err := s.expr(typ, id, e.L, depth)
		if err != nil || !l {
			return false, lt, err
		}
		r, rt, err := s.expr(typ, id, e.R, depth)
		return r, lt || rt, err
	case *schema.Exclusion:
		l, lt, err := s.expr(typ, id, e.L, depth)
		if err != nil || !l {
			return false, lt, err
		}
		r, rt, err := s.expr(typ, id, e.R, depth)
		if err != nil {
			return false, false, err
		}
		return !r, lt || rt, nil
	}
	return false, false, fmt.Errorf("unsupported expression %T", e)
}
