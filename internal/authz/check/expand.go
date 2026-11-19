package check

import (
	"context"
	"fmt"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// ExpandRequest asks who holds Permission on ResourceType:ResourceID, as a
// userset tree.
type ExpandRequest struct {
	ResourceType string
	ResourceID   string
	Permission   string // relation or permission name
	// Recursive expands every userset the tree reaches (group:eng#member,
	// the computed relation behind an arrow) into its own subtree, so the
	// tree names every subject. Without it the tree stops at the first
	// object: usersets and arrow targets are subject leaves, as in
	// Zanzibar's Expand, and the caller expands them in turn if it wants.
	Recursive bool
	// MaxNodes bounds the tree (DefaultTraceNodes when <= 0, never more
	// than MaxTraceNodes).
	MaxNodes int
}

// Validate checks the request against the schema.
func (q ExpandRequest) Validate(sc *schema.Schema) error {
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
	return nil
}

// Expand returns the userset tree of a permission at revision rev, built
// from the trace node types Explain uses:
//
//   - a relation node (KindRelation) has one KindSubject child per stored
//     relationship: a subject, a wildcard (user:*) or a userset
//     (group:eng#member). With Recursive, a userset is a relation or
//     permission node on the userset's object instead, expanded in turn.
//   - a permission node (KindPermission) has one child: its rewrite. A bare
//     reference is the referenced relation's node on the same object.
//   - union, intersection and exclusion nodes have their two operands as
//     children, left first; Expr is the operator's expression.
//   - an arrow node (KindArrow) has one child per object its tupleset
//     names: a KindSubject leaf "folder:f1#view" or, with Recursive, that
//     object's view node expanded.
//
// A relationship with a caveat holds only where its caveat does, so its
// node (the subject leaf, or with Recursive the userset or arrow target
// it leads to) names the caveat in Caveat and carries the relationship's
// stored context in CaveatContext. Expand does not evaluate caveats: the
// tree shows every relationship that may grant, and CheckResult or
// LookupSubjects with a context answers for one. A relationship whose
// caveat the current schema no longer allows on its relation (only
// possible at a snapshot older than a schema change) grants nothing and
// is left out, as Check leaves it out.
//
// Every object#relation is expanded once per tree. A later occurrence is a
// node with Memo set and no children, and one met again inside its own
// expansion (a cycle in the data) is a node with Cut set. Read the tree as
// a set of equations, one per expanded object#relation: the least
// solution is exactly the set of subjects Check grants.
//
// Result, Tainted and Role are not used. When the tree reaches its node
// limit, expansion stops: the parents of the missing nodes count them in
// Omitted and Trace.Truncated is set. A tree is never larger than its
// limit, and the work behind it is bounded by the limit.
func (e *Engine) Expand(ctx context.Context, sc *schema.Schema, rev store.Revision, q ExpandRequest) (*Trace, Stats, error) {
	if err := q.Validate(sc); err != nil {
		return nil, Stats{}, err
	}
	max := q.MaxNodes
	if max <= 0 {
		max = DefaultTraceNodes
	}
	if max > MaxTraceNodes {
		max = MaxTraceNodes
	}
	x := &expander{e: e, ctx: ctx, sc: sc, rev: rev, recursive: q.Recursive,
		tr: &tracer{max: max}, done: map[string]bool{}, active: map[string]bool{}}
	x.tr.cur = &x.tr.top
	if err := x.node(q.ResourceType, q.ResourceID, q.Permission, nil, 0); err != nil {
		return nil, x.stats, err
	}
	return &Trace{Root: x.tr.top.Children[0], Nodes: x.tr.n, Truncated: x.tr.truncated}, x.stats, nil
}

type expander struct {
	e         *Engine
	ctx       context.Context
	sc        *schema.Schema
	rev       store.Revision
	recursive bool
	tr        *tracer
	done      map[string]bool // expanded (or being expanded) earlier in this tree
	active    map[string]bool // on the current path
	stats     Stats
}

func (x *expander) kind(typ, rel string) TraceKind {
	if x.sc.Defs[typ].IsPermission(rel) {
		return KindPermission
	}
	return KindRelation
}

// node records typ:id#rel, reached through a relationship with caveat c
// (nil for none), and the first time it is met its expansion.
func (x *expander) node(typ, id, rel string, c *store.Caveat, depth int) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	if depth > x.e.maxDepth {
		return ErrDepthExceeded
	}
	n := TraceNode{Kind: x.kind(typ, rel), Object: typ + ":" + id, Relation: rel}
	setCaveat(&n, c)
	k := typ + ":" + id + "#" + rel
	switch {
	case x.active[k]:
		n.Cut = true
		x.tr.leaf(n)
		return nil
	case x.done[k]:
		n.Memo = true
		x.tr.leaf(n)
		return nil
	}
	node, parent := x.tr.open(n)
	if node == nil {
		x.tr.close(nil, parent, denied, false)
		return nil
	}
	// Only a recorded node is expanded, so the node limit (never above
	// MaxDispatchesPerCheck) bounds the work as the dispatch limit bounds
	// a check's.
	x.stats.Dispatches++
	x.done[k], x.active[k] = true, true
	var err error
	d := x.sc.Defs[typ]
	if d.IsPermission(rel) {
		err = x.expr(typ, id, d.Permissions[rel].Expr, depth)
	} else {
		err = x.direct(typ, id, d.Relations[rel], depth)
	}
	delete(x.active, k)
	x.tr.close(node, parent, denied, false)
	return err
}

// setCaveat records the caveat a node was reached through.
func setCaveat(n *TraceNode, c *store.Caveat) {
	if c != nil {
		n.Caveat, n.CaveatContext = c.Name, c.Context
	}
}

// direct lists a stored relation's subjects, skipping those the current
// schema no longer allows (only possible at a snapshot older than a schema
// change), exactly as Check does.
func (x *expander) direct(typ, id string, rel *schema.Relation, depth int) error {
	return x.e.eachDirect(x.sc, x.rev, typ, id, rel.Name, func(r store.Caveated) error {
		if !allowsCaveat(x.sc, rel, r) {
			return nil
		}
		if r.SubjectRelation != "" {
			if d, known := x.sc.Defs[r.SubjectType]; !known || !d.Has(r.SubjectRelation) {
				return nil
			}
			if x.recursive {
				return x.node(r.SubjectType, r.SubjectID, r.SubjectRelation, r.Caveat, depth+1)
			}
		}
		n := TraceNode{Kind: KindSubject, Object: typ + ":" + id, Relation: rel.Name, Subject: subjectString(r.Relationship)}
		setCaveat(&n, r.Caveat)
		x.tr.leaf(n)
		return nil
	})
}

func (x *expander) expr(typ, id string, e schema.Expr, depth int) error {
	var kind TraceKind
	var l, r schema.Expr
	switch e := e.(type) {
	case *schema.Ref:
		return x.node(typ, id, e.Name, nil, depth)
	case *schema.Arrow:
		node, parent := x.tr.open(TraceNode{Kind: KindArrow, Object: typ + ":" + id, Expr: exprString(e)})
		var err error
		if node != nil {
			err = x.arrow(typ, id, e, depth)
		}
		x.tr.close(node, parent, denied, false)
		return err
	case *schema.Union:
		kind, l, r = KindUnion, e.L, e.R
	case *schema.Intersection:
		kind, l, r = KindIntersection, e.L, e.R
	case *schema.Exclusion:
		kind, l, r = KindExclusion, e.L, e.R
	default:
		return fmt.Errorf("unsupported expression %T", e)
	}
	node, parent := x.tr.open(TraceNode{Kind: kind, Object: typ + ":" + id, Expr: exprString(e)})
	var err error
	if node != nil {
		if err = x.expr(typ, id, l, depth); err == nil {
			err = x.expr(typ, id, r, depth)
		}
	}
	x.tr.close(node, parent, denied, false)
	return err
}

// arrow lists the objects the tupleset names, each with the computed
// relation, skipping the ones Check skips.
func (x *expander) arrow(typ, id string, e *schema.Arrow, depth int) error {
	var ts *schema.Relation
	if d, ok := x.sc.Defs[typ]; ok {
		ts = d.Relations[e.Tupleset]
	}
	return x.e.eachDirect(x.sc, x.rev, typ, id, e.Tupleset, func(r store.Caveated) error {
		if d, ok := x.sc.Defs[r.SubjectType]; !ok || !d.Has(e.Computed) || r.SubjectID == "*" || !allowsCaveat(x.sc, ts, r) {
			return nil
		}
		if x.recursive {
			return x.node(r.SubjectType, r.SubjectID, e.Computed, r.Caveat, depth+1)
		}
		n := TraceNode{Kind: KindSubject, Object: typ + ":" + id, Relation: e.Tupleset,
			Subject: r.SubjectType + ":" + r.SubjectID + "#" + e.Computed}
		setCaveat(&n, r.Caveat)
		x.tr.leaf(n)
		return nil
	})
}
