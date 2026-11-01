package check

import (
	"context"
	"strings"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// Trace limits. A trace never holds more nodes than a check may do work,
// and by default far fewer, so explaining a check costs bounded memory.
const (
	DefaultTraceNodes = 1000
	MaxTraceNodes     = MaxDispatchesPerCheck
)

// TraceKind says what a trace node evaluated.
type TraceKind string

// Trace node kinds.
const (
	KindRelation     TraceKind = "relation"     // a stored relation on Object
	KindPermission   TraceKind = "permission"   // a computed permission on Object
	KindUnion        TraceKind = "union"        // a + b
	KindIntersection TraceKind = "intersection" // a & b
	KindExclusion    TraceKind = "exclusion"    // a - b
	KindArrow        TraceKind = "arrow"        // tupleset->computed
	KindSubject      TraceKind = "subject"      // a stored relationship naming the subject, or a wildcard
	KindSelf         TraceKind = "self"         // the userset is the subject itself
)

// TraceRole marks the nodes that decided the answer.
type TraceRole string

// Trace roles. A node with no role was evaluated but did not decide the
// answer, for example the false side of a union that was true anyway.
const (
	RoleGrant TraceRole = "grant" // on the path that granted access
	RoleDeny  TraceRole = "deny"  // on a branch that denied access
)

// TraceNode is one evaluated object#relation, operator or matching
// relationship.
type TraceNode struct {
	Kind     TraceKind `json:"kind"`
	Object   string    `json:"object"`             // type:id the node was evaluated on
	Relation string    `json:"relation,omitempty"` // relation or permission name, for relation, permission and self nodes
	Expr     string    `json:"expr,omitempty"`     // the operator's expression, for operator nodes
	Subject  string    `json:"subject,omitempty"`  // the stored subject that matched, for subject nodes
	Result   bool      `json:"result"`
	// Tainted marks a result that depended on a cycle cut. It is exact for
	// the root but would not be reused for the same node entered elsewhere.
	Tainted bool `json:"tainted,omitempty"`
	// Cut marks a node that was already being evaluated higher up the
	// path: a cycle in the data, counted as "not reached through this path".
	Cut bool `json:"cut,omitempty"`
	// Memo marks a node answered from an evaluation earlier in this trace.
	// Its children are under that earlier node.
	Memo bool      `json:"memo,omitempty"`
	Role TraceRole `json:"role,omitempty"`
	// Omitted counts children that were evaluated but not recorded because
	// the trace reached its node limit.
	Omitted  int          `json:"omitted,omitempty"`
	Children []*TraceNode `json:"children,omitempty"`
}

// Trace is the bounded evaluation tree of one check.
type Trace struct {
	Root *TraceNode
	// Nodes is the number of recorded nodes.
	Nodes int
	// Truncated reports that the node limit was reached and some nodes
	// were omitted. The answer is still exact: evaluation continues
	// without recording.
	Truncated bool
}

// Explain is Check with a trace of the evaluation, holding at most maxNodes
// nodes (DefaultTraceNodes when maxNodes <= 0, never more than
// MaxTraceNodes). The shared result cache is not read, so the trace shows
// the reasoning instead of a cache hit; results are still written to it.
// On error the trace is nil.
func (e *Engine) Explain(ctx context.Context, sc *schema.Schema, rev store.Revision, q Request, maxNodes int) (bool, *Trace, Stats, error) {
	if maxNodes <= 0 {
		maxNodes = DefaultTraceNodes
	}
	if maxNodes > MaxTraceNodes {
		maxNodes = MaxTraceNodes
	}
	if err := q.Validate(sc); err != nil {
		return false, nil, Stats{}, err
	}
	tr := &tracer{max: maxNodes}
	tr.cur = &tr.top
	st := &state{e: e, ctx: ctx, sc: sc, rev: rev, target: q.Subject,
		memo: map[string]bool{}, active: map[string]bool{}, tr: tr}
	ok, _, err := st.check(q.ResourceType, q.ResourceID, q.Permission, 0)
	if err != nil {
		return false, nil, st.stats, err
	}
	t := &Trace{Nodes: tr.n, Truncated: tr.truncated}
	if len(tr.top.Children) == 1 {
		t.Root = tr.top.Children[0]
		role := RoleDeny
		if ok {
			role = RoleGrant
		}
		mark(t.Root, role)
	}
	return ok, t, st.stats, nil
}

// tracer builds the tree as a stack: open makes a node the current parent
// and close restores the previous one. Past the node limit, open returns
// nil and the current parent becomes nil, so the whole omitted subtree is
// dropped while the stack stays balanced.
type tracer struct {
	max       int
	n         int
	top       TraceNode // holds the root
	cur       *TraceNode
	truncated bool
}

func (t *tracer) open(n TraceNode) (node, parent *TraceNode) {
	parent = t.cur
	if parent == nil {
		return nil, nil
	}
	if t.n == t.max {
		parent.Omitted++
		t.truncated = true
		t.cur = nil
		return nil, parent
	}
	t.n++
	node = &n
	parent.Children = append(parent.Children, node)
	t.cur = node
	return node, parent
}

func (t *tracer) close(node, parent *TraceNode, ok, tainted bool) {
	if node != nil {
		node.Result = ok
		node.Tainted = tainted
	}
	t.cur = parent
}

// leaf records a node with no children.
func (t *tracer) leaf(n TraceNode) {
	node, parent := t.open(n)
	t.close(node, parent, n.Result, n.Tainted)
}

func (s *state) traceKind(typ, rel string) TraceKind {
	if d, ok := s.sc.Defs[typ]; ok && d.IsPermission(rel) {
		return KindPermission
	}
	return KindRelation
}

// traceExpr evaluates an operator expression inside a trace node. A bare
// reference is not a node of its own: the referenced relation is.
func (s *state) traceExpr(typ, id string, e schema.Expr, depth int) (bool, bool, error) {
	var kind TraceKind
	switch e.(type) {
	case *schema.Union:
		kind = KindUnion
	case *schema.Intersection:
		kind = KindIntersection
	case *schema.Exclusion:
		kind = KindExclusion
	case *schema.Arrow:
		kind = KindArrow
	default:
		return s.evalExpr(typ, id, e, depth)
	}
	node, parent := s.tr.open(TraceNode{Kind: kind, Object: typ + ":" + id, Expr: exprString(e)})
	ok, tainted, err := s.evalExpr(typ, id, e, depth)
	s.tr.close(node, parent, ok, tainted)
	return ok, tainted, err
}

// exprString prints e with only the parentheses its shape needs, so a
// trace shows "viewer + edit - banned" rather than "((viewer + edit) - banned)".
// Operators bind "->", "&", "+", "-" from tightest to loosest and associate
// to the left, so a right operand of equal binding keeps its parentheses.
func exprString(e schema.Expr) string {
	var b strings.Builder
	writeExpr(&b, e)
	return b.String()
}

func precedence(e schema.Expr) int {
	switch e.(type) {
	case *schema.Exclusion:
		return 1
	case *schema.Union:
		return 2
	case *schema.Intersection:
		return 3
	}
	return 4
}

func writeExpr(b *strings.Builder, e schema.Expr) {
	var l, r schema.Expr
	var op string
	switch e := e.(type) {
	case *schema.Union:
		l, r, op = e.L, e.R, " + "
	case *schema.Intersection:
		l, r, op = e.L, e.R, " & "
	case *schema.Exclusion:
		l, r, op = e.L, e.R, " - "
	default:
		b.WriteString(e.String())
		return
	}
	p := precedence(e)
	operand := func(x schema.Expr, wrap bool) {
		if wrap {
			b.WriteByte('(')
		}
		writeExpr(b, x)
		if wrap {
			b.WriteByte(')')
		}
	}
	operand(l, precedence(l) < p)
	b.WriteString(op)
	operand(r, precedence(r) <= p)
}

func subjectString(r store.Relationship) string {
	s := r.SubjectType + ":" + r.SubjectID
	if r.SubjectRelation != "" {
		s += "#" + r.SubjectRelation
	}
	return s
}

// mark sets role on the nodes that decided n's result. Evaluation stops
// at the first true child of a relation, arrow or union, and at the first
// false child of an intersection, so when that short circuit happened the
// last child alone decided; otherwise every child did. An exclusion that
// is false was decided by its last child too: a false left side or a true
// right side. When children were omitted the deciding one may not be
// recorded, so nothing below is marked.
func mark(n *TraceNode, role TraceRole) {
	n.Role = role
	if len(n.Children) == 0 {
		return
	}
	lastOnly := false
	switch n.Kind {
	case KindRelation, KindArrow, KindUnion:
		lastOnly = n.Result
	case KindIntersection, KindExclusion:
		lastOnly = !n.Result
	}
	if lastOnly {
		if n.Omitted == 0 {
			mark(n.Children[len(n.Children)-1], role)
		}
		return
	}
	for _, c := range n.Children {
		mark(c, role)
	}
}
