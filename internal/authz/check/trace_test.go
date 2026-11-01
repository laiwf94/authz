package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

func (f *fixture) explain(resource, perm, subject string, maxNodes int) (bool, *Trace) {
	f.t.Helper()
	ok, tr, err := f.tryExplain(resource, perm, subject, maxNodes)
	if err != nil {
		f.t.Fatalf("explain %s#%s@%s: %v", resource, perm, subject, err)
	}
	return ok, tr
}

func (f *fixture) tryExplain(resource, perm, subject string, maxNodes int) (bool, *Trace, error) {
	rt, rid, _ := strings.Cut(resource, ":")
	subj, err := store.ParseSubject(subject, false)
	if err != nil {
		return false, nil, err
	}
	sc, _ := f.st.Schema()
	ok, tr, _, err := f.eng.Explain(context.Background(), sc, f.st.Head(),
		Request{ResourceType: rt, ResourceID: rid, Permission: perm, Subject: subj}, maxNodes)
	return ok, tr, err
}

// verifyTrace checks that every recorded node is consistent with its
// children and that the roles mark a path that really decides the answer.
func verifyTrace(t *testing.T, ok bool, tr *Trace, maxNodes int) {
	t.Helper()
	if tr == nil || tr.Root == nil {
		t.Fatal("no trace")
	}
	if tr.Root.Result != ok {
		t.Fatalf("root result %v, check said %v", tr.Root.Result, ok)
	}
	want := RoleDeny
	if ok {
		want = RoleGrant
	}
	if tr.Root.Role != want {
		t.Fatalf("root role %q, want %q", tr.Root.Role, want)
	}
	count, omitted := 0, 0
	var walk func(n *TraceNode)
	walk = func(n *TraceNode) {
		count++
		omitted += n.Omitted
		if n.Role != "" && n.Role != want {
			t.Fatalf("node %s %s#%s has role %q in a %q trace", n.Kind, n.Object, n.Relation, n.Role, want)
		}
		decided := 0
		anyTainted := false
		for _, c := range n.Children {
			if c.Role != "" {
				decided++
				if n.Role == "" {
					t.Fatalf("child of an undecided node has a role: %+v", c)
				}
			}
			anyTainted = anyTainted || c.Tainted
			walk(c)
		}
		if n.Tainted && !n.Cut && !anyTainted && n.Omitted == 0 {
			t.Fatalf("node %s %s#%s is tainted with no cut below it", n.Kind, n.Object, n.Relation)
		}
		if n.Omitted > 0 {
			return // children incomplete: only the recorded ones are checked above
		}
		res := make([]bool, len(n.Children))
		for i, c := range n.Children {
			res[i] = c.Result
		}
		switch n.Kind {
		case KindSubject, KindSelf:
			if !n.Result || len(n.Children) != 0 {
				t.Fatalf("leaf %+v", n)
			}
		case KindRelation, KindArrow, KindUnion:
			if n.Cut || n.Memo {
				if len(n.Children) != 0 || (n.Cut && n.Result) {
					t.Fatalf("cut or memo node %+v", n)
				}
				return
			}
			anyTrue := false
			for i, r := range res {
				if r && i != len(res)-1 {
					t.Fatalf("%s %s kept evaluating after a true child", n.Kind, n.Object)
				}
				anyTrue = anyTrue || r
			}
			if anyTrue != n.Result {
				t.Fatalf("%s %s#%s%s = %v, children %v", n.Kind, n.Object, n.Relation, n.Expr, n.Result, res)
			}
			if n.Role != "" && n.Result && decided != 1 {
				t.Fatalf("a true %s should be decided by one child, got %d", n.Kind, decided)
			}
			if n.Role != "" && !n.Result && decided != len(res) {
				t.Fatalf("a false %s is decided by all children", n.Kind)
			}
		case KindPermission:
			if n.Memo || n.Cut {
				return
			}
			if len(res) != 1 || res[0] != n.Result {
				t.Fatalf("permission %s#%s = %v, children %v", n.Object, n.Relation, n.Result, res)
			}
		case KindIntersection:
			if n.Result != (len(res) == 2 && res[0] && res[1]) || (len(res) == 2 && !res[0]) {
				t.Fatalf("intersection %s = %v, children %v", n.Expr, n.Result, res)
			}
		case KindExclusion:
			switch {
			case len(res) == 1 && !res[0] && !n.Result:
			case len(res) == 2 && res[0] && n.Result == !res[1]:
			default:
				t.Fatalf("exclusion %s = %v, children %v", n.Expr, n.Result, res)
			}
		default:
			t.Fatalf("unknown kind %q", n.Kind)
		}
	}
	walk(tr.Root)
	if count != tr.Nodes {
		t.Fatalf("trace says %d nodes, tree has %d", tr.Nodes, count)
	}
	if count > maxNodes {
		t.Fatalf("%d nodes, limit %d", count, maxNodes)
	}
	if tr.Truncated != (omitted > 0) {
		t.Fatalf("truncated=%v with %d omitted", tr.Truncated, omitted)
	}
}

// find returns the nodes matching pred, in evaluation order.
func find(n *TraceNode, pred func(*TraceNode) bool) []*TraceNode {
	var out []*TraceNode
	if pred(n) {
		out = append(out, n)
	}
	for _, c := range n.Children {
		out = append(out, find(c, pred)...)
	}
	return out
}

func sharingFixture(t *testing.T) *fixture {
	return newFixture(t, nil,
		"group:eng#member@user:alice",
		"group:staff#member@group:eng#member",
		"group:staff#member@user:carol",
		"folder:root#viewer@group:staff#member",
		"folder:specs#parent@folder:root",
		"doc:design#parent@folder:specs",
		"doc:design#owner@user:dave",
		"doc:design#editor@group:eng#member",
		"doc:design#banned@user:carol",
		"folder:public#viewer@user:*",
		"doc:readme#parent@folder:public",
	)
}

func TestExplainGrantingPath(t *testing.T) {
	f := sharingFixture(t)
	ok, tr := f.explain("doc:design", "view", "user:alice", 0)
	if !ok {
		t.Fatal("alice should view doc:design")
	}
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	root := tr.Root
	if root.Kind != KindPermission || root.Object != "doc:design" || root.Relation != "view" {
		t.Fatalf("root %+v", root)
	}
	// The granting path ends at the stored relationship group:eng#member@user:alice.
	leaves := find(root, func(n *TraceNode) bool { return n.Role == RoleGrant && n.Kind == KindSubject })
	if len(leaves) != 1 || leaves[0].Object != "group:eng" || leaves[0].Subject != "user:alice" {
		t.Fatalf("granting leaves %+v", leaves)
	}
	// alice is not banned: the banned branch is part of the grant, and false.
	banned := find(root, func(n *TraceNode) bool { return n.Relation == "banned" })
	if len(banned) != 1 || banned[0].Result || banned[0].Role != RoleGrant {
		t.Fatalf("banned node %+v", banned)
	}
	ex := find(root, func(n *TraceNode) bool { return n.Kind == KindExclusion })
	if len(ex) != 1 || ex[0].Expr != "viewer + edit + parent->view - banned" {
		t.Fatalf("exclusion %+v", ex)
	}
	// The union stopped at edit; parent->view was never evaluated.
	if arrows := find(root, func(n *TraceNode) bool { return n.Kind == KindArrow }); len(arrows) != 0 {
		t.Fatalf("union kept evaluating after edit granted: %+v", arrows)
	}
	if _, err := json.Marshal(tr.Root); err != nil {
		t.Fatal(err)
	}
}

func TestExplainDenyingBranch(t *testing.T) {
	f := sharingFixture(t)
	ok, tr := f.explain("doc:design", "view", "user:carol", 0)
	if ok {
		t.Fatal("carol is banned")
	}
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	// carol reaches the folder chain, so the exclusion's left side is
	// true; the denying branch is the ban.
	ex := find(tr.Root, func(n *TraceNode) bool { return n.Kind == KindExclusion })
	if len(ex) != 1 || len(ex[0].Children) != 2 {
		t.Fatalf("exclusion %+v", ex)
	}
	left, right := ex[0].Children[0], ex[0].Children[1]
	if !left.Result || left.Role != "" {
		t.Fatalf("left side should be true and not decisive: %+v", left)
	}
	if right.Relation != "banned" || !right.Result || right.Role != RoleDeny {
		t.Fatalf("denying branch %+v", right)
	}
	if len(right.Children) != 1 || right.Children[0].Subject != "user:carol" || right.Children[0].Role != RoleDeny {
		t.Fatalf("ban relationship %+v", right.Children)
	}

	// A stranger is denied by every branch of the union.
	ok, tr = f.explain("doc:design", "view", "user:erin", 0)
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	ex = find(tr.Root, func(n *TraceNode) bool { return n.Kind == KindExclusion })
	if len(ex[0].Children) != 1 || ex[0].Children[0].Role != RoleDeny {
		t.Fatalf("the left side alone should deny: %+v", ex[0].Children)
	}
	for _, rel := range []string{"viewer", "edit", "owner", "editor"} {
		ns := find(tr.Root, func(n *TraceNode) bool { return n.Object == "doc:design" && n.Relation == rel })
		if len(ns) != 1 || ns[0].Role != RoleDeny || ns[0].Result {
			t.Fatalf("%s: %+v", rel, ns)
		}
	}
	if arrows := find(tr.Root, func(n *TraceNode) bool { return n.Kind == KindArrow && n.Object == "doc:design" }); len(arrows) != 1 ||
		arrows[0].Expr != "parent->view" || arrows[0].Role != RoleDeny || arrows[0].Result {
		t.Fatalf("arrow %+v", arrows)
	}
}

func TestExplainIntersectionAndWildcard(t *testing.T) {
	f := sharingFixture(t)
	ok, tr := f.explain("doc:design", "both", "user:dave", 0)
	if ok {
		t.Fatal("dave cannot see the folder")
	}
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	in := find(tr.Root, func(n *TraceNode) bool { return n.Kind == KindIntersection })
	if len(in) != 1 || len(in[0].Children) != 2 || in[0].Children[0].Role != "" || in[0].Children[1].Role != RoleDeny {
		t.Fatalf("intersection: the false right side denies: %+v", in)
	}

	ok, tr = f.explain("doc:readme", "view", "user:anyone", 0)
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	leaves := find(tr.Root, func(n *TraceNode) bool { return n.Role == RoleGrant && n.Kind == KindSubject })
	if !ok || len(leaves) != 1 || leaves[0].Subject != "user:*" || leaves[0].Object != "folder:public" {
		t.Fatalf("wildcard grant %+v", leaves)
	}

	ok, tr = f.explain("group:staff", "member", "group:staff#member", 0)
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	if !ok || tr.Root.Kind != KindSelf || tr.Nodes != 1 {
		t.Fatalf("a userset contains itself: %+v", tr.Root)
	}
}

func TestExplainCycleCutsAndTaint(t *testing.T) {
	f := newFixture(t, nil,
		"group:a#member@group:b#member",
		"group:b#member@group:c#member",
		"group:c#member@group:a#member",
		"group:c#member@user:zed",
	)
	ok, tr := f.explain("group:a", "member", "user:nobody", 0)
	if ok {
		t.Fatal("stranger")
	}
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	cuts := find(tr.Root, func(n *TraceNode) bool { return n.Cut })
	if len(cuts) != 1 || cuts[0].Object != "group:a" || !cuts[0].Tainted || cuts[0].Result {
		t.Fatalf("cuts %+v", cuts)
	}
	tainted := find(tr.Root, func(n *TraceNode) bool { return n.Tainted && !n.Cut })
	if len(tainted) != 3 { // a, b and c are all computed through the cut
		t.Fatalf("tainted %+v", tainted)
	}

	ok, tr = f.explain("group:a", "member", "user:zed", 0)
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	// c reads group:a#member (cut) before user:zed, but the cut did not
	// decide anything: the grant is exact and untainted.
	if !ok || tr.Root.Tainted {
		t.Fatalf("zed: ok=%v tainted=%v", ok, tr.Root.Tainted)
	}
	for _, c := range find(tr.Root, func(n *TraceNode) bool { return n.Cut }) {
		if c.Role != "" {
			t.Fatalf("a cut on the granting path: %+v", c)
		}
	}
}

func TestExplainMemoizedNodes(t *testing.T) {
	// doc:x#edit is reached twice: as editor's container and again through view.
	f := newFixture(t, nil,
		"group:g#member@user:other",
		"doc:x#viewer@group:g#member",
		"doc:x#editor@group:g#member",
	)
	ok, tr := f.explain("doc:x", "view", "user:u", 0)
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	memo := find(tr.Root, func(n *TraceNode) bool { return n.Memo })
	if len(memo) != 1 || memo[0].Object != "group:g" || memo[0].Result {
		t.Fatalf("memo %+v", memo)
	}
}

func TestExplainNodeLimit(t *testing.T) {
	var rels []string
	for i := 0; i < 500; i++ {
		rels = append(rels, fmt.Sprintf("group:top#member@group:g%d#member", i))
	}
	rels = append(rels, "group:g499#member@user:last")
	f := newFixture(t, nil, rels...)
	for _, limit := range []int{1, 2, 10, 100} {
		ok, tr := f.explain("group:top", "member", "user:last", limit)
		if !ok {
			t.Fatalf("limit %d changed the answer", limit)
		}
		if !tr.Truncated || tr.Nodes != limit || tr.Root.Omitted == 0 {
			t.Fatalf("limit %d: nodes=%d truncated=%v omitted=%d", limit, tr.Nodes, tr.Truncated, tr.Root.Omitted)
		}
		verifyTrace(t, ok, tr, limit)
		// The granting child was omitted, so no child claims to have decided.
		if len(find(tr.Root, func(n *TraceNode) bool { return n.Role != "" })) != 1 {
			t.Fatalf("limit %d: only the root can be marked", limit)
		}
	}
	ok, full := f.explain("group:top", "member", "user:last", MaxTraceNodes*10)
	if !ok || full.Truncated || full.Nodes < 100 {
		t.Fatalf("full trace: nodes=%d truncated=%v", full.Nodes, full.Truncated)
	}
	verifyTrace(t, ok, full, MaxTraceNodes)
	// Relationships are read in subject order, so g499 is not the last group.
	path := find(full.Root, func(n *TraceNode) bool { return n.Role == RoleGrant })
	if len(path) != 3 || path[1].Object != "group:g499" || path[2].Subject != "user:last" {
		t.Fatalf("granting path %+v", path)
	}
	if len(full.Root.Children) != full.Nodes-2 { // root, the groups tried, one subject
		t.Fatalf("%d children, %d nodes", len(full.Root.Children), full.Nodes)
	}
	if _, tr := f.explain("group:top", "member", "user:last", 0); tr.Nodes != full.Nodes {
		t.Fatalf("default limit: %d nodes, want %d", tr.Nodes, full.Nodes)
	}
}

func TestExplainErrors(t *testing.T) {
	var rels []string
	n := DefaultMaxDepth + 5
	for i := 0; i < n; i++ {
		rels = append(rels, fmt.Sprintf("group:g%d#member@group:g%d#member", i, i+1))
	}
	f := newFixture(t, nil, rels...)
	if _, tr, err := f.tryExplain("group:g0", "member", "user:deep", 0); !errors.Is(err, ErrDepthExceeded) || tr != nil {
		t.Fatalf("deep chain: trace %v, err %v", tr, err)
	}
	if _, tr, err := f.tryExplain("doc:x", "nope", "user:a", 0); !errors.Is(err, ErrUnknownName) || tr != nil {
		t.Fatalf("unknown permission: trace %v, err %v", tr, err)
	}
}

func TestExplainIgnoresCacheButMatchesCheck(t *testing.T) {
	f := newFixture(t, NewCache(1000), "group:g#member@user:a", "doc:d#viewer@group:g#member")
	if !f.check("doc:d", "view", "user:a") {
		t.Fatal("check")
	}
	// The answer is cached now; explain still shows the reasoning.
	ok, tr := f.explain("doc:d", "view", "user:a", 0)
	verifyTrace(t, ok, tr, DefaultTraceNodes)
	if !ok || len(find(tr.Root, func(n *TraceNode) bool { return n.Kind == KindSubject && n.Role == RoleGrant })) != 1 {
		t.Fatalf("explain answered from the cache: %+v", tr.Root)
	}
}

// Explain must agree with Check, and with the fixpoint reference, on
// random graphs with cycles, and every trace must be well formed.
func TestExplainMatchesReferenceOnRandomGraphs(t *testing.T) {
	iterations := 30
	if testing.Short() {
		iterations = 5
	}
	for seed := int64(0); seed < int64(iterations); seed++ {
		rng := rand.New(rand.NewSource(seed))
		users, groups, folders, docs := 5, 2+rng.Intn(6), 2+rng.Intn(6), 6
		w := randomWorld(rng, users, groups, folders, docs)
		ref := buildReference(w, users)
		f := newFixture(t, nil, w.rels...)
		for d := 0; d < docs; d++ {
			for u := 0; u < users; u++ {
				id, uid := fmt.Sprintf("d%d", d), fmt.Sprintf("u%d", u)
				for _, c := range []struct {
					perm string
					want bool
				}{
					{"view", ref.docView(id, uid)},
					{"edit", ref.docEdit(id, uid)},
					{"both", ref.docEdit(id, uid) && ref.docParentView(id, uid)},
				} {
					limit := DefaultTraceNodes
					if rng.Intn(3) == 0 {
						limit = 1 + rng.Intn(8) // exercise truncation
					}
					ok, tr := f.explain("doc:"+id, c.perm, "user:"+uid, limit)
					if ok != c.want {
						t.Fatalf("seed %d: explain doc:%s#%s@user:%s = %v, reference %v", seed, id, c.perm, uid, ok, c.want)
					}
					verifyTrace(t, ok, tr, limit)
				}
			}
		}
	}
}

func TestExprString(t *testing.T) {
	f := newFixture(t, nil)
	sc, _ := f.st.Schema()
	for perm, want := range map[string]string{
		"view": "viewer + edit + parent->view - banned",
		"edit": "owner + editor",
		"both": "edit & parent->view",
	} {
		if got := exprString(sc.Defs["doc"].Permissions[perm].Expr); got != want {
			t.Errorf("%s: %q, want %q", perm, got, want)
		}
	}
	// Shapes the default model does not have.
	src := `definition user {}
definition t {
  relation a: user
  relation b: user
  relation c: user
  permission p1 = a - (b - c)
  permission p2 = (a + b) & c
  permission p3 = a + (b + c)
  permission p4 = a - b - c
  permission p5 = a & b + c
}`
	if _, err := f.st.WriteSchema(src); err != nil {
		t.Fatal(err)
	}
	sc, _ = f.st.Schema()
	for perm, want := range map[string]string{
		"p1": "a - (b - c)", "p2": "(a + b) & c", "p3": "a + (b + c)", "p4": "a - b - c", "p5": "a & b + c",
	} {
		if got := exprString(sc.Defs["t"].Permissions[perm].Expr); got != want {
			t.Errorf("%s: %q, want %q", perm, got, want)
		}
	}
}

func BenchmarkExplainDeepFolders(b *testing.B) {
	for _, depth := range []int{1, 10, 40} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			f, q, sc := benchFixture(b, depth, 20, nil)
			rev := f.st.Head()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if ok, _, _, err := f.eng.Explain(context.Background(), sc, rev, q, 0); err != nil || !ok {
					b.Fatal(ok, err)
				}
			}
		})
	}
}
