package check

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

func (f *fixture) tryExpand(resource, perm string, recursive bool, maxNodes int) (*Trace, Stats, error) {
	rt, rid, _ := strings.Cut(resource, ":")
	sc, _ := f.st.Schema()
	return f.eng.Expand(context.Background(), sc, f.st.Head(),
		ExpandRequest{ResourceType: rt, ResourceID: rid, Permission: perm, Recursive: recursive, MaxNodes: maxNodes})
}

func (f *fixture) expand(resource, perm string, recursive bool, maxNodes int) *Trace {
	f.t.Helper()
	tr, _, err := f.tryExpand(resource, perm, recursive, maxNodes)
	if err != nil {
		f.t.Fatalf("expand %s#%s: %v", resource, perm, err)
	}
	return tr
}

// render prints a tree one node per line, indented by depth.
func render(n *TraceNode) string {
	var b strings.Builder
	var walk func(n *TraceNode, depth int)
	walk = func(n *TraceNode, depth int) {
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteString(string(n.Kind) + " " + n.Object)
		if n.Relation != "" {
			b.WriteString("#" + n.Relation)
		}
		if n.Expr != "" {
			b.WriteString(" " + n.Expr)
		}
		if n.Subject != "" {
			b.WriteString(" @" + n.Subject)
		}
		if n.Memo {
			b.WriteString(" (memo)")
		}
		if n.Cut {
			b.WriteString(" (cut)")
		}
		if n.Omitted > 0 {
			fmt.Fprintf(&b, " (+%d omitted)", n.Omitted)
		}
		b.WriteByte('\n')
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	walk(n, 0)
	return b.String()
}

// verifyExpansion checks the bookkeeping of a tree: the node count, the
// limit, Truncated, that no node carries check-only fields, and that every
// object#relation is expanded at most once with memo and cut nodes as
// childless references to it.
func verifyExpansion(t *testing.T, tr *Trace, maxNodes int) {
	t.Helper()
	count, omitted := 0, 0
	full := map[string]bool{}
	var walk func(n *TraceNode)
	walk = func(n *TraceNode) {
		count++
		omitted += n.Omitted
		if n.Result || n.Tainted || n.Role != "" {
			t.Fatalf("expand node carries check fields: %+v", n)
		}
		switch n.Kind {
		case KindRelation, KindPermission:
			k := n.Object + "#" + n.Relation
			if n.Memo || n.Cut {
				if len(n.Children) != 0 || n.Omitted != 0 || (n.Memo && n.Cut) || !full[k] {
					t.Fatalf("reference node %+v (expanded before: %v)", n, full[k])
				}
				break
			}
			if full[k] {
				t.Fatalf("%s expanded twice", k)
			}
			full[k] = true
			if n.Kind == KindPermission && len(n.Children)+n.Omitted != 1 {
				t.Fatalf("permission %s has %d children", k, len(n.Children))
			}
		case KindUnion, KindIntersection, KindExclusion:
			if len(n.Children)+n.Omitted != 2 || n.Expr == "" {
				t.Fatalf("operator %+v", n)
			}
		case KindArrow:
			if n.Expr == "" {
				t.Fatalf("arrow %+v", n)
			}
		case KindSubject:
			if len(n.Children) != 0 || n.Subject == "" {
				t.Fatalf("subject leaf %+v", n)
			}
		default:
			t.Fatalf("unexpected kind %q", n.Kind)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tr.Root)
	if count != tr.Nodes {
		t.Fatalf("tree says %d nodes, has %d", tr.Nodes, count)
	}
	if count > maxNodes {
		t.Fatalf("%d nodes, limit %d", count, maxNodes)
	}
	if tr.Truncated != (omitted > 0) {
		t.Fatalf("truncated=%v with %d omitted", tr.Truncated, omitted)
	}
}

// members solves a recursive tree's equations by fixpoint iteration over
// whole sets of users: the subjects the tree says hold the root, among
// users (user:* stands for all of them). It reads only the tree.
func members(t *testing.T, tr *Trace, users []string) map[string]bool {
	t.Helper()
	if tr.Truncated {
		t.Fatal("cannot solve a truncated tree")
	}
	all := map[string]bool{}
	for _, u := range users {
		all[u] = true
	}
	defs := map[string]*TraceNode{}
	var collect func(n *TraceNode)
	collect = func(n *TraceNode) {
		if (n.Kind == KindRelation || n.Kind == KindPermission) && !n.Memo && !n.Cut {
			defs[n.Object+"#"+n.Relation] = n
		}
		for _, c := range n.Children {
			collect(c)
		}
	}
	collect(tr.Root)
	cur := map[string]map[string]bool{}
	var eval func(n *TraceNode) map[string]bool
	union := func(ns []*TraceNode) map[string]bool {
		out := map[string]bool{}
		for _, c := range ns {
			for u := range eval(c) {
				out[u] = true
			}
		}
		return out
	}
	eval = func(n *TraceNode) map[string]bool {
		switch n.Kind {
		case KindSubject:
			typ, id, _ := strings.Cut(n.Subject, ":")
			if typ != "user" {
				t.Fatalf("recursive tree has a non-user leaf %q", n.Subject)
			}
			if id == "*" {
				return all
			}
			return map[string]bool{id: true}
		case KindRelation, KindPermission:
			if n.Memo || n.Cut {
				return cur[n.Object+"#"+n.Relation]
			}
			return union(n.Children)
		case KindArrow, KindUnion:
			return union(n.Children)
		case KindIntersection, KindExclusion:
			l, r := eval(n.Children[0]), eval(n.Children[1])
			out := map[string]bool{}
			for u := range l {
				if r[u] == (n.Kind == KindIntersection) {
					out[u] = true
				}
			}
			return out
		}
		t.Fatalf("unexpected node %+v", n)
		return nil
	}
	for changed := true; changed; {
		changed = false
		for k, n := range defs {
			next := eval(n)
			if len(next) != len(cur[k]) {
				changed = true
			}
			cur[k] = next
		}
	}
	return cur[tr.Root.Object+"#"+tr.Root.Relation]
}

func TestExpandOneLevel(t *testing.T) {
	f := sharingFixture(t)
	tr := f.expand("doc:design", "view", false, 0)
	verifyExpansion(t, tr, DefaultTraceNodes)
	want := `permission doc:design#view
  exclusion doc:design viewer + edit + parent->view - banned
    union doc:design viewer + edit + parent->view
      union doc:design viewer + edit
        relation doc:design#viewer
        permission doc:design#edit
          union doc:design owner + editor
            relation doc:design#owner
              subject doc:design#owner @user:dave
            relation doc:design#editor
              subject doc:design#editor @group:eng#member
      arrow doc:design parent->view
        subject doc:design#parent @folder:specs#view
    relation doc:design#banned
      subject doc:design#banned @user:carol
`
	if got := render(tr.Root); got != want {
		t.Fatalf("tree:\n%s\nwant:\n%s", got, want)
	}
	if tr.Truncated || tr.Nodes != 15 {
		t.Fatalf("nodes=%d truncated=%v", tr.Nodes, tr.Truncated)
	}

	// A relation expands to its stored subjects, wildcards included.
	tr = f.expand("folder:public", "viewer", false, 0)
	if got := render(tr.Root); got != "relation folder:public#viewer\n  subject folder:public#viewer @user:*\n" {
		t.Fatalf("wildcard relation:\n%s", got)
	}
	// An object with no relationships still has a tree: empty leaves.
	tr = f.expand("doc:nothing", "edit", false, 0)
	want = `permission doc:nothing#edit
  union doc:nothing owner + editor
    relation doc:nothing#owner
    relation doc:nothing#editor
`
	if got := render(tr.Root); got != want {
		t.Fatalf("empty object:\n%s", got)
	}
}

func TestExpandRecursive(t *testing.T) {
	f := sharingFixture(t)
	tr := f.expand("doc:design", "view", true, 0)
	verifyExpansion(t, tr, DefaultTraceNodes)
	want := `permission doc:design#view
  exclusion doc:design viewer + edit + parent->view - banned
    union doc:design viewer + edit + parent->view
      union doc:design viewer + edit
        relation doc:design#viewer
        permission doc:design#edit
          union doc:design owner + editor
            relation doc:design#owner
              subject doc:design#owner @user:dave
            relation doc:design#editor
              relation group:eng#member
                subject group:eng#member @user:alice
      arrow doc:design parent->view
        permission folder:specs#view
          union folder:specs viewer + parent->view
            relation folder:specs#viewer
            arrow folder:specs parent->view
              permission folder:root#view
                union folder:root viewer + parent->view
                  relation folder:root#viewer
                    relation group:staff#member
                      relation group:eng#member (memo)
                      subject group:staff#member @user:carol
                  arrow folder:root parent->view
    relation doc:design#banned
      subject doc:design#banned @user:carol
`
	if got := render(tr.Root); got != want {
		t.Fatalf("tree:\n%s\nwant:\n%s", got, want)
	}
	users := []string{"alice", "carol", "dave", "erin"}
	got := members(t, tr, users)
	if len(got) != 2 || !got["alice"] || !got["dave"] {
		t.Fatalf("doc:design view holders %v, want alice and dave", got)
	}
	// Every answer the tree gives is the answer Check gives.
	for _, u := range users {
		if c := f.check("doc:design", "view", "user:"+u); c != got[u] {
			t.Fatalf("%s: check %v, tree %v", u, c, got[u])
		}
	}
}

func TestExpandCycles(t *testing.T) {
	f := newFixture(t, nil,
		"group:a#member@group:b#member",
		"group:b#member@group:c#member",
		"group:c#member@group:a#member",
		"group:c#member@user:zed",
		"folder:x#parent@folder:y",
		"folder:y#parent@folder:x",
		"folder:y#viewer@user:yan",
	)
	tr := f.expand("group:a", "member", true, 0)
	verifyExpansion(t, tr, DefaultTraceNodes)
	want := `relation group:a#member
  relation group:b#member
    relation group:c#member
      relation group:a#member (cut)
      subject group:c#member @user:zed
`
	if got := render(tr.Root); got != want {
		t.Fatalf("group cycle:\n%s", got)
	}
	if m := members(t, tr, []string{"zed", "yan"}); len(m) != 1 || !m["zed"] {
		t.Fatalf("group:a members %v", m)
	}
	tr = f.expand("folder:x", "view", true, 0)
	verifyExpansion(t, tr, DefaultTraceNodes)
	if cuts := find(tr.Root, func(n *TraceNode) bool { return n.Cut }); len(cuts) != 1 || cuts[0].Object != "folder:x" {
		t.Fatalf("folder cycle cuts %+v", cuts)
	}
	if m := members(t, tr, []string{"zed", "yan"}); len(m) != 1 || !m["yan"] {
		t.Fatalf("folder:x viewers %v", m)
	}
	// One level does not follow the cycle at all.
	tr = f.expand("group:a", "member", false, 0)
	if got := render(tr.Root); got != "relation group:a#member\n  subject group:a#member @group:b#member\n" {
		t.Fatalf("one level:\n%s", got)
	}
}

func TestExpandNodeLimit(t *testing.T) {
	var rels []string
	for i := 0; i < 40; i++ {
		rels = append(rels, fmt.Sprintf("group:top#member@group:g%d#member", i))
		for j := 0; j < 5; j++ {
			rels = append(rels, fmt.Sprintf("group:g%d#member@user:u%d_%d", i, i, j))
		}
	}
	f := newFixture(t, nil, rels...)
	full := f.expand("group:top", "member", true, MaxTraceNodes)
	verifyExpansion(t, full, MaxTraceNodes)
	if full.Truncated || full.Nodes != 1+40*6 {
		t.Fatalf("full tree: nodes=%d truncated=%v", full.Nodes, full.Truncated)
	}
	for _, max := range []int{1, 2, 7, 50, 240} {
		tr, stats, err := f.tryExpand("group:top", "member", true, max)
		if err != nil {
			t.Fatal(err)
		}
		verifyExpansion(t, tr, max)
		if !tr.Truncated || tr.Nodes != max {
			t.Fatalf("max %d: nodes=%d truncated=%v", max, tr.Nodes, tr.Truncated)
		}
		// Expansion stops at the limit instead of walking the rest unrecorded.
		if stats.Dispatches > max {
			t.Fatalf("max %d: %d dispatches", max, stats.Dispatches)
		}
	}
	// The default limit applies to 0, and the hard limit above it.
	if tr := f.expand("group:top", "member", true, 0); tr.Nodes != full.Nodes {
		t.Fatalf("default limit cut a %d-node tree to %d", full.Nodes, tr.Nodes)
	}
	if tr := f.expand("group:top", "member", true, MaxTraceNodes+1); tr.Nodes != full.Nodes {
		t.Fatal("over-limit request")
	}
}

func TestExpandErrors(t *testing.T) {
	f := newFixture(t, nil, "doc:a#viewer@user:x")
	sc, _ := f.st.Schema()
	for _, c := range []struct {
		q    ExpandRequest
		want error
	}{
		{ExpandRequest{ResourceType: "nope", ResourceID: "a", Permission: "view"}, ErrUnknownType},
		{ExpandRequest{ResourceType: "doc", ResourceID: "a", Permission: "nope"}, ErrUnknownName},
		{ExpandRequest{ResourceType: "doc", ResourceID: "a b", Permission: "view"}, store.ErrInvalid},
	} {
		if _, _, err := f.eng.Expand(context.Background(), sc, f.st.Head(), c.q); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v, want %v", c.q, err, c.want)
		}
	}
	if err := (ExpandRequest{}).Validate(nil); !errors.Is(err, store.ErrNoSchema) {
		t.Errorf("nil schema: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := ExpandRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", Recursive: true}
	if _, _, err := f.eng.Expand(ctx, sc, f.st.Head(), q); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	if _, _, err := f.eng.Expand(context.Background(), sc, f.st.Head()+1, q); !errors.Is(err, store.ErrFutureRevision) {
		t.Fatalf("future revision: %v", err)
	}
}

func TestExpandDepthLimit(t *testing.T) {
	var rels []string
	n := DefaultMaxDepth + 5
	for i := 0; i < n; i++ {
		rels = append(rels, fmt.Sprintf("group:g%d#member@group:g%d#member", i, i+1))
	}
	f := newFixture(t, nil, rels...)
	if _, _, err := f.tryExpand("group:g0", "member", true, MaxTraceNodes); !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("deep chain: %v", err)
	}
	if _, _, err := f.tryExpand("group:g10", "member", true, MaxTraceNodes); err != nil {
		t.Fatalf("chain within the limit: %v", err)
	}
	// One level never goes deep.
	if _, _, err := f.tryExpand("group:g0", "member", false, 0); err != nil {
		t.Fatal(err)
	}
}

func TestExpandWorkLimit(t *testing.T) {
	// The graph Check's work limit refuses: every expanded object#relation
	// is a node, so the tree limit (MaxTraceNodes, the same number) stops
	// the expansion first and the answer is a truncated tree, not an error.
	f := newFixture(t, nil)
	var rels []string
	for i := 0; i < 999; i++ {
		rels = append(rels, fmt.Sprintf("group:top#member@group:g%d#member", i))
	}
	f.write(rels...)
	for b := 0; b < 101; b++ {
		batch := make([]string, 0, 1000)
		for i := 0; i < 1000; i++ {
			batch = append(batch, fmt.Sprintf("group:g%d#member@group:h%d_%d#member", b, b, i))
		}
		f.write(batch...)
	}
	tr, stats, err := f.tryExpand("group:top", "member", true, MaxTraceNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Truncated || tr.Nodes != MaxTraceNodes || stats.Dispatches > MaxDispatchesPerCheck {
		t.Fatalf("nodes=%d truncated=%v dispatches=%d", tr.Nodes, tr.Truncated, stats.Dispatches)
	}
}

func TestExpandOldSnapshotAfterSchemaChange(t *testing.T) {
	f := newFixture(t, nil, "group:eng#member@user:a", "doc:d#viewer@group:eng#member", "doc:d#viewer@user:b")
	old := f.st.Head()
	for _, r := range []string{"doc:d#viewer@group:eng#member", "group:eng#member@user:a"} {
		rel, _ := store.ParseRelationship(r)
		if _, err := f.st.Write([]store.Update{{Op: store.OpDelete, Relationship: rel}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	noGroups := strings.Replace(strings.Replace(model, "definition group {\n  relation member: user | group#member\n}", "", 1), " | group#member", "", -1)
	if _, err := f.st.WriteSchema(noGroups); err != nil {
		t.Fatal(err)
	}
	sc, _ := f.st.Schema()
	for _, recursive := range []bool{false, true} {
		tr, _, err := f.eng.Expand(context.Background(), sc, old, ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "viewer", Recursive: recursive})
		if err != nil {
			t.Fatal(err)
		}
		if got := render(tr.Root); got != "relation doc:d#viewer\n  subject doc:d#viewer @user:b\n" {
			t.Fatalf("recursive=%v: removed userset still listed:\n%s", recursive, got)
		}
	}
}

func TestExpandArrowAtOldSnapshot(t *testing.T) {
	// At a snapshot older than a schema change, an arrow can name an
	// object whose type no longer exists: Check and Expand both skip it.
	const before = `
definition user {}
definition team {
  relation member: user
  permission view = member
}
definition folder {
  relation viewer: user
  permission view = viewer
}
definition doc {
  relation parent: folder | team
  permission view = parent->view
}
`
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.WriteSchema(before); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: st, eng: New(st, nil)}
	f.write("doc:d#parent@team:t", "doc:d#parent@folder:f", "folder:f#viewer@user:u", "team:t#member@user:v")
	old := st.Head()
	for _, r := range []string{"doc:d#parent@team:t", "team:t#member@user:v"} {
		rel, _ := store.ParseRelationship(r)
		if _, err := st.Write([]store.Update{{Op: store.OpDelete, Relationship: rel}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	after := strings.Replace(strings.Replace(before, "definition team {\n  relation member: user\n  permission view = member\n}\n", "", 1), " | team", "", 1)
	if _, err := st.WriteSchema(after); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.Schema()
	for _, recursive := range []bool{false, true} {
		tr, _, err := f.eng.Expand(context.Background(), sc, old, ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view", Recursive: recursive})
		if err != nil {
			t.Fatal(err)
		}
		verifyExpansion(t, tr, DefaultTraceNodes)
		arrow := tr.Root.Children[0]
		if arrow.Kind != KindArrow || len(arrow.Children) != 1 || !strings.Contains(render(arrow), "folder:f") {
			t.Fatalf("recursive=%v:\n%s", recursive, render(tr.Root))
		}
	}
	if _, _, err := f.eng.Expand(context.Background(), sc, st.Head()+1, ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view"}); !errors.Is(err, store.ErrFutureRevision) {
		t.Fatalf("future revision through an arrow: %v", err)
	}
}

func TestExpandMatchesReferenceOnRandomGraphs(t *testing.T) {
	iterations := 60
	if testing.Short() {
		iterations = 10
	}
	for seed := int64(0); seed < int64(iterations); seed++ {
		rng := rand.New(rand.NewSource(seed))
		nusers, groups, folders, docs := 6, 2+rng.Intn(6), 2+rng.Intn(6), 8
		w := randomWorld(rng, nusers, groups, folders, docs)
		ref := buildReference(w, nusers)
		f := newFixture(t, nil, w.rels...)
		users := make([]string, nusers)
		for u := range users {
			users[u] = fmt.Sprintf("u%d", u)
		}
		compare := func(res, perm string, want func(u string) bool) {
			t.Helper()
			tr := f.expand(res, perm, true, MaxTraceNodes)
			verifyExpansion(t, tr, MaxTraceNodes)
			got := members(t, tr, users)
			for _, u := range users {
				if got[u] != want(u) {
					t.Fatalf("seed %d: %s#%s holds %s: tree %v, reference %v\n%s\nrelationships:\n%s",
						seed, res, perm, u, got[u], want(u), render(tr.Root), strings.Join(w.rels, "\n"))
				}
			}
			// The one-level tree is the first level of the recursive one.
			one := f.expand(res, perm, false, MaxTraceNodes)
			verifyExpansion(t, one, MaxTraceNodes)
			if one.Nodes > tr.Nodes {
				t.Fatalf("seed %d: one level has %d nodes, recursive %d", seed, one.Nodes, tr.Nodes)
			}
		}
		for d := 0; d < docs; d++ {
			id := fmt.Sprintf("d%d", d)
			compare("doc:"+id, "view", func(u string) bool { return ref.docView(id, u) })
			compare("doc:"+id, "edit", func(u string) bool { return ref.docEdit(id, u) })
			compare("doc:"+id, "both", func(u string) bool { return ref.docEdit(id, u) && ref.docParentView(id, u) })
		}
		for g := 0; g < groups; g++ {
			id := fmt.Sprintf("g%d", g)
			compare("group:"+id, "member", func(u string) bool { return ref.inGroup[id][u] })
		}
		for fo := 0; fo < folders; fo++ {
			id := fmt.Sprintf("f%d", fo)
			compare("folder:"+id, "view", func(u string) bool { return ref.folderView(id, u) })
		}
	}
}

func BenchmarkExpandDeepFolders(b *testing.B) {
	f, q, sc := benchFixture(b, 30, 10, nil)
	eq := ExpandRequest{ResourceType: q.ResourceType, ResourceID: q.ResourceID, Permission: q.Permission, Recursive: true}
	rev := f.st.Head()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := f.eng.Expand(context.Background(), sc, rev, eq); err != nil {
			b.Fatal(err)
		}
	}
}
