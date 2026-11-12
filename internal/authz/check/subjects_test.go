package check

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

func (f *fixture) tryLookupSubjects(resource, perm, subjectType, after string, limit int) (LookupSubjectsResult, Stats, error) {
	rt, rid, _ := strings.Cut(resource, ":")
	st, sr, _ := strings.Cut(subjectType, "#")
	sc, _ := f.st.Schema()
	return f.eng.LookupSubjects(context.Background(), sc, f.st.Head(), LookupSubjectsRequest{ResourceType: rt, ResourceID: rid,
		Permission: perm, SubjectType: st, SubjectRelation: sr, After: after, Limit: limit})
}

// lookupAll pages through every subject with pages of limit and renders
// them as "a b *-x,y".
func (f *fixture) lookupAll(resource, perm, subjectType string, limit int) string {
	f.t.Helper()
	var out []string
	after := ""
	for pages := 0; ; pages++ {
		res, _, err := f.tryLookupSubjects(resource, perm, subjectType, after, limit)
		if err != nil {
			f.t.Fatalf("lookup subjects %s#%s %s: %v", resource, perm, subjectType, err)
		}
		if limit > 0 && len(res.Subjects) > limit {
			f.t.Fatalf("page of %d subjects, limit %d", len(res.Subjects), limit)
		}
		for _, s := range res.Subjects {
			if s.ID == Wildcard {
				out = append(out, "*-"+strings.Join(s.Excluded, ","))
				continue
			}
			if len(s.Excluded) != 0 {
				f.t.Fatalf("%s has exclusions %v", s.ID, s.Excluded)
			}
			out = append(out, s.ID)
		}
		if res.Next == "" {
			return strings.Join(out, " ")
		}
		if pages > 10_000 {
			f.t.Fatal("paging does not end")
		}
		after = res.Next
	}
}

func TestLookupSubjectsSharing(t *testing.T) {
	f := newFixture(t, nil,
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
		"folder:public#viewer@user:pat",
		"doc:readme#parent@folder:public",
		"doc:readme#banned@user:troll",
		"doc:readme#banned@user:spam",
		"doc:readme#owner@user:olga",
		"doc:readme#editor@group:staff#member",
	)
	for _, c := range []struct{ res, perm, subj, want string }{
		{"doc:design", "view", "user", "alice dave"}, // carol sees the folder but is banned
		{"doc:design", "edit", "user", "alice dave"},
		{"doc:design", "both", "user", "alice"},            // dave cannot see the folder
		{"doc:design", "banned", "user", "carol"},          // a relation directly
		{"folder:specs", "view", "user", "alice carol"},    // inherited from root
		{"doc:readme", "view", "user", "*-spam,troll"},     // the wildcard minus the banned
		{"doc:readme", "both", "user", "alice carol olga"}, // editors and owner, all of whom see the public folder
		{"folder:public", "view", "user", "*-"},            // pat is inside the wildcard
		{"doc:nothing", "view", "user", ""},
		{"doc:design", "view", "folder", ""}, // no folder holds a doc permission
		// Usersets: every userset that holds the permission, including
		// the ones only reached through another group.
		{"doc:design", "edit", "group#member", "eng"},
		{"doc:design", "view", "group#member", "eng staff"},
		{"doc:readme", "view", "group#member", "eng staff"}, // staff edit; user:* does not match usersets
		{"group:staff", "member", "group#member", "eng staff"},
		{"folder:specs", "view", "folder#view", "root specs"},
		{"folder:specs", "view", "folder#viewer", "root specs"}, // a userset holds itself
	} {
		for _, limit := range []int{0, 1, 2} {
			if got := f.lookupAll(c.res, c.perm, c.subj, limit); got != c.want {
				t.Errorf("%s#%s %s (limit %d) = %q, want %q", c.res, c.perm, c.subj, limit, got, c.want)
			}
		}
	}
	// Every listed userset is one Check grants, and no other is.
	for _, res := range []string{"doc:design", "doc:readme", "folder:specs", "group:staff"} {
		for _, perm := range []string{"view", "edit", "both", "member", "viewer"} {
			for _, us := range []string{"group#member", "folder#view", "folder#viewer"} {
				r, _, err := f.tryLookupSubjects(res, perm, us, "", 0)
				if err != nil {
					continue // not a permission of this type
				}
				typ, rel, _ := strings.Cut(us, "#")
				for _, id := range []string{"eng", "staff", "root", "specs", "public", "nobody"} {
					if want := f.check(res, perm, typ+":"+id+"#"+rel); holds(r, id) != want {
						t.Errorf("%s#%s %s: lookup %+v holds %s = %v, check %v", res, perm, us, r.Subjects, id, !want, want)
					}
				}
			}
		}
	}
	// What lookup says matches Check, also for subjects no relationship names.
	for _, u := range []string{"alice", "carol", "dave", "olga", "pat", "troll", "spam", "nobody"} {
		for _, res := range []string{"doc:design", "doc:readme"} {
			for _, perm := range []string{"view", "edit", "both"} {
				listed := f.lookupAll(res, perm, "user", 0)
				res2, _, _ := f.tryLookupSubjects(res, perm, "user", "", 0)
				want := f.check(res, perm, "user:"+u)
				got := false
				for _, s := range res2.Subjects {
					if s.ID == u || (s.ID == Wildcard && !contains(s.Excluded, u)) {
						got = true
					}
				}
				if got != want {
					t.Errorf("%s#%s: lookup %q holds %s = %v, check %v", res, perm, listed, u, got, want)
				}
			}
		}
	}
}

func TestLookupSubjectsCycles(t *testing.T) {
	f := newFixture(t, nil,
		"group:a#member@group:b#member",
		"group:b#member@group:c#member",
		"group:c#member@group:a#member",
		"group:a#member@user:ann",
		"group:c#member@user:zed",
		"group:d#member@group:a#member",
		"group:d#member@group:d#member",
		"folder:x#parent@folder:y",
		"folder:y#parent@folder:x",
		"folder:y#viewer@user:yan",
		"folder:x#viewer@group:d#member",
	)
	for _, g := range []string{"a", "b", "c", "d"} {
		if got := f.lookupAll("group:"+g, "member", "user", 0); got != "ann zed" {
			t.Errorf("group %s = %q", g, got)
		}
	}
	if got := f.lookupAll("group:d", "member", "group#member", 0); got != "a b c d" {
		t.Errorf("usersets of d = %q", got)
	}
	for _, fo := range []string{"x", "y"} {
		if got := f.lookupAll("folder:"+fo, "view", "user", 1); got != "ann yan zed" {
			t.Errorf("folder %s = %q", fo, got)
		}
	}
	// A cycle repeats the walk until it settles; the work stays small.
	_, stats, err := f.tryLookupSubjects("folder:x", "view", "user", "", 0)
	if err != nil || stats.Dispatches == 0 || stats.Dispatches > 60 {
		t.Fatalf("cycle took %d dispatches: %v", stats.Dispatches, err)
	}
}

// Without a cycle every node is evaluated once.
func TestLookupSubjectsDispatchesOncePerNode(t *testing.T) {
	f := newFixture(t, nil, "doc:d#viewer@group:g#member", "doc:d#editor@group:g#member", "group:g#member@user:u")
	_, stats, err := f.tryLookupSubjects("doc:d", "view", "user", "", 0)
	// view, viewer, group:g#member, edit, owner, editor, parent arrow has no
	// tupleset node, banned
	if err != nil || stats.Dispatches != 7 {
		t.Fatalf("dispatches %d: %v", stats.Dispatches, err)
	}
}

func TestSubjectSetOperations(t *testing.T) {
	ids := func(s ...string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, x := range s {
			m[x] = struct{}{}
		}
		return m
	}
	show := func(s subjectSet) string {
		var xs []string
		for id := range s.ids {
			xs = append(xs, id)
		}
		sort.Strings(xs)
		if s.all {
			return "*-" + strings.Join(xs, ",")
		}
		return strings.Join(xs, ",")
	}
	none := subjectSet{}
	ab, bc := setOf(false, ids("a", "b")), setOf(false, ids("b", "c"))
	allA, allB := setOf(true, ids("a")), setOf(true, ids("b", "c"))
	for _, c := range []struct {
		name string
		got  subjectSet
		want string
	}{
		{"none+ab", union(none, ab), "a,b"},
		{"ab+none", union(ab, none), "a,b"},
		{"ab+bc", union(ab, bc), "a,b,c"},
		{"*-a + ab", union(allA, ab), "*-"},
		{"bc + *-a", union(bc, allA), "*-a"},
		{"*-a + *-bc", union(allA, allB), "*-"},
		{"*-ab + *-bc", union(setOf(true, ids("a", "b")), allB), "*-b"},
		{"ab & bc", intersect(ab, bc), "b"},
		{"*-a & ab", intersect(allA, ab), "b"},
		{"ab & *-a", intersect(ab, allA), "b"},
		{"*-a & *-bc", intersect(allA, allB), "*-a,b,c"},
		{"none & *-a", intersect(none, allA), ""},
		{"ab - bc", subtract(ab, bc), "a"},
		{"ab - *-a", subtract(ab, allA), "a"},
		{"*-a - bc", subtract(allA, bc), "*-a,b,c"},
		{"*-a - *-bc", subtract(allA, allB), "b,c"},
		{"*-bc - *-a", subtract(allB, allA), "a"},
		{"* - *", subtract(setOf(true, nil), setOf(true, nil)), ""},
	} {
		if got := show(c.got); got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
	// Membership laws on a universe that includes IDs no set names.
	universe := []string{"a", "b", "c", "d"}
	sets := []subjectSet{none, ab, bc, allA, allB, setOf(true, nil)}
	for _, x := range sets {
		for _, y := range sets {
			for _, id := range universe {
				if union(x, y).has(id) != (x.has(id) || y.has(id)) ||
					intersect(x, y).has(id) != (x.has(id) && y.has(id)) ||
					subtract(x, y).has(id) != (x.has(id) && !y.has(id)) {
					t.Fatalf("%s op %s disagrees on %s", show(x), show(y), id)
				}
			}
			if !union(x, y).equal(union(y, x)) || !intersect(x, y).equal(intersect(y, x)) {
				t.Fatalf("%s and %s do not commute", show(x), show(y))
			}
		}
	}
	if ab.equal(bc) || ab.equal(setOf(true, ids("a", "b"))) || ab.equal(setOf(false, ids("a"))) {
		t.Fatal("unequal sets compare equal")
	}
}

func TestLookupSubjectsPaging(t *testing.T) {
	var rels []string
	for i := 0; i < 25; i++ {
		rels = append(rels, fmt.Sprintf("doc:d#viewer@user:u%02d", i))
	}
	f := newFixture(t, nil, rels...)
	res, _, err := f.tryLookupSubjects("doc:d", "view", "user", "", 10)
	if err != nil || len(res.Subjects) != 10 || res.Subjects[0].ID != "u00" || res.Next != "u09" {
		t.Fatalf("first page %+v %v", res, err)
	}
	res, _, _ = f.tryLookupSubjects("doc:d", "view", "user", "u09", 10)
	if len(res.Subjects) != 10 || res.Subjects[0].ID != "u10" || res.Next != "u19" {
		t.Fatalf("second page %+v", res)
	}
	res, _, _ = f.tryLookupSubjects("doc:d", "view", "user", "u19", 10)
	if len(res.Subjects) != 5 || res.Next != "" {
		t.Fatalf("last page %+v", res)
	}
	// Exactly one page's worth ends without a cursor.
	res, _, _ = f.tryLookupSubjects("doc:d", "view", "user", "u14", 10)
	if len(res.Subjects) != 10 || res.Next != "" {
		t.Fatalf("exact page %+v", res)
	}
	// A cursor between IDs, past the end, and the wildcard cursor.
	res, _, _ = f.tryLookupSubjects("doc:d", "view", "user", "u105", 2)
	if len(res.Subjects) != 2 || res.Subjects[0].ID != "u11" {
		t.Fatalf("between IDs %+v", res)
	}
	if res, _, _ = f.tryLookupSubjects("doc:d", "view", "user", "zz", 0); len(res.Subjects) != 0 || res.Next != "" {
		t.Fatalf("past the end %+v", res)
	}
	if res, _, _ = f.tryLookupSubjects("doc:d", "view", "user", Wildcard, 3); len(res.Subjects) != 3 || res.Subjects[0].ID != "u00" {
		t.Fatalf("after the wildcard %+v", res)
	}
	// The limit is capped.
	big := make([]string, 0, MaxLookupLimit+5)
	for i := 0; i < MaxLookupLimit+5; i++ {
		big = append(big, fmt.Sprintf("doc:e#viewer@user:v%04d", i))
	}
	for len(big) > 0 {
		n := min(len(big), 500)
		f.write(big[:n]...)
		big = big[n:]
	}
	if res, _, _ = f.tryLookupSubjects("doc:e", "view", "user", "", MaxLookupLimit*2); len(res.Subjects) != MaxLookupLimit || res.Next == "" {
		t.Fatalf("capped page has %d subjects", len(res.Subjects))
	}
	// A wildcard is one entry; nothing follows it.
	f.write("folder:w#viewer@user:*", "folder:w#viewer@user:a")
	res, _, _ = f.tryLookupSubjects("folder:w", "view", "user", "", 1)
	if len(res.Subjects) != 1 || res.Subjects[0].ID != Wildcard || len(res.Subjects[0].Excluded) != 0 || res.Next != "" {
		t.Fatalf("wildcard page %+v", res)
	}
	if res, _, _ = f.tryLookupSubjects("folder:w", "view", "user", Wildcard, 1); len(res.Subjects) != 0 {
		t.Fatalf("after the wildcard %+v", res)
	}
}

func TestLookupSubjectsErrors(t *testing.T) {
	f := newFixture(t, nil, "doc:a#viewer@user:x")
	sc, _ := f.st.Schema()
	for _, c := range []struct {
		q    LookupSubjectsRequest
		want error
	}{
		{LookupSubjectsRequest{ResourceType: "nope", ResourceID: "a", Permission: "view", SubjectType: "user"}, ErrUnknownType},
		{LookupSubjectsRequest{ResourceType: "doc", ResourceID: "a b", Permission: "view", SubjectType: "user"}, store.ErrInvalid},
		{LookupSubjectsRequest{ResourceType: "doc", ResourceID: "a", Permission: "nope", SubjectType: "user"}, ErrUnknownName},
		{LookupSubjectsRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", SubjectType: "ghost"}, ErrUnknownType},
		{LookupSubjectsRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", SubjectType: "group", SubjectRelation: "nope"}, ErrUnknownName},
		{LookupSubjectsRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", SubjectType: "user", After: "a b"}, store.ErrInvalid},
	} {
		if _, _, err := f.eng.LookupSubjects(context.Background(), sc, f.st.Head(), c.q); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v, want %v", c.q, err, c.want)
		}
	}
	if err := (LookupSubjectsRequest{}).Validate(nil); !errors.Is(err, store.ErrNoSchema) {
		t.Errorf("nil schema: %v", err)
	}
	ok := LookupSubjectsRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", SubjectType: "user"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := f.eng.LookupSubjects(ctx, sc, f.st.Head(), ok); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	if _, _, err := f.eng.LookupSubjects(context.Background(), sc, f.st.Head()+1, ok); !errors.Is(err, store.ErrFutureRevision) {
		t.Errorf("future revision: %v", err)
	}
	f.write("doc:p#parent@folder:f")
	ok.ResourceID = "p"
	if _, _, err := f.eng.LookupSubjects(context.Background(), sc, f.st.Head()-1, ok); err != nil {
		t.Errorf("older revision: %v", err)
	}
	// An arrow reads the tupleset at the revision too.
	sub := &futureAfter{Reader: f.st, n: 1}
	e := New(sub, nil)
	if _, _, err := e.LookupSubjects(context.Background(), sc, f.st.Head(), ok); !errors.Is(err, store.ErrFutureRevision) {
		t.Errorf("failing tupleset read: %v", err)
	}
	sub = &futureAfter{Reader: f.st, n: 0}
	if _, _, err := New(sub, nil).LookupSubjects(context.Background(), sc, f.st.Head(),
		LookupSubjectsRequest{ResourceType: "doc", ResourceID: "p", Permission: "both", SubjectType: "user"}); !errors.Is(err, store.ErrFutureRevision) {
		t.Errorf("failing first read: %v", err)
	}
	f.write("doc:q#viewer@group:g#member", "group:g#member@user:x")
	for n := 0; n < 4; n++ {
		if _, _, err := New(&futureAfter{Reader: f.st, n: n}, nil).LookupSubjects(context.Background(), sc, f.st.Head(),
			LookupSubjectsRequest{ResourceType: "doc", ResourceID: "q", Permission: "view", SubjectType: "user"}); !errors.Is(err, store.ErrFutureRevision) {
			t.Errorf("read %d failing: %v", n, err)
		}
	}
}

// futureAfter answers n reads and then fails every read as a future
// revision, to reach each read's error path.
type futureAfter struct {
	Reader
	n int
}

func (r *futureAfter) ReadDirect(rev store.Revision, typ, id, rel string) ([]store.Relationship, error) {
	if r.n == 0 {
		return nil, store.ErrFutureRevision
	}
	r.n--
	return r.Reader.ReadDirect(rev, typ, id, rel)
}

func TestLookupSubjectsDepthLimit(t *testing.T) {
	var rels []string
	n := DefaultMaxDepth + 5
	for i := 0; i < n; i++ {
		rels = append(rels, fmt.Sprintf("group:g%d#member@group:g%d#member", i, i+1))
	}
	rels = append(rels, fmt.Sprintf("group:g%d#member@user:deep", n))
	f := newFixture(t, nil, rels...)
	if _, _, err := f.tryLookupSubjects("group:g0", "member", "user", "", 0); !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("deep chain: %v", err)
	}
	if got := f.lookupAll(fmt.Sprintf("group:g%d", n-10), "member", "user", 0); got != "deep" {
		t.Fatalf("chain within the limit = %q", got)
	}
}

// A cycle through the subtracted side of an exclusion has no least
// fixpoint: the walk alternates and the work limit ends it.
func TestLookupSubjectsCycleThroughExclusion(t *testing.T) {
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.WriteSchema(`
definition user {}
definition node {
  relation next: node
  relation base: user
  permission p = base - next->p
}`); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: st, eng: New(st, nil)}
	f.write("node:a#next@node:a", "node:a#base@user:u", "node:b#base@user:u", "node:b#next@node:c")
	if _, stats, err := f.tryLookupSubjects("node:a", "p", "user", "", 0); !errors.Is(err, ErrTooMuchWork) || stats.Dispatches <= MaxDispatchesPerCheck {
		t.Fatalf("oscillating cycle: %v after %d dispatches", err, stats.Dispatches)
	}
	// Without the cycle the exclusion is answered.
	if got := f.lookupAll("node:b", "p", "user", 0); got != "u" {
		t.Fatalf("node b = %q", got)
	}
}

func TestLookupSubjectsOldSnapshotAfterSchemaChange(t *testing.T) {
	f := newFixture(t, nil, "group:eng#member@user:a", "doc:d#viewer@group:eng#member", "doc:d#viewer@user:b",
		"doc:d#parent@folder:f", "folder:f#viewer@user:c")
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
	res, _, err := f.eng.LookupSubjects(context.Background(), sc, old, LookupSubjectsRequest{ResourceType: "doc", ResourceID: "d", Permission: "view", SubjectType: "user"})
	if err != nil || len(res.Subjects) != 2 || res.Subjects[0].ID != "b" || res.Subjects[1].ID != "c" {
		t.Fatalf("old snapshot: %+v %v", res, err)
	}
	// An arrow to a type the schema no longer has grants nothing either.
	for _, r := range []string{"doc:d#parent@folder:f", "folder:f#viewer@user:c"} {
		rel, _ := store.ParseRelationship(r)
		if _, err := f.st.Write([]store.Update{{Op: store.OpDelete, Relationship: rel}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	noFolders := strings.Replace(strings.Replace(strings.Replace(noGroups, "definition folder {\n  relation parent: folder\n  relation viewer: user | user:*\n  permission view = viewer + parent->view\n}", "", 1),
		"  relation parent: folder\n  relation owner", "  relation parent: doc\n  relation owner", 1), "parent->view", "parent->owner", -1)
	if _, err := f.st.WriteSchema(noFolders); err != nil {
		t.Fatal(err)
	}
	sc, _ = f.st.Schema()
	res, _, err = f.eng.LookupSubjects(context.Background(), sc, old, LookupSubjectsRequest{ResourceType: "doc", ResourceID: "d", Permission: "view", SubjectType: "user"})
	if err != nil || len(res.Subjects) != 1 || res.Subjects[0].ID != "b" {
		t.Fatalf("old snapshot through a removed arrow target: %+v %v", res, err)
	}
}

// holds reads a lookup result as membership.
func holds(res LookupSubjectsResult, id string) bool {
	for _, s := range res.Subjects {
		if s.ID == id || (s.ID == Wildcard && !contains(s.Excluded, id)) {
			return true
		}
	}
	return false
}

func TestLookupSubjectsMatchesReferenceOnRandomGraphs(t *testing.T) {
	iterations := 60
	if testing.Short() {
		iterations = 10
	}
	for seed := int64(0); seed < int64(iterations); seed++ {
		rng := rand.New(rand.NewSource(seed))
		nusers, groups, folders, docs := 6, 2+rng.Intn(6), 2+rng.Intn(6), 8
		w := randomWorld(rng, nusers, groups, folders, docs)
		// Wildcards with exclusions: some docs are public and ban someone.
		for d := 0; d < docs; d += 3 {
			id := fmt.Sprintf("d%d", d)
			w.rels = append(w.rels, fmt.Sprintf("doc:%s#parent@folder:pub", id))
			w.docParent[id] = append(w.docParent[id], "pub")
		}
		w.rels = append(w.rels, "folder:pub#viewer@user:*")
		w.folderPublic["pub"] = true
		ref := buildReference(w, nusers)
		f := newFixture(t, nil, w.rels...)
		users := []string{"nobody"} // named by no relationship
		for u := 0; u < nusers; u++ {
			users = append(users, fmt.Sprintf("u%d", u))
		}
		limit := 1 + rng.Intn(4)
		compare := func(res, perm string, want func(u string) bool) {
			t.Helper()
			full, _, err := f.tryLookupSubjects(res, perm, "user", "", MaxLookupLimit)
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range users {
				if got := holds(full, u); got != want(u) {
					t.Fatalf("seed %d: %s#%s holds %s: lookup %v, reference %v\nrelationships:\n%s",
						seed, res, perm, u, got, want(u), strings.Join(w.rels, "\n"))
				}
			}
			for _, s := range full.Subjects {
				if s.ID != Wildcard && !contains(users, s.ID) {
					t.Fatalf("seed %d: %s#%s lists unknown %s", seed, res, perm, s.ID)
				}
			}
			// Small pages add up to the whole list.
			var whole []string
			for _, s := range full.Subjects {
				if s.ID == Wildcard {
					whole = append(whole, "*-"+strings.Join(s.Excluded, ","))
				} else {
					whole = append(whole, s.ID)
				}
			}
			if paged := f.lookupAll(res, perm, "user", limit); paged != strings.Join(whole, " ") {
				t.Fatalf("seed %d: %s#%s paged by %d %q, whole %q", seed, res, perm, limit, paged, whole)
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
		// Usersets: the groups whose members hold a doc permission are
		// exactly those Check grants it to as group:g#member.
		for d := 0; d < docs; d++ {
			res := fmt.Sprintf("doc:d%d", d)
			for _, perm := range []string{"view", "edit", "both"} {
				got, _, err := f.tryLookupSubjects(res, perm, "group#member", "", MaxLookupLimit)
				if err != nil {
					t.Fatal(err)
				}
				for g := 0; g < groups; g++ {
					id := fmt.Sprintf("g%d", g)
					if want := f.check(res, perm, "group:"+id+"#member"); holds(got, id) != want {
						t.Fatalf("seed %d: %s#%s userset group:%s#member: lookup %v, check %v", seed, res, perm, id, !want, want)
					}
				}
			}
		}
	}
}

func BenchmarkLookupSubjectsDeepFolders(b *testing.B) {
	for _, depth := range []int{1, 10, 40} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			f, q, sc := benchFixture(b, depth, 20, nil)
			lq := LookupSubjectsRequest{ResourceType: q.ResourceType, ResourceID: q.ResourceID, Permission: q.Permission, SubjectType: "user", Limit: MaxLookupLimit}
			rev := f.st.Head()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if res, _, err := f.eng.LookupSubjects(context.Background(), sc, rev, lq); err != nil || len(res.Subjects) != depth*20+1 {
					b.Fatal(len(res.Subjects), err)
				}
			}
		})
	}
}
