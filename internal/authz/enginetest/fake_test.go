package enginetest

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

// blockingSchema subtracts a recursive permission: blocks climbs the same
// folder tree as view, so the fake's handling of exclusion over a fixpoint
// is exercised, not only over stored relations.
const blockingSchema = `
definition user {}

definition team {
  relation member: user | team#member
}

definition folder {
  relation parent: folder
  relation viewer: user | user:* | team#member
  relation blocked: user | team#member
  permission blocks = blocked + parent->blocks
  permission view = (viewer + parent->view) - blocks
}

definition doc {
  relation parent: folder
  relation owner: user | team#member
  relation auditor: user
  permission view = parent->view + owner
  permission audit = auditor & parent->view
  permission active = owner - parent->blocks
  permission either = owner & (auditor + parent->view)
  permission strict = owner - (auditor - parent->blocks)
}
`

func blockingGraph(rng *rand.Rand) []string {
	users, teams, folders, docs := 5, 3, 5, 5
	u := func() string { return fmt.Sprintf("user:u%d", rng.Intn(users)) }
	tm := func() string { return fmt.Sprintf("team:t%d#member", rng.Intn(teams)) }
	fo := func() string { return fmt.Sprintf("folder:f%d", rng.Intn(folders)) }
	seen := map[string]bool{}
	var rels []string
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			rels = append(rels, r)
		}
	}
	for i := 0; i < teams; i++ {
		add(fmt.Sprintf("team:t%d#member@%s", rng.Intn(teams), u()))
		if rng.Intn(2) == 0 {
			add(fmt.Sprintf("team:t%d#member@%s", rng.Intn(teams), tm()))
		}
	}
	for i := 0; i < folders*2; i++ {
		switch rng.Intn(6) {
		case 0, 1:
			add(fo() + "#parent@" + fo())
		case 2:
			add(fo() + "#viewer@" + u())
		case 3:
			add(fo() + "#viewer@" + tm())
		case 4:
			add(fo() + "#blocked@" + u())
		case 5:
			if rng.Intn(3) == 0 {
				add(fo() + "#viewer@user:*")
			} else {
				add(fo() + "#blocked@" + tm())
			}
		}
	}
	for i := 0; i < docs*2; i++ {
		d := fmt.Sprintf("doc:d%d", rng.Intn(docs))
		switch rng.Intn(4) {
		case 0:
			add(d + "#parent@" + fo())
		case 1:
			add(d + "#owner@" + u())
		case 2:
			add(d + "#owner@" + tm())
		case 3:
			add(d + "#auditor@" + u())
		}
	}
	return rels
}

// The fake and the real engine, given the same writes, return equal
// results for every query at every revision: the same answers, pages,
// cursors, trees, revisions and tokens.
func TestFakeMatchesLocal(t *testing.T) {
	seeds := 8
	if testing.Short() {
		seeds = 3
	}
	for seed := int64(0); seed < int64(seeds); seed++ {
		for name, src := range map[string]string{"sharing": SharingSchema, "blocking": blockingSchema} {
			t.Run(fmt.Sprintf("%s/%d", name, seed), func(t *testing.T) {
				t.Parallel()
				rng := rand.New(rand.NewSource(seed))
				fake, err := NewFake(src)
				if err != nil {
					t.Fatal(err)
				}
				local := NewLocal(t, src, engine.Options{CacheSize: 1000})
				var rels []string
				if src == SharingSchema {
					rels = randomGraph(seed)
				} else {
					rels = blockingGraph(rng)
				}
				sf, sl := touch(t, fake, rels...), touch(t, local, rels...)
				agree(t, "write", sf, sl)
				compareAll(t, fake, local, sf, seed)
				// Then change the graph: delete some of it, one way or the other.
				var res [2]any
				if rng.Intn(2) == 0 {
					f := store.Filter{ResourceType: "folder"}
					a, errA := fake.DeleteRelationships(bg, engine.DeleteRequest{Filter: f, Limit: 3, AllowPartial: true})
					b, errB := local.DeleteRelationships(bg, engine.DeleteRequest{Filter: f, Limit: 3, AllowPartial: true})
					res = [2]any{fmt.Sprint(a, errA), fmt.Sprint(b, errB)}
					sf, sl = a.At, b.At
				} else {
					var ups []store.Update
					for i, r := range rels {
						if i%3 == 0 {
							ups = append(ups, store.Update{Op: store.OpDelete, Relationship: relationship(t, r)})
						}
					}
					a, errA := fake.Write(bg, engine.WriteRequest{Updates: ups})
					b, errB := local.Write(bg, engine.WriteRequest{Updates: ups})
					res = [2]any{fmt.Sprint(a, errA), fmt.Sprint(b, errB)}
					sf, sl = a.At, b.At
				}
				agree(t, "change", res[0], res[1])
				agree(t, "change snapshot", sf, sl)
				compareAll(t, fake, local, sf, seed)
			})
		}
	}
}

func agree(t *testing.T, what string, fake, local any) {
	t.Helper()
	if !reflect.DeepEqual(fake, local) {
		t.Fatalf("%s:\nfake  %+v\nlocal %+v", what, fake, local)
	}
}

// compareAll asks both engines everything at snapshot s.
func compareAll(t *testing.T, fake *Fake, local *engine.Local, s engine.Snapshot, seed int64) {
	t.Helper()
	sc := fake.Schema()
	cons := exact(s)
	var subjects []store.Subject
	for _, typ := range sc.Order {
		for i := 0; i < 6; i++ {
			subjects = append(subjects, store.Subject{Type: typ, ID: fmt.Sprintf("%c%d", typ[0], i)})
		}
	}
	subjects = append(subjects, store.Subject{Type: "user", ID: "nobody"})
	for _, g := range []string{"group", "team"} {
		if d, ok := sc.Defs[g]; ok && d.Has("member") {
			for i := 0; i < 4; i++ {
				subjects = append(subjects, store.Subject{Type: g, ID: fmt.Sprintf("%c%d", g[0], i), Relation: "member"})
			}
		}
	}
	for _, typ := range sc.Order {
		d := sc.Defs[typ]
		for _, perm := range d.Order {
			for _, sub := range subjects {
				for _, limit := range []int{1, 0} {
					req := engine.LookupResourcesRequest{ResourceType: typ, Permission: perm, Subject: sub, Consistency: cons, Limit: limit}
					for pages := 0; pages < 20; pages++ {
						a, errA := fake.LookupResources(bg, req)
						b, errB := local.LookupResources(bg, req)
						agree(t, fmt.Sprintf("seed %d: lookup %s#%s for %s after %q", seed, typ, perm, sub, req.Cursor), fmt.Sprint(a, errA), fmt.Sprint(b, errB))
						if a.Cursor == "" {
							break
						}
						req.Cursor = a.Cursor
					}
				}
			}
			for i := 0; i < 6; i++ {
				id := fmt.Sprintf("%c%d", typ[0], i)
				for _, sub := range subjects {
					req := engine.CheckRequest{ResourceType: typ, ResourceID: id, Permission: perm, Subject: sub, Consistency: cons}
					a, errA := fake.Check(bg, req)
					b, errB := local.Check(bg, req)
					agree(t, fmt.Sprintf("seed %d: check %s:%s#%s for %s", seed, typ, id, perm, sub), fmt.Sprint(a, errA), fmt.Sprint(b, errB))
				}
				for _, st := range sc.Order {
					rels := []string{""} // users, and the usersets the schemas store
					if sc.Defs[st].Has("member") {
						rels = append(rels, "member")
					}
					for _, sr := range rels {
						for _, limit := range []int{1, 0} {
							req := engine.LookupSubjectsRequest{ResourceType: typ, ResourceID: id, Permission: perm,
								SubjectType: st, SubjectRelation: sr, Consistency: cons, Limit: limit}
							for pages := 0; pages < 20; pages++ {
								a, errA := fake.LookupSubjects(bg, req)
								b, errB := local.LookupSubjects(bg, req)
								agree(t, fmt.Sprintf("seed %d: lookup subjects %s:%s#%s of %s#%s after %q", seed, typ, id, perm, st, sr, req.Cursor),
									fmt.Sprint(a, errA), fmt.Sprint(b, errB))
								if a.Cursor == "" {
									break
								}
								req.Cursor = a.Cursor
							}
						}
					}
				}
				for _, recursive := range []bool{false, true} {
					for _, max := range []int{0, 1, 3, 8} {
						req := engine.ExpandRequest{ResourceType: typ, ResourceID: id, Permission: perm, Recursive: recursive, MaxNodes: max, Consistency: cons}
						a, errA := fake.Expand(bg, req)
						b, errB := local.Expand(bg, req)
						if (errA == nil) != (errB == nil) || (errA != nil && errA.Error() != errB.Error()) {
							t.Fatalf("seed %d: expand %+v: fake %v, local %v", seed, req, errA, errB)
						}
						if errA == nil {
							agree(t, fmt.Sprintf("seed %d: expand %+v", seed, req), a, b)
						}
					}
				}
			}
		}
		for _, limit := range []int{1, 3, 0} {
			req := engine.ReadRequest{Filter: store.Filter{ResourceType: typ}, Consistency: cons, Limit: limit}
			for pages := 0; pages < 100; pages++ {
				a, errA := fake.ReadRelationships(bg, req)
				b, errB := local.ReadRelationships(bg, req)
				agree(t, fmt.Sprintf("seed %d: read %s", seed, typ), fmt.Sprint(a, errA), fmt.Sprint(b, errB))
				if a.Cursor == "" {
					break
				}
				req.Cursor = a.Cursor
			}
		}
	}
}

// A cycle through the subtracted side of an exclusion has no stable
// answer: the fake says so instead of picking one.
func TestFakeUnstratified(t *testing.T) {
	src := `
definition user {}
definition node {
  relation link: node
  relation base: user
  permission p = base - link->p
}`
	f, err := NewFake(src, "node:a#base@user:u", "node:a#link@node:b", "node:b#base@user:u", "node:b#link@node:a")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Check(bg, engine.CheckRequest{ResourceType: "node", ResourceID: "a", Permission: "p", Subject: store.Subject{Type: "user", ID: "u"}})
	wantErr(t, "even cycle through an exclusion", err, check.ErrTooMuchWork)
	_, err = f.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "node", ResourceID: "a", Permission: "p", SubjectType: "user"})
	wantErr(t, "lookup subjects", err, check.ErrTooMuchWork)
	_, err = f.LookupResources(bg, engine.LookupResourcesRequest{ResourceType: "node", Permission: "p", Subject: store.Subject{Type: "user", ID: "u"}})
	wantErr(t, "lookup resources", err, check.ErrTooMuchWork)
	_, err = f.CheckBulk(bg, engine.CheckBulkRequest{Items: []engine.CheckItem{{ResourceType: "node", ResourceID: "a", Permission: "p", Subject: store.Subject{Type: "user", ID: "u"}}}})
	if err != nil {
		t.Fatal(err)
	}
	// A chain that ends is stratified by the data: c has no link, so
	// p(c) holds, p(b) does not and p(a) does.
	f, err = NewFake(src, "node:a#base@user:u", "node:a#link@node:b", "node:b#base@user:u", "node:b#link@node:c", "node:c#base@user:u")
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"a": true, "b": false, "c": true} {
		if got := allowed(t, f, engine.Consistency{}, "node:"+id+"#p", "user:u"); got != want {
			t.Errorf("p(%s) = %v, want %v", id, got, want)
		}
	}
}

func TestFakeFailAndExpire(t *testing.T) {
	f, err := NewFake(SharingSchema, SharingRelationships...)
	if err != nil {
		t.Fatal(err)
	}
	if f.Head() != 2 {
		t.Fatalf("head %d, want 2 (the schema, then the relationships)", f.Head())
	}
	old, err := f.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: store.Subject{Type: "user", ID: "alice"}})
	if err != nil || !old.Allowed {
		t.Fatalf("check: %+v, %v", old, err)
	}
	f.Fail(store.ErrUnavailable)
	alice := store.Subject{Type: "user", ID: "alice"}
	for name, call := range map[string]func() error{
		"Check": func() error {
			_, err := f.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: alice})
			return err
		},
		"CheckBulk": func() error { _, err := f.CheckBulk(bg, engine.CheckBulkRequest{}); return err },
		"LookupResources": func() error {
			_, err := f.LookupResources(bg, engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: alice})
			return err
		},
		"LookupSubjects": func() error {
			_, err := f.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", SubjectType: "user"})
			return err
		},
		"Expand": func() error {
			_, err := f.Expand(bg, engine.ExpandRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view"})
			return err
		},
		"ReadRelationships": func() error {
			_, err := f.ReadRelationships(bg, engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}})
			return err
		},
		"Write": func() error {
			_, err := f.Write(bg, engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#owner@user:a")}})
			return err
		},
		"DeleteRelationships": func() error {
			_, err := f.DeleteRelationships(bg, engine.DeleteRequest{Filter: store.Filter{ResourceType: "doc"}, AllowPartial: true})
			return err
		},
	} {
		wantErr(t, name, call(), store.ErrUnavailable)
	}
	f.Fail(nil)
	if f.Head() != 2 {
		t.Fatalf("failed calls changed the head to %d", f.Head())
	}

	w, err := f.Write(bg, engine.WriteRequest{Updates: []store.Update{update(t, store.OpDelete, "group:eng#member@user:alice")}})
	if err != nil {
		t.Fatal(err)
	}
	f.ExpireBefore(w.At.Revision + 100) // capped at the head
	sub := store.Subject{Type: "user", ID: "alice"}
	reads := map[string]func(engine.Consistency) error{
		"Check": func(c engine.Consistency) error {
			_, err := f.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: sub, Consistency: c})
			return err
		},
		"CheckBulk": func(c engine.Consistency) error {
			_, err := f.CheckBulk(bg, engine.CheckBulkRequest{Consistency: c, Items: []engine.CheckItem{{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: sub}}})
			return err
		},
		"LookupResources": func(c engine.Consistency) error {
			_, err := f.LookupResources(bg, engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: sub, Consistency: c})
			return err
		},
		"LookupSubjects": func(c engine.Consistency) error {
			_, err := f.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", SubjectType: "user", Consistency: c})
			return err
		},
		"Expand": func(c engine.Consistency) error {
			_, err := f.Expand(bg, engine.ExpandRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Consistency: c})
			return err
		},
		"ReadRelationships": func(c engine.Consistency) error {
			_, err := f.ReadRelationships(bg, engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Consistency: c})
			return err
		},
	}
	for name, read := range reads {
		wantErr(t, name+" at an expired snapshot", read(exact(old.At)), store.ErrSnapshotExpired)
		if err := read(fresh(old.At)); err != nil {
			t.Errorf("%s at least as fresh as an expired snapshot: %v", name, err)
		}
		if err := read(exact(w.At)); err != nil {
			t.Errorf("%s at the head: %v", name, err)
		}
	}
	f.ExpireBefore(1) // never moves back
	wantErr(t, "after a lower expiry", reads["Check"](exact(old.At)), store.ErrSnapshotExpired)
}

func TestNewFake(t *testing.T) {
	_, err := NewFake("definition {")
	wantErr(t, "bad schema", err, store.ErrInvalid)
	_, err = NewFake(SharingSchema, "doc:plan#viewer")
	wantErr(t, "bad relationship", err, store.ErrInvalid)
	_, err = NewFake(SharingSchema, "doc:plan#view@user:alice")
	wantErr(t, "relationship to a permission", err, store.ErrInvalid)

	// Two fakes with the same history issue the same tokens, and accept
	// each other's.
	a, _ := NewFake(SharingSchema, SharingRelationships...)
	b, _ := NewFake(SharingSchema, SharingRelationships...)
	ra, _ := a.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: store.Subject{Type: "user", ID: "alice"}})
	rb, err := b.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
		Subject: store.Subject{Type: "user", ID: "alice"}, Consistency: exact(ra.At)})
	if err != nil || ra != rb {
		t.Fatalf("fakes differ: %+v and %+v, %v", ra, rb, err)
	}
	if rev, err := a.Tokens().Decode(ra.At.Token); err != nil || rev != ra.At.Revision {
		t.Fatalf("token decodes to %d, %v", rev, err)
	}
	other, _ := token.NewIssuer(make([]byte, token.KeySize))
	_, err = a.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
		Subject: store.Subject{Type: "user", ID: "alice"}, Consistency: engine.Consistency{Mode: engine.AtExactSnapshot, Token: other.Encode(1)}})
	wantErr(t, "a token under another key", err, token.ErrInvalid)

	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := NewFake(SharingSchema); err != nil {
		t.Fatal(err)
	}
	_, err = a.CheckBulk(ctx, engine.CheckBulkRequest{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled empty bulk: %v", err)
	}
}

// countdown is a context that ends after a number of Err calls, so a test
// can cancel a query part way through, deterministically.
type countdown struct {
	context.Context
	left int
}

func (c *countdown) Err() error {
	if c.left <= 0 {
		return context.Canceled
	}
	c.left--
	return nil
}

func chain(n int) []string {
	rels := []string{fmt.Sprintf("folder:f%d#viewer@user:end", n)}
	for i := 0; i < n; i++ {
		rels = append(rels, fmt.Sprintf("folder:f%d#parent@folder:f%d", i, i+1))
	}
	return rels
}

func TestFakeLimits(t *testing.T) {
	// A chain deeper than the real engine's depth limit: expand fails the
	// same way in both, and the fake's check still answers.
	deep := chain(check.DefaultMaxDepth + 5)
	f, err := NewFake(SharingSchema, deep...)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLocal(t, SharingSchema, engine.Options{}, deep...)
	req := engine.ExpandRequest{ResourceType: "folder", ResourceID: "f0", Permission: "view", Recursive: true, MaxNodes: check.MaxTraceNodes}
	_, errF := f.Expand(bg, req)
	_, errL := l.Expand(bg, req)
	wantErr(t, "fake expand of a deep chain", errF, check.ErrDepthExceeded)
	wantErr(t, "local expand of a deep chain", errL, check.ErrDepthExceeded)
	if !allowed(t, f, engine.Consistency{}, "folder:f0#view", "user:end") {
		t.Fatal("the fake denies the end of a deep chain")
	}

	// Cancelled part way through a solve and part way through a tree.
	sub := store.Subject{Type: "user", ID: "end"}
	_, err = f.Check(&countdown{Context: bg, left: 2}, engine.CheckRequest{ResourceType: "folder", ResourceID: "f0", Permission: "view", Subject: sub})
	wantErr(t, "check cancelled while solving", err, context.Canceled)
	_, err = f.Expand(&countdown{Context: bg, left: 5}, engine.ExpandRequest{ResourceType: "folder", ResourceID: "f0", Permission: "view", Recursive: true})
	wantErr(t, "expand cancelled while building", err, context.Canceled)

	// A chain long enough that solving it passes MaxFakeWork.
	long := chain(1100)
	f, err = NewFake(SharingSchema, long[:900]...)
	if err != nil {
		t.Fatal(err)
	}
	touch(t, f, long[900:]...)
	_, err = f.Check(bg, engine.CheckRequest{ResourceType: "folder", ResourceID: "f0", Permission: "view", Subject: sub})
	wantErr(t, "check of a very long chain", err, check.ErrTooMuchWork)
	_, err = f.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "folder", ResourceID: "f0", Permission: "view", SubjectType: "user"})
	wantErr(t, "lookup subjects of a very long chain", err, check.ErrTooMuchWork)
}
