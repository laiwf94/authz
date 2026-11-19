package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

// lookupAllSubjects pages through a subject lookup, limit at a time.
func (f *caveatFixture) lookupAllSubjects(rev store.Revision, resource, perm, subjectType string, ctx map[string]any, limit int) ([]FoundSubject, Stats, error) {
	f.t.Helper()
	rt, rid, _ := strings.Cut(resource, ":")
	st, sr, _ := strings.Cut(subjectType, "#")
	var all []FoundSubject
	var stats Stats
	after := ""
	for range 1000 {
		res, s, err := f.eng.LookupSubjects(context.Background(), f.sc, rev, LookupSubjectsRequest{ResourceType: rt, ResourceID: rid,
			Permission: perm, SubjectType: st, SubjectRelation: sr, After: after, Limit: limit, Context: ctx})
		stats.Dispatches += s.Dispatches
		stats.Caveats += s.Caveats
		if err != nil {
			return nil, stats, err
		}
		if len(res.Subjects) > limit && limit > 0 {
			f.t.Fatalf("page of %d over limit %d", len(res.Subjects), limit)
		}
		all = append(all, res.Subjects...)
		if res.Next == "" {
			return all, stats, nil
		}
		after = res.Next
	}
	f.t.Fatal("paging does not end")
	return nil, stats, nil
}

// answerFor is the answer a subject lookup's list gives id: its own entry,
// else the wildcard's unless the wildcard excludes it, else denied.
func answerFor(found []FoundSubject, id string) Result {
	res := func(f FoundSubject) Result {
		if f.Conditional {
			return Result{Permissionship: Conditional, Missing: f.Missing}
		}
		return allowed
	}
	for _, f := range found {
		if f.ID == id {
			return res(f)
		}
	}
	if len(found) > 0 && found[0].ID == Wildcard && !slices.Contains(found[0].Excluded, id) {
		return res(found[0])
	}
	return denied
}

func showFound(found []FoundSubject) string {
	var parts []string
	for _, f := range found {
		s := f.ID
		if len(f.Excluded) > 0 {
			s += "-" + strings.Join(f.Excluded, ",")
		}
		if f.Conditional {
			s += fmt.Sprintf("?%v", f.Missing)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func jsonContext(t testing.TB, s string) map[string]any {
	t.Helper()
	if s == "" {
		return nil
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLookupSubjectsCaveats(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("doc:d#viewer@user:a", "")
	f.write("doc:d#viewer@user:b", "ip_allowed")
	f.write("doc:d#viewer@user:*", "flag")
	f.write("doc:d#banned@user:c", `flag {"on":true}`)
	f.write("doc:d#banned@user:e", "flag")
	f.write("group:g#member@user:s", "on_shift")
	f.write("doc:d#viewer@group:g#member", "")
	f.write("doc:d#viewer@user:x", `ip_allowed {"allowed":"10.0.0.0/8","client_ip":"10.1.2.3"}`)
	f.write("doc:d#viewer@user:y", `ip_allowed {"allowed":"10.0.0.0/8","client_ip":"8.8.8.8"}`)
	rev := f.st.Head()
	for _, c := range []struct{ perm, ctx, want string }{
		// The wildcard is conditional on flag's on; b and s depend on more,
		// a and x are allowed outright, c is banned outright, y's caveat
		// fails but the wildcard may still grant y. e is banned and granted on the same unknown flag: and(on, not on)
		// is conditional on it, which is the wildcard's own answer.
		{"view", "", "*-a,b,c,s,x?[on] a b?[allowed client_ip on] s?[hour on shift_end shift_start] x"},
		// With on set the wildcard grants everyone but the banned: a, b,
		// s and x hold it like everyone else.
		{"view", `{"on":true}`, "*-c,e"},
		{"view", `{"on":false}`, "a b?[allowed client_ip] s?[hour shift_end shift_start] x"},
		{"view", `{"on":false,"hour":10,"shift_start":9,"shift_end":17,"allowed":"10.0.0.0/8","client_ip":"10.0.0.1"}`, "a b s x"},
		{"viewer", "", "*-a,b,s,x?[on] a b?[allowed client_ip on] s?[hour on shift_end shift_start] x"},
		{"banned", "", "c e?[on]"},
		{"banned", `{"on":false}`, "c"},
	} {
		got, _, err := f.lookupAllSubjects(rev, "doc:d", c.perm, "user", jsonContext(t, c.ctx), 0)
		if err != nil || showFound(got) != c.want {
			t.Errorf("%s %s:\n got %s (%v)\nwant %s", c.perm, c.ctx, showFound(got), err, c.want)
		}
		// Paging one at a time lists the same.
		paged, _, err := f.lookupAllSubjects(rev, "doc:d", c.perm, "user", jsonContext(t, c.ctx), 1)
		if err != nil || !reflect.DeepEqual(paged, got) {
			t.Errorf("%s %s one at a time: %s (%v)", c.perm, c.ctx, showFound(paged), err)
		}
	}
	// Usersets: doc:d#viewer lists group:g#member without a caveat.
	got, _, err := f.lookupAllSubjects(rev, "doc:d", "view", "group#member", nil, 0)
	if err != nil || showFound(got) != "g" {
		t.Fatalf("usersets: %s %v", showFound(got), err)
	}
	// Errors: a caveat that fails at run time, a context that does not
	// encode, and one too large.
	f.write("doc:o#odd@user:u", `boom {"m":{"k":1}}`)
	if _, _, err := f.lookupAllSubjects(f.st.Head(), "doc:o", "strange", "user", nil, 0); !errors.Is(err, ErrCaveat) {
		t.Fatalf("boom: %v", err)
	}
	if _, _, err := f.lookupAllSubjects(rev, "doc:d", "view", "user", map[string]any{"f": func() {}}, 0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad context: %v", err)
	}
	if _, _, err := f.lookupAllSubjects(rev, "doc:d", "view", "user", map[string]any{"s": strings.Repeat("x", MaxContextSize)}, 0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("big context: %v", err)
	}
	// The caveats of one lookup share the per-check cost budget: enough
	// caveated relationships that their caveats together cost more.
	_, one, err := f.lookupAllSubjects(rev, "doc:d", "view", "user", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.write("doc:x#odd@user:u", `costly {"n":1}`)
	_, st, err := f.result("doc:x", "strange", "user:u", "")
	if err != nil || st.Caveats != 1 || one.Caveats == 0 {
		t.Fatalf("%+v %+v %v", st, one, err)
	}
	n := MaxCaveatCostPerCheck/st.CaveatCost + 1
	for lo := 0; lo < n; lo += store.MaxUpdatesPerWrite {
		var ups []store.Update
		for i := lo; i < min(n, lo+store.MaxUpdatesPerWrite); i++ {
			ups = append(ups, store.Update{Op: store.OpTouch, Relationship: store.Relationship{ResourceType: "doc", ResourceID: "c", Relation: "odd",
				SubjectType: "user", SubjectID: fmt.Sprint("u", i)}, Caveat: &store.Caveat{Name: "costly", Context: map[string]any{"n": 1}}})
		}
		if _, err := f.st.Write(ups, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.lookupAllSubjects(f.st.Head(), "doc:c", "strange", "user", nil, 0); !errors.Is(err, ErrTooMuchWork) {
		t.Fatalf("%d costly caveats: %v", n, err)
	}
}

// A caveated member on a cycle is found as conditional, and its caveat is
// evaluated once however many rounds the fixpoint takes.
func TestLookupSubjectsCaveatOnCycle(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("group:a#member@group:b#member", "")
	f.write("group:b#member@group:c#member", "")
	f.write("group:c#member@group:a#member", "")
	f.write("group:c#member@user:u", `on_shift {"shift_start":9,"shift_end":17}`)
	f.write("group:b#member@user:v", "")
	for _, g := range []string{"a", "b", "c"} {
		got, st, err := f.lookupAllSubjects(f.st.Head(), "group:"+g, "member", "user", nil, 0)
		if err != nil || showFound(got) != "u?[hour] v" || st.Caveats != 1 {
			t.Fatalf("group %s: %s %+v %v", g, showFound(got), st, err)
		}
		got, _, err = f.lookupAllSubjects(f.st.Head(), "group:"+g, "member", "user", map[string]any{"hour": 8}, 0)
		if err != nil || showFound(got) != "v" {
			t.Fatalf("group %s at 8: %s %v", g, showFound(got), err)
		}
	}
}

// writeRandomCaveatGraph fills f with a random graph of caveated and plain
// relationships over the caveat model: groups in groups (cycles
// included), docs with users, wildcards, groups, bans, editors and parent
// folders.
func writeRandomCaveatGraph(f *caveatFixture, seed int64, users []string) {
	rng := rand.New(rand.NewSource(seed))
	cavs := []string{"", "flag", `flag {"on":true}`, `flag {"on":false}`}
	shift := []string{"", "on_shift", `on_shift {"shift_start":9,"shift_end":17}`}
	for i := range 150 {
		u := users[rng.Intn(len(users))]
		g, h := fmt.Sprint("g", rng.Intn(5)), fmt.Sprint("g", rng.Intn(5))
		d := fmt.Sprint("d", rng.Intn(4))
		switch i % 8 {
		case 0:
			f.write("group:"+g+"#member@user:"+u, shift[rng.Intn(len(shift))])
		case 1:
			if g != h || rng.Intn(4) == 0 {
				f.write("group:"+g+"#member@group:"+h+"#member", "")
			}
		case 2:
			f.write("doc:"+d+"#viewer@group:"+g+"#member", []string{"", "flag", `flag {"on":true}`}[rng.Intn(3)])
		case 3:
			f.write("doc:"+d+"#viewer@user:"+u, []string{"", "ip_allowed", `ip_allowed {"allowed":"10.0.0.0/8"}`}[rng.Intn(3)])
		case 4:
			f.write("doc:"+d+"#banned@user:"+u, cavs[rng.Intn(len(cavs))])
		case 5:
			f.write("doc:"+d+"#parent@folder:f"+fmt.Sprint(rng.Intn(3)), cavs[rng.Intn(2)])
			f.write("folder:f"+fmt.Sprint(rng.Intn(3))+"#viewer@user:"+u, cavs[rng.Intn(len(cavs))])
		case 6:
			if rng.Intn(3) == 0 {
				f.write("doc:"+d+"#viewer@user:*", cavs[1+rng.Intn(3)])
			}
		case 7:
			f.write("doc:"+d+"#editor@user:"+u, shift[1+rng.Intn(2)])
		}
	}
}

var lookupContexts = []string{"", `{"on":true}`, `{"on":false}`, `{"hour":10}`, `{"hour":20,"on":true}`,
	`{"client_ip":"10.0.0.1","hour":10,"on":true}`, `{"client_ip":"8.8.8.8","allowed":"10.0.0.0/8"}`,
	`{"client_ip":"10.0.0.1","allowed":"10.0.0.0/8","hour":12,"shift_start":11,"shift_end":13,"on":false}`}

// LookupSubjects finds exactly the subjects CheckResult does not deny, each
// with CheckResult's answer, over random caveated graphs and contexts,
// for plain subjects (including ones no relationship names) and usersets.
func TestLookupSubjectsMatchesCheckResultOverCaveats(t *testing.T) {
	users := []string{"u0", "u1", "u2", "u3"}
	counts := map[Permissionship]int{}
	for seed := range int64(6) {
		f := newCaveatFixture(t, nil)
		writeRandomCaveatGraph(f, seed, users)
		rev := f.st.Head()
		for _, cs := range lookupContexts {
			ctx := jsonContext(t, cs)
			for d := range 4 {
				doc := fmt.Sprint("doc:d", d)
				for _, perm := range []string{"view", "viewer", "banned", "edit"} {
					found, _, err := f.lookupAllSubjects(rev, doc, perm, "user", ctx, 2)
					if err != nil {
						t.Fatal(err)
					}
					for _, u := range append(users, "nobody") {
						want, _, err := f.eng.CheckResult(context.Background(), f.sc, rev, mustRequest(t, doc, perm, "user:"+u), ctx)
						if err != nil {
							t.Fatal(err)
						}
						if got := answerFor(found, u); !sameResult(got, want) {
							t.Fatalf("seed %d %s %s %s: lookup says %s, check %s\nfound %s", seed, doc, perm, u, answer(got), answer(want), showFound(found))
						}
						counts[want.Permissionship]++
					}
				}
				found, _, err := f.lookupAllSubjects(rev, doc, "view", "group#member", ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				for g := range 5 {
					want, _, err := f.eng.CheckResult(context.Background(), f.sc, rev, mustRequest(t, doc, "view", fmt.Sprintf("group:g%d#member", g)), ctx)
					if err != nil {
						t.Fatal(err)
					}
					if got := answerFor(found, fmt.Sprint("g", g)); !sameResult(got, want) {
						t.Fatalf("seed %d %s group g%d: lookup says %s, check %s", seed, doc, g, answer(got), answer(want))
					}
				}
			}
		}
	}
	if counts[Allowed] == 0 || counts[Denied] == 0 || counts[Conditional] == 0 {
		t.Fatalf("the graphs do not exercise every answer: %v", counts)
	}
}

// LookupResourcesContext lists each object CheckResult allows in IDs and
// each it answers conditional in Conditional, a page counting both.
func TestLookupResourcesConditional(t *testing.T) {
	users := []string{"u0", "u1", "u2"}
	f := newCaveatFixture(t, nil)
	writeRandomCaveatGraph(f, 3, users)
	rev := f.st.Head()
	bg := context.Background()
	kinds := map[Permissionship]int{}
	for _, cs := range lookupContexts {
		ctx := jsonContext(t, cs)
		for _, u := range users {
			sub := store.Subject{Type: "user", ID: u}
			var ids []string
			var cond []ConditionalID
			after := ""
			for range 100 {
				res, err := f.eng.LookupResourcesContext(bg, f.sc, f.st, rev, "doc", "view", sub, after, 1, ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(res.IDs)+len(res.Conditional) > 1 {
					t.Fatalf("page over its limit: %+v", res)
				}
				ids, cond = append(ids, res.IDs...), append(cond, res.Conditional...)
				if res.Next == "" {
					break
				}
				after = res.Next
			}
			var wantIDs []string
			var wantCond []ConditionalID
			for d := range 4 {
				r, _, err := f.eng.CheckResult(bg, f.sc, rev, mustRequest(t, fmt.Sprint("doc:d", d), "view", "user:"+u), ctx)
				if err != nil {
					t.Fatal(err)
				}
				kinds[r.Permissionship]++
				switch r.Permissionship {
				case Allowed:
					wantIDs = append(wantIDs, fmt.Sprint("d", d))
				case Conditional:
					wantCond = append(wantCond, ConditionalID{ID: fmt.Sprint("d", d), Missing: r.Missing})
				}
			}
			if !slices.Equal(ids, wantIDs) || !reflect.DeepEqual(cond, wantCond) {
				t.Fatalf("%s %s: %v %+v, want %v %+v", u, cs, ids, cond, wantIDs, wantCond)
			}
		}
	}
	if kinds[Allowed] == 0 || kinds[Conditional] == 0 || kinds[Denied] == 0 {
		t.Fatalf("the graph does not exercise every answer: %v", kinds)
	}
	// A bad context is refused before any object is checked.
	if _, err := f.eng.LookupResourcesContext(bg, f.sc, f.st, rev, "doc", "view", store.Subject{Type: "user", ID: "u0"}, "", 0,
		map[string]any{"s": strings.Repeat("x", MaxContextSize)}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("big context: %v", err)
	}
}

func TestExpandCaveats(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("doc:d#viewer@user:a", "")
	f.write("doc:d#viewer@user:b", `ip_allowed {"allowed":"10.0.0.0/8"}`)
	f.write("doc:d#viewer@user:*", "flag")
	f.write("doc:d#viewer@group:g#member", "flag")
	f.write("group:g#member@user:s", "on_shift")
	f.write("doc:d#parent@folder:f", `flag {"on":true}`)
	f.write("folder:f#viewer@user:v", "")
	bg := context.Background()
	show := func(tr *Trace) string {
		var b strings.Builder
		var walk func(n *TraceNode, depth int)
		walk = func(n *TraceNode, depth int) {
			fmt.Fprintf(&b, "%s%s %s#%s %s", strings.Repeat(" ", depth), n.Kind, n.Object, n.Relation, n.Subject)
			if n.Caveat != "" {
				ctx, _ := json.Marshal(n.CaveatContext)
				fmt.Fprintf(&b, " [%s %s]", n.Caveat, ctx)
			}
			b.WriteString("\n")
			for _, c := range n.Children {
				walk(c, depth+1)
			}
		}
		walk(tr.Root, 0)
		return b.String()
	}
	tr, _, err := f.eng.Expand(bg, f.sc, f.st.Head(), ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	want := `relation doc:d#viewer 
 subject doc:d#viewer group:g#member [flag null]
 subject doc:d#viewer user:*` + " [flag null]\n" +
		` subject doc:d#viewer user:a
 subject doc:d#viewer user:b [ip_allowed {"allowed":"10.0.0.0/8"}]
`
	if got := show(tr); got != want {
		t.Fatalf("expand:\n%s\nwant:\n%s", got, want)
	}
	tr, _, err = f.eng.Expand(bg, f.sc, f.st.Head(), ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view", Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	got := show(tr)
	for _, line := range []string{
		"\n    relation group:g#member  [flag null]\n     subject group:g#member user:s [on_shift null]\n",
		"\n    permission folder:f#view  [flag {\"on\":true}]\n",
		"\n      subject folder:f#viewer user:v\n",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("recursive expand lacks %q:\n%s", line, got)
		}
	}
	// A caveat the schema no longer allows is left out of a tree of an
	// older snapshot, as Check leaves it out. The relationship must be gone
	// at the head for the schema change to be accepted.
	old := f.write("folder:f#viewer@user:w", "flag")
	if _, err := f.st.Write([]store.Update{{Op: store.OpDelete, Relationship: mustRel(t, "folder:f#viewer@user:w")}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.WriteSchema(strings.Replace(caveatModel, "relation viewer: user | user with flag\n  permission view = viewer", "relation viewer: user\n  permission view = viewer", 1)); err != nil {
		t.Fatal(err)
	}
	sc := mustSchema(t, f.st)
	tr, _, err = f.eng.Expand(bg, sc, old, ExpandRequest{ResourceType: "folder", ResourceID: "f", Permission: "viewer"})
	if err != nil || strings.Contains(show(tr), "user:w") || !strings.Contains(show(tr), "user:v") {
		t.Fatalf("stale caveat: %v\n%s", err, show(tr))
	}
	if r, _, err := f.eng.CheckResult(bg, sc, old, mustRequest(t, "folder:f", "viewer", "user:w"), map[string]any{"on": true}); err != nil || r.Permissionship != Denied {
		t.Fatalf("check of the stale caveat: %s %v", answer(r), err)
	}
	found, _, err := f.eng.LookupSubjects(bg, sc, old, LookupSubjectsRequest{ResourceType: "folder", ResourceID: "f", Permission: "viewer", SubjectType: "user", Context: map[string]any{"on": true}})
	if err != nil || showFound(found.Subjects) != "v" {
		t.Fatalf("lookup of the stale caveat: %s %v", showFound(found.Subjects), err)
	}
}

func mustRel(t testing.TB, s string) store.Relationship {
	t.Helper()
	r, err := store.ParseRelationship(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A lookup over a caveated graph: a 200-member group, a quarter of them
// on a caveat the context decides and a quarter on one it leaves open,
// granted through a caveated userset.
func BenchmarkLookupSubjectsCaveated(b *testing.B) {
	f := newCaveatFixture(b, nil)
	for i := range 200 {
		cav := []string{"", "", `on_shift {"shift_start":9,"shift_end":17}`, "on_shift"}[i%4]
		f.write(fmt.Sprintf("group:g#member@user:u%03d", i), cav)
	}
	f.write("doc:d#viewer@group:g#member", "flag")
	f.write("doc:d#banned@user:u001", "flag")
	rev := f.st.Head()
	ctx := map[string]any{"on": true, "hour": 10}
	b.ReportAllocs()
	for b.Loop() {
		res, _, err := f.eng.LookupSubjects(context.Background(), f.sc, rev, LookupSubjectsRequest{ResourceType: "doc", ResourceID: "d",
			Permission: "view", SubjectType: "user", Limit: MaxLookupLimit, Context: ctx})
		if err != nil || len(res.Subjects) == 0 {
			b.Fatal(err)
		}
	}
}
