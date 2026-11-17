package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

const caveatModel = `
caveat ip_allowed(allowed cidr, client_ip ipaddress) {
  allowed.containsIP(client_ip)
}

caveat on_shift(shift_start int, shift_end int, hour int) {
  hour >= shift_start && hour < shift_end
}

caveat flag(on bool) { on }

caveat costly(n int) { [1, 2, 3, 4, 5, 6, 7, 8].all(a, [1, 2, 3, 4, 5, 6, 7, 8].all(b, a * b * n >= 0)) && n < 0 }

caveat boom(m map<int>) { m["missing"] > 0 }

definition user {}

definition group {
  relation member: user | user with on_shift | user with costly | group#member
}

definition folder {
  relation viewer: user | user with flag
  permission view = viewer
}

definition doc {
  relation parent: folder | folder with flag
  relation viewer: user | user with ip_allowed | user:* with flag | group#member | group#member with flag
  relation banned: user | user with flag
  relation editor: user with on_shift
  relation odd: user with costly | user with boom
  permission view = (viewer + parent->view) - banned
  permission edit = editor & viewer
  permission strange = odd
}
`

type caveatFixture struct {
	t   testing.TB
	st  *store.Store
	sc  *schema.Schema
	eng *Engine
}

func newCaveatFixture(t testing.TB, cache *Cache) *caveatFixture {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.WriteSchema(caveatModel); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.Schema()
	return &caveatFixture{t: t, st: st, sc: sc, eng: New(st, cache)}
}

// write stores rel, with a caveat when cav is "name" or "name {json context}".
func (f *caveatFixture) write(rel, cav string) store.Revision {
	f.t.Helper()
	r, err := store.ParseRelationship(rel)
	if err != nil {
		f.t.Fatal(err)
	}
	u := store.Update{Op: store.OpTouch, Relationship: r}
	if cav != "" {
		name, ctx, _ := strings.Cut(cav, " ")
		u.Caveat = &store.Caveat{Name: name}
		if ctx != "" {
			if err := json.Unmarshal([]byte(ctx), &u.Caveat.Context); err != nil {
				f.t.Fatal(err)
			}
		}
	}
	rev, err := f.st.Write([]store.Update{u}, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return rev
}

func (f *caveatFixture) result(resource, perm, subject, ctx string) (Result, Stats, error) {
	f.t.Helper()
	typ, id, _ := strings.Cut(resource, ":")
	sub, err := store.ParseSubject(subject, false)
	if err != nil {
		f.t.Fatal(err)
	}
	var c map[string]any
	if ctx != "" {
		if err := json.Unmarshal([]byte(ctx), &c); err != nil {
			f.t.Fatal(err)
		}
	}
	return f.eng.CheckResult(context.Background(), f.sc, f.st.Head(),
		Request{ResourceType: typ, ResourceID: id, Permission: perm, Subject: sub}, c)
}

// answer renders a result as "allowed", "denied" or "conditional[a b]".
func answer(r Result) string {
	if r.Permissionship == Conditional {
		return fmt.Sprintf("conditional%v", r.Missing)
	}
	return r.Permissionship.String()
}

func TestCaveatedChecks(t *testing.T) {
	type rel struct{ rel, cav string }
	type chk struct{ resource, perm, subject, ctx, want string }
	for _, tc := range []struct {
		name   string
		rels   []rel
		checks []chk
	}{
		{"direct caveat", []rel{{"doc:d#viewer@user:a", `ip_allowed {"allowed":"10.0.0.0/8"}`}}, []chk{
			{"doc:d", "viewer", "user:a", `{"client_ip":"10.1.2.3"}`, "allowed"},
			{"doc:d", "viewer", "user:a", `{"client_ip":"192.168.0.1"}`, "denied"},
			{"doc:d", "viewer", "user:a", "", "conditional[client_ip]"},
			{"doc:d", "viewer", "user:b", "", "denied"},
			// The stored context wins over the request's.
			{"doc:d", "viewer", "user:a", `{"allowed":"0.0.0.0/0","client_ip":"192.168.0.1"}`, "denied"},
		}},
		{"nothing stored", []rel{{"doc:d#viewer@user:a", "ip_allowed"}}, []chk{
			{"doc:d", "viewer", "user:a", "", "conditional[allowed client_ip]"},
			{"doc:d", "viewer", "user:a", `{"allowed":"10.0.0.0/8"}`, "conditional[client_ip]"},
			{"doc:d", "viewer", "user:a", `{"allowed":"10.0.0.0/8","client_ip":"10.0.0.1"}`, "allowed"},
		}},
		{"a plain relationship wins over a caveated one", []rel{
			{"doc:d#viewer@user:*", "flag"},
			{"doc:d#viewer@user:a", ""},
		}, []chk{
			{"doc:d", "view", "user:a", "", "allowed"},
			{"doc:d", "view", "user:b", "", "conditional[on]"},
			{"doc:d", "view", "user:b", `{"on":true}`, "allowed"},
			{"doc:d", "view", "user:b", `{"on":false}`, "denied"},
		}},
		{"caveated membership", []rel{
			{"group:g#member@user:a", `on_shift {"shift_start":9,"shift_end":17}`},
			{"doc:d#viewer@group:g#member", ""},
		}, []chk{
			{"doc:d", "view", "user:a", `{"hour":10}`, "allowed"},
			{"doc:d", "view", "user:a", `{"hour":20}`, "denied"},
			{"doc:d", "view", "user:a", "", "conditional[hour]"},
			{"doc:d", "view", "group:g#member", "", "allowed"},
		}},
		{"caveat on the userset and in the group", []rel{
			{"group:g#member@user:a", `on_shift {"shift_start":9,"shift_end":17}`},
			{"doc:d#viewer@group:g#member", "flag"},
		}, []chk{
			{"doc:d", "view", "user:a", "", "conditional[hour on]"},
			{"doc:d", "view", "user:a", `{"on":true}`, "conditional[hour]"},
			{"doc:d", "view", "user:a", `{"on":false}`, "denied"},
			{"doc:d", "view", "user:a", `{"on":true,"hour":9}`, "allowed"},
			{"doc:d", "view", "group:g#member", "", "conditional[on]"},
		}},
		{"caveated arrow", []rel{
			{"doc:d#parent@folder:f", "flag"},
			{"folder:f#viewer@user:a", ""},
		}, []chk{
			{"doc:d", "view", "user:a", "", "conditional[on]"},
			{"doc:d", "view", "user:a", `{"on":true}`, "allowed"},
			{"doc:d", "view", "user:b", "", "denied"},
		}},
		{"two conditional branches", []rel{
			{"doc:d#viewer@user:a", "ip_allowed"},
			{"doc:d#parent@folder:f", ""},
			{"folder:f#viewer@user:a", "flag"},
		}, []chk{
			{"doc:d", "view", "user:a", "", "conditional[allowed client_ip on]"},
			{"doc:d", "view", "user:a", `{"on":true}`, "allowed"},
			{"doc:d", "view", "user:a", `{"on":false}`, "conditional[allowed client_ip]"},
		}},
		{"caveated exclusion", []rel{
			{"doc:d#viewer@user:a", ""},
			{"doc:d#banned@user:a", "flag"},
		}, []chk{
			// Unknown whether a is banned, so unknown whether a may view.
			{"doc:d", "view", "user:a", "", "conditional[on]"},
			{"doc:d", "view", "user:a", `{"on":true}`, "denied"},
			{"doc:d", "view", "user:a", `{"on":false}`, "allowed"},
		}},
		{"intersection", []rel{
			{"doc:d#editor@user:a", `on_shift {"shift_start":9,"shift_end":17}`},
			{"doc:d#viewer@user:a", "ip_allowed"},
			{"doc:d#editor@user:b", `on_shift {"shift_start":9,"shift_end":17}`},
		}, []chk{
			{"doc:d", "edit", "user:a", "", "conditional[allowed client_ip hour]"},
			{"doc:d", "edit", "user:a", `{"hour":3}`, "denied"},
			{"doc:d", "edit", "user:a", `{"hour":10}`, "conditional[allowed client_ip]"},
			{"doc:d", "edit", "user:a", `{"hour":10,"allowed":"10.0.0.0/8","client_ip":"10.0.0.1"}`, "allowed"},
			// b is no viewer: denied whatever the hour.
			{"doc:d", "edit", "user:b", "", "denied"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cache := range []*Cache{nil, NewCache(1000)} {
				f := newCaveatFixture(t, cache)
				for _, r := range tc.rels {
					f.write(r.rel, r.cav)
				}
				// Twice, so the second round runs from the cache.
				for round := range 2 {
					for _, c := range tc.checks {
						r, _, err := f.result(c.resource, c.perm, c.subject, c.ctx)
						if err != nil {
							t.Fatalf("%s#%s@%s %s: %v", c.resource, c.perm, c.subject, c.ctx, err)
						}
						if got := answer(r); got != c.want {
							t.Errorf("cache %v round %d: %s#%s@%s %s = %s, want %s", cache != nil, round, c.resource, c.perm, c.subject, c.ctx, got, c.want)
						}
						ok, _, err := f.eng.Check(context.Background(), f.sc, f.st.Head(), mustRequest(t, c.resource, c.perm, c.subject))
						if err != nil {
							t.Fatal(err)
						}
						if c.ctx == "" && ok != (c.want == "allowed") {
							t.Errorf("Check %s#%s@%s = %v, want %s", c.resource, c.perm, c.subject, ok, c.want)
						}
					}
				}
			}
		})
	}
}

func mustRequest(t testing.TB, resource, perm, subject string) Request {
	t.Helper()
	typ, id, _ := strings.Cut(resource, ":")
	sub, err := store.ParseSubject(subject, false)
	if err != nil {
		t.Fatal(err)
	}
	return Request{ResourceType: typ, ResourceID: id, Permission: perm, Subject: sub}
}

func TestCaveatErrors(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("doc:d#viewer@user:a", `ip_allowed {"allowed":"10.0.0.0/8"}`)
	f.write("doc:d#odd@user:boom", `boom {"m":{"a":1}}`)
	f.write("doc:d#odd@user:costly", `costly`)
	for _, tc := range []struct {
		perm, subject, ctx string
		want               error
		msg                string
	}{
		{"viewer", "user:a", `{"client_ip":"not an address"}`, ErrCaveat, "ip_allowed on doc:d#viewer@user:a"},
		{"viewer", "user:a", `{"client_ip":7}`, ErrCaveat, "client_ip"},
		{"strange", "user:boom", "", ErrCaveat, "boom on doc:d#odd@user:boom"},
		{"strange", "user:costly", `{"n":1}`, nil, ""},
	} {
		_, _, err := f.result("doc:d", tc.perm, tc.subject, tc.ctx)
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s %s: %v", tc.subject, tc.ctx, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s %s: %v, want %v with %q", tc.subject, tc.ctx, err, tc.want, tc.msg)
		}
	}

	// A context that cannot be encoded or is too big is refused up front.
	for _, ctx := range []map[string]any{
		{"x": make(chan int)},
		{"x": strings.Repeat("y", MaxContextSize)},
	} {
		_, _, err := f.eng.CheckResult(context.Background(), f.sc, f.st.Head(), mustRequest(t, "doc:d", "viewer", "user:a"), ctx)
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("context %.20v: %v", ctx, err)
		}
	}
	// An invalid request is refused before the context is looked at.
	if _, _, err := f.eng.CheckResult(context.Background(), f.sc, f.st.Head(), mustRequest(t, "doc:d", "nope", "user:a"), nil); !errors.Is(err, ErrUnknownName) {
		t.Errorf("unknown permission: %v", err)
	}
	if _, _, _, err := f.eng.ExplainResult(context.Background(), f.sc, f.st.Head(), mustRequest(t, "doc:d", "viewer", "user:a"), map[string]any{"x": make(chan int)}, 0); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("explain with a bad context: %v", err)
	}
	if _, _, _, err := f.eng.ExplainResult(context.Background(), f.sc, f.st.Head(), mustRequest(t, "doc:d", "strange", "user:boom"), nil, 0); !errors.Is(err, ErrCaveat) {
		t.Errorf("explain with a failing caveat: %v", err)
	}
}

// Stats count the caveats a check evaluates and their cost, and the
// caveats of one check share one cost budget.
func TestCaveatCostPerCheck(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("doc:d#odd@user:u", "costly")
	_, st, err := f.result("doc:d", "strange", "user:u", `{"n":1}`)
	if err != nil || st.Caveats != 1 || st.CaveatCost == 0 {
		t.Fatalf("stats %+v, %v", st, err)
	}

	// Enough groups, each with a caveated membership that is false, that
	// their caveats together cost more than the budget.
	one := newCaveatFixture(t, nil)
	one.write("group:g0#member@user:u", `costly {"n":1}`)
	one.write("doc:d#viewer@group:g0#member", "")
	_, st, err = one.result("doc:d", "view", "user:u", "")
	if err != nil || st.Caveats != 1 {
		t.Fatalf("%+v, %v", st, err)
	}
	n := MaxCaveatCostPerCheck/st.CaveatCost + 1
	if n > MaxDispatchesPerCheck/2 {
		t.Fatalf("a caveat of cost %d cannot reach the budget within the dispatch limit", st.CaveatCost)
	}
	g := newCaveatFixture(t, nil)
	for lo := 0; lo < n; lo += store.MaxUpdatesPerWrite / 2 {
		var ups []store.Update
		for i := lo; i < min(n, lo+store.MaxUpdatesPerWrite/2); i++ {
			gid := fmt.Sprint("g", i)
			ups = append(ups,
				store.Update{Op: store.OpTouch, Relationship: store.Relationship{ResourceType: "group", ResourceID: gid, Relation: "member", SubjectType: "user", SubjectID: "u"},
					Caveat: &store.Caveat{Name: "costly", Context: map[string]any{"n": 1}}},
				store.Update{Op: store.OpTouch, Relationship: store.Relationship{ResourceType: "doc", ResourceID: "d", Relation: "viewer", SubjectType: "group", SubjectID: gid, SubjectRelation: "member"}})
		}
		if _, err := g.st.Write(ups, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := g.result("doc:d", "view", "user:u", ""); !errors.Is(err, ErrTooMuchWork) {
		t.Fatalf("%d caveats: %v", n, err)
	}
}

func TestCaveatExplain(t *testing.T) {
	f := newCaveatFixture(t, NewCache(100))
	f.write("doc:d#viewer@user:a", "ip_allowed")
	f.write("doc:d#viewer@user:b", "")
	f.write("doc:d#banned@user:b", `flag {"on":false}`)
	q := mustRequest(t, "doc:d", "view", "user:a")
	r, tr, _, err := f.eng.ExplainResult(context.Background(), f.sc, f.st.Head(), q, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if answer(r) != "conditional[allowed client_ip]" || !tr.Root.Conditional || tr.Root.Result || tr.Root.Role != RoleConditional {
		t.Fatalf("root %+v", tr.Root)
	}
	var subj *TraceNode
	var walk func(n *TraceNode)
	walk = func(n *TraceNode) {
		if n.Kind == KindSubject && n.Caveat == "ip_allowed" {
			subj = n
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tr.Root)
	if subj == nil || !subj.Conditional || !reflect.DeepEqual(subj.Missing, []string{"allowed", "client_ip"}) || subj.Role != RoleConditional {
		t.Fatalf("subject node %+v in %s", subj, dump(tr.Root))
	}
	ok, _, _, err := f.eng.Explain(context.Background(), f.sc, f.st.Head(), q, 0)
	if err != nil || ok {
		t.Fatalf("Explain = %v, %v", ok, err)
	}
	// b views: the caveated ban is false, recorded as a false caveated
	// subject node.
	r, tr, _, err = f.eng.ExplainResult(context.Background(), f.sc, f.st.Head(), mustRequest(t, "doc:d", "view", "user:b"), nil, 0)
	if err != nil || !r.Allowed() || tr.Root.Role != RoleGrant {
		t.Fatalf("b: %v %+v %v", answer(r), tr.Root, err)
	}
	if !strings.Contains(dump(tr.Root), "subject doc:d banned user:b flag false") {
		t.Fatalf("b's trace:\n%s", dump(tr.Root))
	}
	// A denied caveat on a userset is recorded too, and the denial marked.
	f.write("group:g#member@user:c", "")
	f.write("doc:d#viewer@group:g#member", `flag {"on":false}`)
	r, tr, _, err = f.eng.ExplainResult(context.Background(), f.sc, f.st.Head(), mustRequest(t, "doc:d", "view", "user:c"), nil, 0)
	if err != nil || answer(r) != "denied" || tr.Root.Role != RoleDeny || !strings.Contains(dump(tr.Root), "subject doc:d viewer group:g#member flag false") {
		t.Fatalf("c: %v %v\n%s", answer(r), err, dump(tr.Root))
	}
}

func dump(n *TraceNode) string {
	var b strings.Builder
	var walk func(n *TraceNode, depth int)
	walk = func(n *TraceNode, depth int) {
		fmt.Fprintf(&b, "%s%s %s %s %s %s %v\n", strings.Repeat("  ", depth), n.Kind, n.Object, n.Relation, n.Subject, n.Caveat, n.Result)
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	walk(n, 0)
	return strings.ReplaceAll(b.String(), "  ", " ")
}

func TestExpandAndLookupSubjectsRefuseCaveatedRelations(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("doc:d#viewer@user:a", "")
	f.write("folder:f#viewer@user:a", "")
	bg := context.Background()
	for _, q := range []struct{ typ, rel string }{{"doc", "viewer"}, {"doc", "view"}, {"folder", "view"}} {
		_, _, err := f.eng.Expand(bg, f.sc, f.st.Head(), ExpandRequest{ResourceType: q.typ, ResourceID: "d", Permission: q.rel})
		_, _, err2 := f.eng.LookupSubjects(bg, f.sc, f.st.Head(), LookupSubjectsRequest{ResourceType: q.typ, ResourceID: "d", Permission: q.rel, SubjectType: "user"})
		for _, e := range []error{err, err2} {
			if !errors.Is(e, ErrCaveatedRelation) {
				t.Errorf("%s#%s: %v", q.typ, q.rel, e)
			}
		}
	}
	// doc#parent lists folder with flag: the arrow is refused even when
	// the relation it reads first has no caveat.
	if err := refuseCaveated(f.sc, "doc", "parent"); !errors.Is(err, ErrCaveatedRelation) || !strings.Contains(err.Error(), "doc#parent allows folder with flag") {
		t.Fatal(err)
	}
	for _, q := range [][2]string{{"user", "x"}, {"doc", "view"}, {"nope", "x"}} {
		if err := refuseCaveated(f.sc, q[0], q[1]); err != nil {
			t.Errorf("%v: %v", q, err)
		}
	}
	// A schema without caveats expands as before.
	ff := newFixture(t, nil, "doc:a#viewer@user:x")
	if _, _, err := ff.eng.Expand(bg, mustSchema(t, ff.st), ff.st.Head(), ExpandRequest{ResourceType: "doc", ResourceID: "a", Permission: "view"}); err != nil {
		t.Fatal(err)
	}
}

func mustSchema(t testing.TB, st *store.Store) *schema.Schema {
	t.Helper()
	sc, _ := st.Schema()
	if sc == nil {
		t.Fatal("no schema")
	}
	return sc
}

// LookupResources lists only the objects the subject definitely has the
// permission on.
func TestLookupResourcesSkipsConditional(t *testing.T) {
	f := newCaveatFixture(t, nil)
	f.write("doc:a#viewer@user:u", "")
	f.write("doc:b#viewer@user:u", "ip_allowed")
	f.write("doc:c#viewer@user:*", `flag {"on":true}`)
	got, err := f.eng.LookupResources(context.Background(), f.sc, f.st, f.st.Head(), "doc", "view", store.Subject{Type: "user", ID: "u"}, "", 0)
	if err != nil || strings.Join(got.IDs, ",") != "a,c" {
		t.Fatalf("lookup = %v, %v", got.IDs, err)
	}
}

// A result that evaluated no caveat is cached once for every context; one
// that did is cached per context.
func TestCaveatCacheKeys(t *testing.T) {
	cache := NewCache(1000)
	f := newCaveatFixture(t, cache)
	f.write("group:big#member@user:u", "")
	f.write("doc:d#viewer@group:big#member", "")
	f.write("doc:e#viewer@user:u", "ip_allowed")
	bg := context.Background()
	rev := f.st.Head()
	for i := range 3 {
		ctx := map[string]any{"client_ip": fmt.Sprintf("10.0.0.%d", i), "allowed": "10.0.0.0/31"}
		r, st, err := f.eng.CheckResult(bg, f.sc, rev, mustRequest(t, "doc:d", "viewer", "user:u"), ctx)
		if err != nil || !r.Allowed() {
			t.Fatal(answer(r), err)
		}
		if i > 0 && (st.CacheHits != 1 || st.Dispatches != 0) {
			t.Fatalf("context %d: no caveat was evaluated, so the result should come from the cache: %+v", i, st)
		}
		r, st, err = f.eng.CheckResult(bg, f.sc, rev, mustRequest(t, "doc:e", "viewer", "user:u"), ctx)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[int]string{0: "allowed", 1: "allowed", 2: "denied"}[i]; answer(r) != want {
			t.Fatalf("context %d: %s, want %s", i, answer(r), want)
		}
		if st.CacheHits != 0 || st.Caveats != 1 {
			t.Fatalf("context %d: a caveated result was shared across contexts: %+v", i, st)
		}
		// The same context again, written with its keys the other way
		// round, hits.
		again := map[string]any{"allowed": "10.0.0.0/31", "client_ip": fmt.Sprintf("10.0.0.%d", i)}
		r2, st, err := f.eng.CheckResult(bg, f.sc, rev, mustRequest(t, "doc:e", "viewer", "user:u"), again)
		if err != nil || answer(r2) != answer(r) || st.CacheHits != 1 || st.Caveats != 0 {
			t.Fatalf("context %d again: %s %+v %v", i, answer(r2), st, err)
		}
	}
	// No context is a context too: its conditional answer is cached apart.
	r, _, err := f.eng.CheckResult(bg, f.sc, rev, mustRequest(t, "doc:e", "viewer", "user:u"), nil)
	if err != nil || answer(r) != "conditional[allowed client_ip]" {
		t.Fatal(answer(r), err)
	}
	r, st, err := f.eng.CheckResult(bg, f.sc, rev, mustRequest(t, "doc:e", "viewer", "user:u"), map[string]any{})
	if err != nil || answer(r) != "conditional[allowed client_ip]" || st.CacheHits != 1 {
		t.Fatal(answer(r), st, err)
	}
	if ok, _ := cache.Get("x"); ok {
		t.Fatal("empty cache hit")
	}
}

// Results from the cache, across contexts and requests that share
// sub-problems, are the results of evaluating afresh.
func TestCaveatCacheMatchesFreshEvaluation(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	cached := newCaveatFixture(t, NewCache(50_000))
	fresh := New(cached.st, nil)
	users := []string{"u0", "u1", "u2"}
	cavs := []string{"", "flag", `flag {"on":true}`, `flag {"on":false}`}
	for i := range 120 {
		u := users[rng.Intn(len(users))]
		g, h := fmt.Sprint("g", rng.Intn(6)), fmt.Sprint("g", rng.Intn(6))
		d := fmt.Sprint("d", rng.Intn(5))
		switch i % 6 {
		case 0:
			cached.write("group:"+g+"#member@user:"+u, []string{"", `on_shift {"shift_start":9,"shift_end":17}`}[rng.Intn(2)])
		case 1:
			if g != h {
				cached.write("group:"+g+"#member@group:"+h+"#member", "")
			}
		case 2:
			cached.write("doc:"+d+"#viewer@group:"+g+"#member", []string{"", "flag"}[rng.Intn(2)])
		case 3:
			cached.write("doc:"+d+"#viewer@user:"+u, []string{"", `ip_allowed {"allowed":"10.0.0.0/8"}`}[rng.Intn(2)])
		case 4:
			cached.write("doc:"+d+"#banned@user:"+u, cavs[rng.Intn(len(cavs))])
		case 5:
			cached.write("doc:"+d+"#parent@folder:f"+fmt.Sprint(rng.Intn(2)), cavs[rng.Intn(2)])
			cached.write("folder:f"+fmt.Sprint(rng.Intn(2))+"#viewer@user:"+u, cavs[rng.Intn(len(cavs))])
		}
	}
	contexts := []map[string]any{nil, {"on": true}, {"on": false}, {"hour": 10}, {"hour": 20, "on": true},
		{"client_ip": "10.0.0.1", "hour": 10, "on": true}, {"client_ip": "8.8.8.8"}}
	rev := cached.st.Head()
	bg := context.Background()
	counts := map[Permissionship]int{}
	for range 3 {
		for _, ctx := range contexts {
			for d := range 5 {
				for _, u := range users {
					for _, perm := range []string{"view", "viewer", "banned"} {
						q := mustRequest(t, fmt.Sprint("doc:d", d), perm, "user:"+u)
						got, _, err := cached.eng.CheckResult(bg, cached.sc, rev, q, ctx)
						if err != nil {
							t.Fatal(err)
						}
						want, _, err := fresh.CheckResult(bg, cached.sc, rev, q, ctx)
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("%v %v: cached %s, fresh %s", q, ctx, answer(got), answer(want))
						}
						counts[got.Permissionship]++
					}
				}
			}
		}
	}
	if counts[Allowed] == 0 || counts[Denied] == 0 || counts[Conditional] == 0 {
		t.Fatalf("the graph does not exercise every answer: %v", counts)
	}
}

func TestResultCombinators(t *testing.T) {
	c := func(names ...string) Result { return Result{Permissionship: Conditional, Missing: names} }
	for _, tc := range []struct {
		got  Result
		want string
	}{
		{or(allowed, c("a")), "allowed"},
		{or(c("a"), allowed), "allowed"},
		{or(denied, c("a")), "conditional[a]"},
		{or(c("a"), denied), "conditional[a]"},
		{or(c("a", "c"), c("b", "c")), "conditional[a b c]"},
		{or(denied, denied), "denied"},
		{and(denied, c("a")), "denied"},
		{and(c("a"), denied), "denied"},
		{and(allowed, c("a")), "conditional[a]"},
		{and(c("a"), allowed), "conditional[a]"},
		{and(c("b"), c("a")), "conditional[a b]"},
		{and(allowed, allowed), "allowed"},
		{not(allowed), "denied"},
		{not(denied), "allowed"},
		{not(c("a")), "conditional[a]"},
	} {
		if got := answer(tc.got); got != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
	a := []string{"a", "b"}
	if m := mergeNames(a, []string{"b"}); &m[0] != &a[0] {
		t.Error("a subset should share the larger list")
	}
	if m := mergeNames([]string{"b"}, a); &m[0] != &a[0] {
		t.Error("a subset should share the larger list")
	}
	if m := mergeNames(nil, a); &m[0] != &a[0] {
		t.Error("an empty list adds nothing")
	}
	if Permissionship(9).String() != "denied" {
		t.Error("unknown answers print as denied")
	}
}

func BenchmarkCaveatedCheck(b *testing.B) {
	f := newCaveatFixture(b, NewCache(100_000))
	f.write("group:g#member@user:u", `on_shift {"shift_start":9,"shift_end":17}`)
	f.write("doc:d#viewer@group:g#member", "")
	f.write("doc:d#viewer@user:u", `ip_allowed {"allowed":"10.0.0.0/8"}`)
	q := mustRequest(b, "doc:d", "view", "user:u")
	bg := context.Background()
	rev := f.st.Head()
	for _, bc := range []struct {
		name string
		eng  *Engine
		ctx  map[string]any
	}{
		{"uncached/allowed", New(f.st, nil), map[string]any{"hour": 10, "client_ip": "10.0.0.1"}},
		{"uncached/conditional", New(f.st, nil), nil},
		{"cached/allowed", f.eng, map[string]any{"hour": 10, "client_ip": "10.0.0.1"}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := bc.eng.CheckResult(bg, f.sc, rev, q, bc.ctx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
