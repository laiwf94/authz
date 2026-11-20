package check

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/platform/clock"
)

// This file checks the engine on random caveated graphs whose
// relationships expire and are touched again over time, at every revision,
// against a reference written separately: its caveats are evaluated in Go,
// not CEL, and its memberships are solved by iterating whole tables to a
// fixpoint (any graph) or by plain recursion (graphs without cycles), not by
// the engine's memoised, cached depth-first walk.

const refModel = `
caveat flag(on bool) { on }

caveat on_shift(shift_start int, shift_end int, hour int) {
  hour >= shift_start && hour < shift_end
}

caveat ip_allowed(allowed cidr, client_ip ipaddress) { allowed.containsIP(client_ip) }

caveat in_region(regions list<string>, region string) { region in regions }

definition user {}

definition group {
  relation member: user | user with on_shift | user with flag | group#member | group#member with flag
}

definition folder {
  relation parent: folder | folder with flag
  relation viewer: user | user with ip_allowed | user:* | user:* with flag | group#member | group#member with in_region
  permission view = viewer + parent->view
}

definition doc {
  relation parent: folder | folder with in_region
  relation owner: user
  relation editor: user | user with on_shift | group#member
  relation viewer: user | user with ip_allowed | group#member | group#member with flag
  relation banned: user | user with flag | user with in_region
  permission edit = owner + editor
  permission view = (viewer + edit + parent->view) - banned
  permission both = edit & parent->view
}
`

// tri is the reference's answer: allowed, denied, or conditional on the
// parameters names lists (sorted). The fixpoint solver leaves names empty.
type tri struct {
	v     Permissionship
	names []string
}

var (
	tAllow = tri{v: Allowed}
	tDeny  = tri{v: Denied}
)

func unionNames(a, b []string) []string {
	out := slices.Concat(a, b)
	sort.Strings(out)
	return slices.Compact(out)
}

// kor, kand and knot are Kleene's three-valued or, and and not; a
// conditional answer depends on the union of its conditional operands'
// parameters.
func kor(a, b tri) tri {
	switch {
	case a.v == Allowed || b.v == Allowed:
		return tAllow
	case a.v == Denied:
		return b
	case b.v == Denied:
		return a
	}
	return tri{v: Conditional, names: unionNames(a.names, b.names)}
}

func kand(a, b tri) tri {
	switch {
	case a.v == Denied || b.v == Denied:
		return tDeny
	case a.v == Allowed:
		return b
	case b.v == Allowed:
		return a
	}
	return tri{v: Conditional, names: unionNames(a.names, b.names)}
}

func knot(a tri) tri {
	switch a.v {
	case Allowed:
		return tDeny
	case Denied:
		return tAllow
	}
	return a
}

func boolTri(b bool) tri {
	if b {
		return tAllow
	}
	return tDeny
}

func unknown(names ...string) tri {
	sort.Strings(names)
	return tri{v: Conditional, names: names}
}

// refCaveat is a caveat on a reference edge, with its stored context in
// plain Go values.
type refCaveat struct {
	name string
	ctx  map[string]any
}

// eval evaluates the caveat in Go: the stored context over the request's,
// and a missing parameter makes a comparison unknown.
func (c *refCaveat) eval(req map[string]any) tri {
	if c == nil {
		return tAllow
	}
	get := func(k string) (any, bool) {
		if v, ok := c.ctx[k]; ok {
			return v, true
		}
		v, ok := req[k]
		return v, ok
	}
	// both evaluates f over two parameters, or is unknown on those missing.
	both := func(a, b string, f func(x, y any) bool) tri {
		x, okx := get(a)
		y, oky := get(b)
		switch {
		case okx && oky:
			return boolTri(f(x, y))
		case okx:
			return unknown(b)
		case oky:
			return unknown(a)
		}
		return unknown(a, b)
	}
	switch c.name {
	case "flag":
		if v, ok := get("on"); ok {
			return boolTri(v.(bool))
		}
		return unknown("on")
	case "on_shift":
		ge := both("hour", "shift_start", func(h, s any) bool { return h.(int) >= s.(int) })
		lt := both("hour", "shift_end", func(h, e any) bool { return h.(int) < e.(int) })
		return kand(ge, lt)
	case "ip_allowed":
		return both("allowed", "client_ip", func(a, ip any) bool {
			return netip.MustParsePrefix(a.(string)).Contains(netip.MustParseAddr(ip.(string)))
		})
	case "in_region":
		return both("regions", "region", func(rs, r any) bool { return slices.Contains(rs.([]any), r) })
	}
	panic("unknown caveat " + c.name)
}

func (c *refCaveat) String() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf(" with %s %v", c.name, c.ctx)
}

// refEdge is one relationship as the reference sees it.
type refEdge struct {
	resType, resID, rel string
	subType, subID      string
	subRel              string
	cav                 *refCaveat
}

func (e refEdge) key() string {
	s := e.resType + ":" + e.resID + "#" + e.rel + "@" + e.subType + ":" + e.subID
	if e.subRel != "" {
		s += "#" + e.subRel
	}
	return s
}

// refGraph answers checks over the edges live at one revision.
type refGraph struct {
	byObj map[string][]refEdge // "type:id#rel" -> edges
	req   map[string]any
	// fixpoint mode: get reads the tables of the previous round.
	member, folderView map[string]tri // "g|u", "f|u"
	recursive          bool
	memo               map[string]tri
}

func newRefGraph(edges []refEdge, req map[string]any, groups, folders int, users []string, recursive bool) *refGraph {
	g := &refGraph{byObj: map[string][]refEdge{}, req: req, recursive: recursive, memo: map[string]tri{}}
	for _, e := range edges {
		k := e.resType + ":" + e.resID + "#" + e.rel
		g.byObj[k] = append(g.byObj[k], e)
	}
	if recursive {
		return g
	}
	// Iterate whole tables, starting from nothing, until no answer moves.
	// Kleene's operators are monotone in denied < conditional < allowed, so
	// this reaches the least fixpoint.
	g.member, g.folderView = map[string]tri{}, map[string]tri{}
	for changed := true; changed; {
		changed = false
		nm, nf := map[string]tri{}, map[string]tri{}
		for _, u := range users {
			for i := range groups {
				id := fmt.Sprint("g", i)
				nm[id+"|"+u] = g.memberStep(id, u)
			}
			for i := range folders {
				id := fmt.Sprint("f", i)
				nf[id+"|"+u] = g.folderStep(id, u)
			}
		}
		for k, v := range nm {
			if g.member[k].v != v.v {
				changed = true
			}
		}
		for k, v := range nf {
			if g.folderView[k].v != v.v {
				changed = true
			}
		}
		g.member, g.folderView = nm, nf
	}
	return g
}

func (g *refGraph) strip(t tri) tri {
	if g.recursive {
		return t
	}
	return tri{v: t.v}
}

func (g *refGraph) inGroup(id, u string) tri {
	if !g.recursive {
		return g.member[id+"|"+u]
	}
	k := "m|" + id + "|" + u
	if t, ok := g.memo[k]; ok {
		return t
	}
	t := g.memberStep(id, u)
	g.memo[k] = t
	return t
}

func (g *refGraph) viewsFolder(id, u string) tri {
	if !g.recursive {
		return g.folderView[id+"|"+u]
	}
	k := "f|" + id + "|" + u
	if t, ok := g.memo[k]; ok {
		return t
	}
	t := g.folderStep(id, u)
	g.memo[k] = t
	return t
}

// direct is the answer of a stored relation for user u: its edges naming u
// (or every user), and the group memberships it names.
func (g *refGraph) direct(obj, u string) tri {
	acc := tDeny
	for _, e := range g.byObj[obj] {
		c := g.strip(e.cav.eval(g.req))
		switch {
		case e.subType == "user" && (e.subID == u || e.subID == "*"):
			acc = kor(acc, c)
		case e.subType == "group":
			acc = kor(acc, kand(c, g.inGroup(e.subID, u)))
		}
	}
	return acc
}

func (g *refGraph) memberStep(id, u string) tri { return g.direct("group:"+id+"#member", u) }

func (g *refGraph) folderStep(id, u string) tri {
	acc := g.direct("folder:"+id+"#viewer", u)
	for _, e := range g.byObj["folder:"+id+"#parent"] {
		acc = kor(acc, kand(g.strip(e.cav.eval(g.req)), g.viewsFolder(e.subID, u)))
	}
	return acc
}

func (g *refGraph) docParentView(id, u string) tri {
	acc := tDeny
	for _, e := range g.byObj["doc:"+id+"#parent"] {
		acc = kor(acc, kand(g.strip(e.cav.eval(g.req)), g.viewsFolder(e.subID, u)))
	}
	return acc
}

func (g *refGraph) docEdit(id, u string) tri {
	return kor(g.direct("doc:"+id+"#owner", u), g.direct("doc:"+id+"#editor", u))
}

// answer is the reference's answer for typ:id#perm@user:u.
func (g *refGraph) answer(typ, id, perm, u string) tri {
	switch typ + "#" + perm {
	case "group#member":
		return g.inGroup(id, u)
	case "folder#view":
		return g.viewsFolder(id, u)
	case "doc#edit":
		return g.docEdit(id, u)
	case "doc#both":
		return kand(g.docEdit(id, u), g.docParentView(id, u))
	case "doc#view":
		base := kor(kor(g.direct("doc:"+id+"#viewer", u), g.docEdit(id, u)), g.docParentView(id, u))
		return kand(base, knot(g.direct("doc:"+id+"#banned", u)))
	}
	panic("no reference for " + typ + "#" + perm)
}

// refWorld generates random edges for refModel.
type refWorld struct {
	rng                   *rand.Rand
	users                 []string // named by relationships
	groups, folders, docs int
	acyclic               bool
}

var refStoredContexts = map[string][]map[string]any{
	"flag":       {nil, {"on": true}, {"on": false}},
	"on_shift":   {nil, {"shift_start": 9, "shift_end": 17}, {"shift_end": 17}},
	"ip_allowed": {nil, {"allowed": "10.0.0.0/8"}, {"allowed": "10.0.0.0/8", "client_ip": "8.8.8.8"}},
	"in_region":  {nil, {"regions": []any{"eu", "us"}}, {"region": "eu"}},
}

// refRequestContexts are the contexts each check is asked with; the last
// supplies every parameter.
var refRequestContexts = []map[string]any{
	nil,
	{"on": true, "hour": 10},
	{"on": false, "hour": 20, "client_ip": "10.1.2.3", "region": "eu"},
	{"on": true, "hour": 12, "shift_start": 11, "shift_end": 13, "client_ip": "192.168.1.1", "allowed": "192.168.0.0/16", "regions": []any{"us"}, "region": "us"},
}

func (w *refWorld) pick(names ...string) *refCaveat {
	n := names[w.rng.Intn(len(names))]
	if n == "" {
		return nil
	}
	ctxs := refStoredContexts[n]
	return &refCaveat{name: n, ctx: ctxs[w.rng.Intn(len(ctxs))]}
}

func (w *refWorld) user() string { return w.users[w.rng.Intn(len(w.users))] }

// pair returns two indexes below n, ordered a < b when the world is acyclic.
func (w *refWorld) pair(n int) (int, int, bool) {
	a, b := w.rng.Intn(n), w.rng.Intn(n)
	if w.acyclic {
		if a == b {
			return 0, 0, false
		}
		return min(a, b), max(a, b), true
	}
	return a, b, true
}

func (w *refWorld) edge() refEdge {
	for {
		switch w.rng.Intn(13) {
		case 0, 1:
			return refEdge{"group", fmt.Sprint("g", w.rng.Intn(w.groups)), "member", "user", w.user(), "", w.pick("", "on_shift", "flag")}
		case 2:
			// Nested groups point from higher to lower indexes when acyclic.
			lo, hi, ok := w.pair(w.groups)
			if ok {
				return refEdge{"group", fmt.Sprint("g", hi), "member", "group", fmt.Sprint("g", lo), "member", w.pick("", "flag")}
			}
		case 3:
			// Folders' parents have higher indexes when acyclic.
			lo, hi, ok := w.pair(w.folders)
			if ok {
				return refEdge{"folder", fmt.Sprint("f", lo), "parent", "folder", fmt.Sprint("f", hi), "", w.pick("", "flag")}
			}
		case 4:
			return refEdge{"folder", fmt.Sprint("f", w.rng.Intn(w.folders)), "viewer", "user", w.user(), "", w.pick("", "ip_allowed")}
		case 5:
			if w.rng.Intn(4) == 0 {
				return refEdge{"folder", fmt.Sprint("f", w.rng.Intn(w.folders)), "viewer", "user", "*", "", w.pick("", "flag")}
			}
		case 6:
			return refEdge{"folder", fmt.Sprint("f", w.rng.Intn(w.folders)), "viewer", "group", fmt.Sprint("g", w.rng.Intn(w.groups)), "member", w.pick("", "in_region")}
		default:
			d := fmt.Sprint("d", w.rng.Intn(w.docs))
			switch w.rng.Intn(7) {
			case 0:
				return refEdge{"doc", d, "parent", "folder", fmt.Sprint("f", w.rng.Intn(w.folders)), "", w.pick("", "in_region")}
			case 1:
				return refEdge{"doc", d, "owner", "user", w.user(), "", nil}
			case 2:
				return refEdge{"doc", d, "editor", "user", w.user(), "", w.pick("", "on_shift")}
			case 3:
				return refEdge{"doc", d, "editor", "group", fmt.Sprint("g", w.rng.Intn(w.groups)), "member", nil}
			case 4:
				return refEdge{"doc", d, "viewer", "user", w.user(), "", w.pick("", "ip_allowed")}
			case 5:
				return refEdge{"doc", d, "viewer", "group", fmt.Sprint("g", w.rng.Intn(w.groups)), "member", w.pick("", "flag")}
			case 6:
				return refEdge{"doc", d, "banned", "user", w.user(), "", w.pick("", "flag", "in_region")}
			}
		}
	}
}

// refState is a relationship as stored: its edge and its expiry (zero for
// none).
type refState struct {
	edge    refEdge
	expires time.Time
}

// refRevision is what the reference knows about one revision: its commit
// time and the relationships written by then.
type refRevision struct {
	rev  store.Revision
	at   time.Time
	rels map[string]refState
}

// live is the edges a snapshot at this revision sees: written by then,
// and not expired at its commit time.
func (r refRevision) live() []refEdge {
	keys := make([]string, 0, len(r.rels))
	for k := range r.rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []refEdge
	for _, k := range keys {
		s := r.rels[k]
		if s.expires.IsZero() || r.at.Before(s.expires) {
			out = append(out, s.edge)
		}
	}
	return out
}

func storeUpdate(t testing.TB, e refEdge, expires time.Time) store.Update {
	rel, err := store.ParseRelationship(e.key())
	if err != nil {
		t.Fatal(err)
	}
	u := store.Update{Op: store.OpTouch, Relationship: rel, ExpiresAt: expires}
	if e.cav != nil {
		u.Caveat = &store.Caveat{Name: e.cav.name, Context: e.cav.ctx}
	}
	return u
}

// refTimeline writes random batches of touches and deletes, some with
// expiries landing exactly on, just before or just after later commit
// times, while a fake clock moves on between batches. It returns what the
// reference knows of every revision.
func refTimeline(t testing.TB, st *store.Store, clk *clock.Fake, w *refWorld, steps int) []refRevision {
	t0 := clk.Now()
	cur := map[string]refState{}
	var revs []refRevision
	steps_ := []time.Duration{time.Nanosecond, time.Second, 10 * time.Second}
	for range steps {
		clk.Advance(steps_[w.rng.Intn(len(steps_))])
		now := clk.Now()
		var ups []store.Update
		next := map[string]refState{}
		for k, v := range cur {
			next[k] = v
		}
		touched := map[string]bool{}
		for range 2 + w.rng.Intn(10) {
			if len(cur) > 0 && w.rng.Intn(8) == 0 {
				// Delete one stored relationship (a no-op if it expired).
				keys := make([]string, 0, len(cur))
				for k := range cur {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				k := keys[w.rng.Intn(len(keys))]
				if touched[k] {
					continue
				}
				touched[k] = true
				rel, _ := store.ParseRelationship(k)
				ups = append(ups, store.Update{Op: store.OpDelete, Relationship: rel})
				delete(next, k)
				continue
			}
			e := w.edge()
			if touched[e.key()] {
				continue
			}
			touched[e.key()] = true
			var exp time.Time
			switch w.rng.Intn(10) {
			case 0:
				exp = now // expired at its own commit
			case 1:
				exp = now.Add(time.Nanosecond)
			case 2, 3:
				// On a likely later commit time, or a nanosecond either side.
				exp = now.Add(steps_[w.rng.Intn(len(steps_))] + time.Duration(w.rng.Intn(3)-1))
			case 4:
				exp = t0.Add(time.Second) // perhaps already past
			}
			ups = append(ups, storeUpdate(t, e, exp))
			next[e.key()] = refState{edge: e, expires: exp}
		}
		if len(ups) == 0 {
			continue
		}
		rev, err := st.Write(ups, nil)
		if err != nil {
			t.Fatalf("write %v: %v", ups, err)
		}
		cur = next
		if len(revs) > 0 && rev == revs[len(revs)-1].rev {
			// Every update was a no-op (an identical touch, or a delete of
			// a relationship already expired), so no revision was made.
			continue
		}
		at, err := st.RevisionTime(rev)
		if err != nil || !at.Equal(now) {
			t.Fatalf("revision %d committed at %v (%v), want %v", rev, at, err, now)
		}
		revs = append(revs, refRevision{rev: rev, at: at, rels: next})
	}
	return revs
}

func (r tri) String() string {
	if r.v == Conditional {
		return fmt.Sprintf("conditional%v", r.names)
	}
	return r.v.String()
}

// fill returns req with the names given values from the last request
// context, which supplies every parameter.
func fill(req map[string]any, names []string) map[string]any {
	full := refRequestContexts[len(refRequestContexts)-1]
	out := map[string]any{}
	for k, v := range req {
		out[k] = v
	}
	for _, n := range names {
		out[n] = full[n]
	}
	return out
}

// TestCaveatsAndExpiryMatchReference checks CheckResult, LookupResources and
// LookupSubjects at every revision of random timelines over refModel, with
// a cached and an uncached engine, against the reference.
//
// Permissionship must always match. On graphs without cycles, where the
// answer is a plain Kleene formula, the missing parameters must match too.
// On graphs with cycles, the least fixpoint over sets of missing names is
// coarser than what a walk over simple paths can report, so there each
// conditional answer must instead turn definite, and match the reference,
// once the parameters it names are supplied.
func TestCaveatsAndExpiryMatchReference(t *testing.T) {
	seeds := 16
	if testing.Short() {
		seeds = 6
	}
	t0 := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	bg := context.Background()
	counts := map[string]int{}
	for seed := range int64(seeds) {
		rng := rand.New(rand.NewSource(seed))
		w := &refWorld{rng: rng, users: []string{"u0", "u1", "u2", "u3"},
			groups: 2 + rng.Intn(4), folders: 2 + rng.Intn(4), docs: 4, acyclic: seed%2 == 0}
		// "nobody" is named by no relationship: only a wildcard reaches it.
		users := append(slices.Clone(w.users), "nobody")
		clk := clock.NewFake(t0)
		st, err := store.Open(store.Options{Clock: clk})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.WriteSchema(refModel); err != nil {
			t.Fatal(err)
		}
		sc, _ := st.Schema()
		revs := refTimeline(t, st, clk, w, 8)
		cached := New(st, NewCache(20_000))
		fresh := New(st, nil)
		cf := &caveatFixture{t: t, st: st, sc: sc, eng: cached}

		// Newest first, then oldest first again: the cache must not carry
		// an answer across revisions.
		order := slices.Clone(revs)
		slices.Reverse(order)
		order = append(order, revs...)
		for pass, rv := range order {
			engines := []*Engine{cached, fresh}
			if pass >= len(revs) {
				engines = engines[:1] // the second pass is for the cache
			}
			edges := rv.live()
			show := func() string {
				var b strings.Builder
				for _, e := range edges {
					fmt.Fprintf(&b, "  %s%s\n", e.key(), e.cav)
				}
				return b.String()
			}
			for ci, req := range refRequestContexts {
				fix := newRefGraph(edges, req, w.groups, w.folders, users, false)
				var rec *refGraph
				if w.acyclic {
					rec = newRefGraph(edges, req, w.groups, w.folders, users, true)
				}
				compare := func(where string, got Result, typ, id, perm, u string) {
					t.Helper()
					want := fix.answer(typ, id, perm, u)
					if rec != nil {
						if r := rec.answer(typ, id, perm, u); r.v != want.v {
							t.Fatalf("the two references disagree on %s:%s#%s@user:%s: %s and %s", typ, id, perm, u, r, want)
						} else {
							want = r
						}
					}
					ok := got.Permissionship == want.v
					if ok && rec != nil && got.Permissionship == Conditional {
						ok = slices.Equal(got.Missing, want.names)
					}
					if !ok {
						t.Fatalf("seed %d, revision %d at %s, context %v: %s %s:%s#%s@user:%s = %s, reference says %s\nlive relationships:\n%s",
							seed, rv.rev, rv.at.Format(time.RFC3339Nano), req, where, typ, id, perm, u, answer(got), want, show())
					}
					counts[where+" "+want.v.String()]++
				}
				objects := []struct {
					typ   string
					n     int
					perms []string
				}{{"group", w.groups, []string{"member"}}, {"folder", w.folders, []string{"view"}}, {"doc", w.docs, []string{"view", "edit", "both"}}}
				for _, o := range objects {
					for i := range o.n {
						id := fmt.Sprint(o.typ[:1], i)
						for _, perm := range o.perms {
							for _, u := range users {
								q := Request{ResourceType: o.typ, ResourceID: id, Permission: perm, Subject: store.Subject{Type: "user", ID: u}}
								for _, eng := range engines {
									got, _, err := eng.CheckResult(bg, sc, rv.rev, q, req)
									if err != nil {
										t.Fatalf("seed %d: %v: %v", seed, q, err)
									}
									compare("check", got, o.typ, id, perm, u)
									if got.Permissionship != Conditional || w.acyclic {
										continue
									}
									// Supplying what it names decides it.
									more := fill(req, got.Missing)
									got2, _, err := eng.CheckResult(bg, sc, rv.rev, q, more)
									want2 := newRefGraph(edges, more, w.groups, w.folders, users, false).answer(o.typ, id, perm, u)
									if err != nil || got2.Permissionship == Conditional || got2.Permissionship != want2.v {
										t.Fatalf("seed %d, revision %d: %v with %v = %s (%v), then with %v = %s, reference %s\nlive relationships:\n%s",
											seed, rv.rev, q, req, answer(got), err, more, answer(got2), want2, show())
									}
									counts["filled"]++
								}
							}
						}
					}
				}
				// Lookups at this revision give every user the same answers.
				for _, u := range users {
					res, err := cached.LookupResourcesContext(bg, sc, st, rv.rev, "doc", "view", store.Subject{Type: "user", ID: u}, "", 0, req)
					if err != nil {
						t.Fatal(err)
					}
					for i := range w.docs {
						id := fmt.Sprint("d", i)
						got := denied
						if slices.Contains(res.IDs, id) {
							got = allowed
						}
						for _, c := range res.Conditional {
							if c.ID == id {
								got = Result{Permissionship: Conditional, Missing: c.Missing}
							}
						}
						compare("lookup-resources", got, "doc", id, "view", u)
					}
				}
				for i := range w.docs {
					for _, perm := range []string{"view", "edit", "both"} {
						found, _, err := cf.lookupAllSubjects(rv.rev, fmt.Sprint("doc:d", i), perm, "user", req, 1+ci)
						if err != nil {
							t.Fatal(err)
						}
						for _, u := range users {
							compare("lookup-subjects", answerFor(found, u), "doc", fmt.Sprint("d", i), perm, u)
						}
					}
				}
			}
		}
	}
	t.Logf("answers: %v", counts)
	for _, k := range []string{"check allowed", "check denied", "check conditional", "lookup-resources conditional", "lookup-subjects conditional", "filled"} {
		if counts[k] == 0 {
			t.Errorf("the timelines never exercise %q: %v", k, counts)
		}
	}
}

// The reference's caveats agree with the schema's CEL on every stored and
// request context the random graphs use, so a disagreement above is the
// walk's, not the reference's.
func TestReferenceCaveatsMatchCEL(t *testing.T) {
	sc, err := schema.Parse(refModel)
	if err != nil {
		t.Fatal(err)
	}
	for name, stored := range refStoredContexts {
		cv := sc.Caveats[name]
		for _, sctx := range stored {
			for _, req := range append(slices.Clone(refRequestContexts), map[string]any{"hour": 9}, map[string]any{"hour": 17, "shift_start": 18}) {
				merged := map[string]any{}
				for k, v := range req {
					if _, ok := cv.Param(k); ok {
						merged[k] = v
					}
				}
				for k, v := range sctx {
					merged[k] = v
				}
				res, err := cv.Program.Eval(merged)
				if err != nil {
					t.Fatalf("%s %v %v: %v", name, sctx, req, err)
				}
				got := tri{v: Conditional, names: res.Missing}
				if res.Known() {
					got = boolTri(res.Value == true)
				}
				want := (&refCaveat{name: name, ctx: sctx}).eval(req)
				if got.String() != want.String() {
					t.Errorf("%s stored %v, request %v: CEL %s, reference %s", name, sctx, req, got, want)
				}
			}
		}
	}
}
