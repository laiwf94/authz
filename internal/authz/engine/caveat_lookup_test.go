package engine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/store"
)

func TestLookupsWithCaveatContext(t *testing.T) {
	e, _, m := caveatFixture(t)
	bg := context.Background()
	w, err := e.Write(bg, WriteRequest{Updates: []store.Update{
		{Op: store.OpTouch, Relationship: rel(t, "doc:a#viewer@user:alice")},
		{Op: store.OpTouch, Relationship: rel(t, "doc:b#viewer@user:alice"), Caveat: &store.Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}},
		{Op: store.OpTouch, Relationship: rel(t, "doc:c#editor@user:alice"), Caveat: &store.Caveat{Name: "tier_at_least", Context: map[string]any{"min": 2}}},
		{Op: store.OpTouch, Relationship: rel(t, "doc:b#viewer@user:bob")},
		{Op: store.OpTouch, Relationship: rel(t, "doc:b#editor@user:carol"), Caveat: &store.Caveat{Name: "tier_at_least"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	at := Consistency{Mode: AtExactSnapshot, Token: w.At.Token}
	alice := subj(t, "user:alice")
	for _, c := range []struct {
		ctx  map[string]any
		ids  []string
		cond []check.ConditionalID
	}{
		{nil, []string{"a"}, []check.ConditionalID{{ID: "b", Missing: []string{"client_ip"}}, {ID: "c", Missing: []string{"tier"}}}},
		{map[string]any{"client_ip": "10.1.1.1", "tier": 1}, []string{"a", "b"}, nil},
		{map[string]any{"client_ip": "8.8.8.8", "tier": 3}, []string{"a", "c"}, nil},
		{map[string]any{"tier": 3}, []string{"a", "c"}, []check.ConditionalID{{ID: "b", Missing: []string{"client_ip"}}}},
	} {
		res, err := e.LookupResources(bg, LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: alice, Consistency: at, Context: c.ctx})
		if err != nil || !reflect.DeepEqual(res.ResourceIDs, c.ids) || !reflect.DeepEqual(res.Conditional, c.cond) || res.At != w.At {
			t.Fatalf("lookup with %v: %+v %v", c.ctx, res, err)
		}
	}
	// A page of one counts a conditional object.
	page, err := e.LookupResources(bg, LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: alice, Consistency: at, Cursor: "a", Limit: 1})
	if err != nil || len(page.ResourceIDs) != 0 || len(page.Conditional) != 1 || page.Cursor != "b" {
		t.Fatalf("second page: %+v %v", page, err)
	}

	before := m.Counter("grantd_check_caveats_total", "", "").Value()
	subs, err := e.LookupSubjects(bg, LookupSubjectsRequest{ResourceType: "doc", ResourceID: "b", Permission: "view", SubjectType: "user", Consistency: at})
	want := []check.FoundSubject{{ID: "alice", Conditional: true, Missing: []string{"client_ip"}}, {ID: "bob"}, {ID: "carol", Conditional: true, Missing: []string{"min", "tier"}}}
	if err != nil || !reflect.DeepEqual(subs.Subjects, want) {
		t.Fatalf("lookup subjects: %+v %v", subs, err)
	}
	if got := m.Counter("grantd_check_caveats_total", "", "").Value() - before; got != 2 {
		t.Fatalf("lookup subjects counted %d caveats, want 2", got)
	}
	subs, err = e.LookupSubjects(bg, LookupSubjectsRequest{ResourceType: "doc", ResourceID: "b", Permission: "view", SubjectType: "user", Consistency: at,
		Context: map[string]any{"client_ip": "10.0.0.1", "tier": 5, "min": 9}})
	if err != nil || !reflect.DeepEqual(subs.Subjects, []check.FoundSubject{{ID: "alice"}, {ID: "bob"}}) {
		t.Fatalf("lookup subjects with a context: %+v %v", subs, err)
	}
	// A caveat that fails at run time fails the lookup.
	if _, err := e.LookupSubjects(bg, LookupSubjectsRequest{ResourceType: "doc", ResourceID: "b", Permission: "view", SubjectType: "user", Consistency: at,
		Context: map[string]any{"client_ip": "not an address"}}); err == nil {
		t.Fatal("bad client_ip accepted")
	}

	// Expand names each caveat with its stored context.
	ex, err := e.Expand(bg, ExpandRequest{ResourceType: "doc", ResourceID: "b", Permission: "viewer", Consistency: at})
	if err != nil {
		t.Fatal(err)
	}
	var caveats []string
	for _, n := range ex.Tree.Root.Children {
		caveats = append(caveats, n.Subject+" "+n.Caveat)
		if n.Caveat == "ip_allowed" && !reflect.DeepEqual(n.CaveatContext, map[string]any{"allowed": "10.0.0.0/8"}) {
			t.Fatalf("stored context %v", n.CaveatContext)
		}
	}
	if !reflect.DeepEqual(caveats, []string{"user:alice ip_allowed", "user:bob "}) {
		t.Fatalf("expand: %v", caveats)
	}
}

func TestReadRelationshipsCaveatsAndExpiry(t *testing.T) {
	e, clk, _ := caveatFixture(t)
	bg := context.Background()
	expires := t0.Add(time.Hour)
	w, err := e.Write(bg, WriteRequest{Updates: []store.Update{
		{Op: store.OpTouch, Relationship: rel(t, "doc:a#viewer@user:alice")},
		{Op: store.OpTouch, Relationship: rel(t, "doc:a#viewer@user:bob"), ExpiresAt: expires},
		{Op: store.OpTouch, Relationship: rel(t, "doc:a#viewer@user:carol"), Caveat: &store.Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}},
		{Op: store.OpTouch, Relationship: rel(t, "doc:a#editor@user:dave"), ExpiresAt: expires, Caveat: &store.Caveat{Name: "tier_at_least"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	at := Consistency{Mode: AtExactSnapshot, Token: w.At.Token}
	res, err := e.ReadRelationships(bg, ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Consistency: at})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, r := range res.Relationships {
		s := r.String()
		if res.Caveats[i] != nil {
			s += " " + res.Caveats[i].Name
		}
		if !res.ExpiresAt[i].IsZero() {
			s += " " + res.ExpiresAt[i].Format(time.RFC3339)
		}
		got = append(got, s)
	}
	want := []string{"doc:a#editor@user:dave tier_at_least 2026-11-23T10:00:00Z", "doc:a#viewer@user:alice",
		"doc:a#viewer@user:bob 2026-11-23T10:00:00Z", "doc:a#viewer@user:carol ip_allowed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read: %q", got)
	}
	// Pages are cut at the limit with their caveats and expiries; a page
	// without either has neither slice.
	p, err := e.ReadRelationships(bg, ReadRequest{Filter: store.Filter{ResourceType: "doc", Relation: "viewer"}, Consistency: at, Limit: 1})
	if err != nil || len(p.Relationships) != 1 || p.Caveats != nil || p.ExpiresAt != nil {
		t.Fatalf("first viewer page: %+v %v", p, err)
	}
	p, err = e.ReadRelationships(bg, ReadRequest{Filter: store.Filter{ResourceType: "doc", Relation: "viewer"}, Consistency: at, Cursor: p.Cursor, Limit: 1})
	if err != nil || p.Relationships[0].SubjectID != "bob" || p.Caveats != nil || !p.ExpiresAt[0].Equal(expires) {
		t.Fatalf("second viewer page: %+v %v", p, err)
	}
	// Once the clock passes the expiry, a read at the head leaves the
	// expired relationships out; the old snapshot still has them.
	clk.Set(expires)
	if _, err := e.Write(bg, WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: rel(t, "doc:b#viewer@user:erin")}}}); err != nil {
		t.Fatal(err)
	}
	head, err := e.ReadRelationships(bg, ReadRequest{Filter: store.Filter{ResourceType: "doc", ResourceID: "a"}, Consistency: Consistency{Mode: FullyConsistent}})
	if err != nil || len(head.Relationships) != 2 || head.ExpiresAt != nil || head.Caveats[1] == nil || head.Caveats[1].Name != "ip_allowed" {
		t.Fatalf("read after expiry: %+v %v", head, err)
	}
	old, err := e.ReadRelationships(bg, ReadRequest{Filter: store.Filter{ResourceType: "doc", ResourceID: "a"}, Consistency: at})
	if err != nil || len(old.Relationships) != 4 {
		t.Fatalf("old snapshot after expiry: %+v %v", old, err)
	}
}
