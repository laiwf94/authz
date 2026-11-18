package engine

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/clock"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const caveatSchema = `
caveat ip_allowed(allowed cidr, client_ip ipaddress) { allowed.containsIP(client_ip) }
caveat tier_at_least(min int, tier int) { tier >= min }
definition user {}
definition doc {
  relation viewer: user | user with ip_allowed
  relation editor: user with tier_at_least
  permission view = viewer + editor
}`

var t0 = time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)

// caveatFixture is an engine over a store with caveatSchema whose commit
// times come from a fake clock.
func caveatFixture(t *testing.T) (*Local, *clock.Fake, *metrics.Registry) {
	t.Helper()
	clk := clock.NewFake(t0)
	st, err := store.Open(store.Options{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.WriteSchema(caveatSchema); err != nil {
		t.Fatal(err)
	}
	tok, err := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	e, err := New(Options{Store: st, Tokens: tok, CacheSize: 1000, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	return e, clk, m
}

func rel(t *testing.T, s string) store.Relationship {
	t.Helper()
	r, err := store.ParseRelationship(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func caveatCheck(t *testing.T, e *Local, id, subject string, c Consistency, ctx map[string]any) CheckResult {
	t.Helper()
	res, err := e.Check(context.Background(), CheckRequest{ResourceType: "doc", ResourceID: id, Permission: "view",
		Subject: subj(t, subject), Consistency: c, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed != (res.Permissionship == check.Allowed) {
		t.Fatalf("Allowed %v with permissionship %v", res.Allowed, res.Permissionship)
	}
	if (len(res.Missing) > 0) != (res.Permissionship == check.Conditional) {
		t.Fatalf("missing %v with permissionship %v", res.Missing, res.Permissionship)
	}
	return res
}

func TestCheckCaveatContext(t *testing.T) {
	e, _, m := caveatFixture(t)
	bg := context.Background()
	var b bytes.Buffer
	if err := m.Write(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "grantd_check_caveats_total") {
		t.Fatal("the caveat counter is exposed before any caveat was evaluated")
	}
	w, err := e.Write(bg, WriteRequest{Updates: []store.Update{
		{Op: store.OpTouch, Relationship: rel(t, "doc:plan#viewer@user:alice"),
			Caveat: &store.Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}},
		{Op: store.OpTouch, Relationship: rel(t, "doc:plan#editor@user:bob"),
			Caveat: &store.Caveat{Name: "tier_at_least", Context: map[string]any{"min": 2}}},
		{Op: store.OpTouch, Relationship: rel(t, "doc:open#viewer@user:alice")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	at := Consistency{Mode: AtLeastAsFresh, Token: w.At.Token}

	for _, c := range []struct {
		id, subject string
		ctx         map[string]any
		want        check.Permissionship
		missing     []string
	}{
		{"plan", "user:alice", nil, check.Conditional, []string{"client_ip"}},
		{"plan", "user:alice", map[string]any{"client_ip": "10.1.2.3"}, check.Allowed, nil},
		{"plan", "user:alice", map[string]any{"client_ip": "192.168.0.1"}, check.Denied, nil},
		// The stored context wins over the request's.
		{"plan", "user:alice", map[string]any{"client_ip": "10.1.2.3", "allowed": "192.168.0.0/16"}, check.Allowed, nil},
		{"plan", "user:bob", map[string]any{"tier": 3}, check.Allowed, nil},
		{"plan", "user:bob", map[string]any{"tier": 1}, check.Denied, nil},
		{"plan", "user:bob", map[string]any{"client_ip": "10.1.2.3"}, check.Conditional, []string{"tier"}},
		{"plan", "user:carol", nil, check.Denied, nil},
		// A relationship without a caveat needs no context.
		{"open", "user:alice", nil, check.Allowed, nil},
	} {
		got := caveatCheck(t, e, c.id, c.subject, at, c.ctx)
		if got.Permissionship != c.want || !reflect.DeepEqual(got.Missing, c.missing) {
			t.Errorf("%s %s with %v: %v %v, want %v %v", c.id, c.subject, c.ctx, got.Permissionship, got.Missing, c.want, c.missing)
		}
		if got.At != w.At {
			t.Errorf("%s %s read at %v, want %v", c.id, c.subject, got.At, w.At)
		}
	}

	b.Reset()
	if err := m.Write(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "grantd_check_caveats_total ") {
		t.Fatalf("no caveat counter after caveated checks:\n%s", b.String())
	}

	// A context value of the wrong type fails the check; one too large is
	// refused before it runs.
	_, err = e.Check(bg, CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
		Subject: subj(t, "user:alice"), Consistency: at, Context: map[string]any{"client_ip": 7}})
	if !errors.Is(err, check.ErrCaveat) {
		t.Fatalf("wrong type: %v, want ErrCaveat", err)
	}
	_, err = e.Check(bg, CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
		Subject: subj(t, "user:alice"), Consistency: at, Context: map[string]any{"pad": strings.Repeat("x", check.MaxContextSize)}})
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("oversized context: %v, want store.ErrInvalid", err)
	}
}

func TestCheckBulkCaveatContext(t *testing.T) {
	e, _, _ := caveatFixture(t)
	bg := context.Background()
	w, err := e.Write(bg, WriteRequest{Updates: []store.Update{
		{Op: store.OpTouch, Relationship: rel(t, "doc:plan#viewer@user:alice"),
			Caveat: &store.Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	alice := subj(t, "user:alice")
	item := func(ctx map[string]any) CheckItem {
		return CheckItem{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: alice, Context: ctx}
	}
	res, err := e.CheckBulk(bg, CheckBulkRequest{Consistency: Consistency{Mode: AtExactSnapshot, Token: w.At.Token}, Items: []CheckItem{
		item(map[string]any{"client_ip": "10.0.0.1"}),
		item(nil),
		item(map[string]any{"client_ip": "8.8.8.8"}),
		item(map[string]any{"client_ip": true}),
		{ResourceType: "nope", ResourceID: "x", Permission: "view", Subject: alice},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []ItemResult{
		{Allowed: true, Permissionship: check.Allowed},
		{Permissionship: check.Conditional, Missing: []string{"client_ip"}},
		{Permissionship: check.Denied},
	}
	if !reflect.DeepEqual(res.Results[:3], want) {
		t.Fatalf("results %+v, want %+v", res.Results[:3], want)
	}
	if r := res.Results[3]; !errors.Is(r.Err, check.ErrCaveat) || r.Allowed || r.Permissionship != check.Denied {
		t.Fatalf("wrong type item: %+v", r)
	}
	if r := res.Results[4]; !errors.Is(r.Err, check.ErrUnknownType) {
		t.Fatalf("unknown type item: %+v", r)
	}
	if res.At != w.At {
		t.Fatalf("read at %v, want %v", res.At, w.At)
	}
	// Each item is answered as a single check with its context would be.
	for i, it := range []CheckItem{item(map[string]any{"client_ip": "10.0.0.1"}), item(nil)} {
		single, err := e.Check(bg, CheckRequest{ResourceType: it.ResourceType, ResourceID: it.ResourceID, Permission: it.Permission,
			Subject: it.Subject, Context: it.Context, Consistency: Consistency{Mode: AtExactSnapshot, Token: w.At.Token}})
		if err != nil {
			t.Fatal(err)
		}
		if single.Permissionship != res.Results[i].Permissionship || !reflect.DeepEqual(single.Missing, res.Results[i].Missing) {
			t.Fatalf("item %d: bulk %+v, single %+v", i, res.Results[i], single)
		}
	}
}

// TestCheckExpiringThroughEngine writes a time-limited share through the
// engine and checks it at the revisions on either side of its expiry.
func TestCheckExpiringThroughEngine(t *testing.T) {
	e, clk, _ := caveatFixture(t)
	bg := context.Background()
	expires := t0.Add(time.Hour)
	w, err := e.Write(bg, WriteRequest{Updates: []store.Update{
		{Op: store.OpTouch, Relationship: rel(t, "doc:plan#viewer@user:alice"), ExpiresAt: expires},
	}})
	if err != nil {
		t.Fatal(err)
	}
	before := Consistency{Mode: AtExactSnapshot, Token: w.At.Token}
	if r := caveatCheck(t, e, "plan", "user:alice", before, nil); !r.Allowed {
		t.Fatalf("before expiry: %+v", r)
	}

	clk.Set(expires.Add(-time.Nanosecond))
	w1, err := e.Write(bg, WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: rel(t, "doc:other#viewer@user:bob")}}})
	if err != nil {
		t.Fatal(err)
	}
	if r := caveatCheck(t, e, "plan", "user:alice", Consistency{Mode: AtExactSnapshot, Token: w1.At.Token}, nil); !r.Allowed {
		t.Fatalf("1ns before expiry: %+v", r)
	}

	clk.Set(expires)
	w2, err := e.Write(bg, WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: rel(t, "doc:other#viewer@user:carol")}}})
	if err != nil {
		t.Fatal(err)
	}
	if r := caveatCheck(t, e, "plan", "user:alice", Consistency{Mode: AtExactSnapshot, Token: w2.At.Token}, nil); r.Permissionship != check.Denied {
		t.Fatalf("at expiry: %+v", r)
	}
	if r := caveatCheck(t, e, "plan", "user:alice", Consistency{Mode: FullyConsistent}, nil); r.Allowed {
		t.Fatalf("at the head after expiry: %+v", r)
	}
	// The snapshot from before the expiry still sees the share.
	if r := caveatCheck(t, e, "plan", "user:alice", before, nil); !r.Allowed {
		t.Fatalf("old snapshot after expiry: %+v", r)
	}

	// A write that combines a caveat and an expiry: conditional until the
	// expiry, then denied whatever the context.
	clk.Set(t0.Add(2 * time.Hour))
	w3, err := e.Write(bg, WriteRequest{Updates: []store.Update{
		{Op: store.OpTouch, Relationship: rel(t, "doc:plan#viewer@user:dave"), ExpiresAt: t0.Add(3 * time.Hour),
			Caveat: &store.Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"client_ip": "10.0.0.9"}
	if r := caveatCheck(t, e, "plan", "user:dave", Consistency{Mode: AtExactSnapshot, Token: w3.At.Token}, in); !r.Allowed {
		t.Fatalf("caveated share before expiry: %+v", r)
	}
	clk.Set(t0.Add(3 * time.Hour))
	w4, err := e.Write(bg, WriteRequest{Updates: []store.Update{{Op: store.OpDelete, Relationship: rel(t, "doc:other#viewer@user:bob")}}})
	if err != nil {
		t.Fatal(err)
	}
	if r := caveatCheck(t, e, "plan", "user:dave", Consistency{Mode: AtExactSnapshot, Token: w4.At.Token}, in); r.Permissionship != check.Denied {
		t.Fatalf("caveated share after expiry: %+v", r)
	}
	if r := caveatCheck(t, e, "plan", "user:dave", Consistency{Mode: AtExactSnapshot, Token: w4.At.Token}, nil); r.Permissionship != check.Denied {
		t.Fatalf("caveated share after expiry, no context: %+v", r)
	}
}
