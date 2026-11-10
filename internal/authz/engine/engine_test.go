package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const schemaSrc = `
definition user {}
definition group { relation member: user | group#member }
definition doc {
  relation owner: user
  relation viewer: user | group#member | user:*
  relation banned: user
  permission view = (viewer + owner) - banned
}`

type fixture struct {
	st  *store.Store
	tok *token.Issuer
	e   *Local
	m   *metrics.Registry
}

func newFixture(t testing.TB, opts Options) *fixture {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tok, err := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	opts.Store, opts.Tokens = st, tok
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	e, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, tok: tok, e: e, m: opts.Metrics}
}

func (f *fixture) schema(t testing.TB) {
	t.Helper()
	if _, err := f.st.WriteSchema(schemaSrc); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) write(t testing.TB, ops ...string) Snapshot {
	t.Helper()
	var ups []store.Update
	for _, o := range ops {
		op, rel, _ := strings.Cut(o, " ")
		r, err := store.ParseRelationship(rel)
		if err != nil {
			t.Fatal(err)
		}
		ups = append(ups, store.Update{Op: store.Op(op), Relationship: r})
	}
	res, err := f.e.Write(context.Background(), WriteRequest{Updates: ups})
	if err != nil {
		t.Fatal(err)
	}
	return res.At
}

func subj(t testing.TB, s string) store.Subject {
	t.Helper()
	sub, err := store.ParseSubject(s, false)
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func (f *fixture) check(t testing.TB, resource, perm, subject string, c Consistency) CheckResult {
	t.Helper()
	typ, id, _ := strings.Cut(resource, ":")
	res, err := f.e.Check(context.Background(), CheckRequest{ResourceType: typ, ResourceID: id, Permission: perm,
		Subject: subj(t, subject), Consistency: c})
	if err != nil {
		t.Fatalf("check %s %s %s: %v", resource, perm, subject, err)
	}
	return res
}

func TestNewRefusesMissingParts(t *testing.T) {
	st, _ := store.Open(store.Options{})
	defer st.Close()
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{1}, token.KeySize))
	for name, o := range map[string]Options{
		"no store":  {Tokens: tok},
		"no tokens": {Store: st},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted %+v", name, o)
		}
	}
	e, err := New(Options{Store: st, Tokens: tok})
	if err != nil {
		t.Fatal(err)
	}
	if e.Tokens() != tok || e.quantum != DefaultQuantum {
		t.Fatalf("defaults not applied: quantum %v", e.quantum)
	}
}

func TestCheckAndTokens(t *testing.T) {
	f := newFixture(t, Options{CacheSize: 100, Quantum: time.Hour})
	f.schema(t)
	w := f.write(t, "touch group:eng#member@user:alice", "touch doc:plan#viewer@group:eng#member", "touch doc:plan#owner@user:olga")
	if w.Revision != f.st.Head() || w.Token != f.tok.Encode(w.Revision) {
		t.Fatalf("write snapshot %+v, head %d", w, f.st.Head())
	}
	fresh := Consistency{Mode: AtLeastAsFresh, Token: w.Token}
	for _, c := range []struct {
		subject string
		want    bool
	}{{"user:alice", true}, {"user:olga", true}, {"user:bob", false}, {"group:eng#member", true}} {
		res := f.check(t, "doc:plan", "view", c.subject, fresh)
		if res.Allowed != c.want {
			t.Errorf("%s view doc:plan = %v, want %v", c.subject, res.Allowed, c.want)
		}
		if res.At.Revision < w.Revision || res.At.Token != f.tok.Encode(res.At.Revision) {
			t.Errorf("checked at %+v, older than the write %d or with a foreign token", res.At, w.Revision)
		}
	}
	// A ban in a later revision: the old token at its exact snapshot still
	// allows, the new token denies.
	ban := f.write(t, "touch doc:plan#banned@user:alice")
	if !f.check(t, "doc:plan", "view", "user:alice", Consistency{Mode: AtExactSnapshot, Token: w.Token}).Allowed {
		t.Error("exact snapshot before the ban should allow")
	}
	if f.check(t, "doc:plan", "view", "user:alice", Consistency{Mode: AtLeastAsFresh, Token: ban.Token}).Allowed {
		t.Error("at least as fresh as the ban should deny")
	}
	if res := f.check(t, "doc:plan", "view", "user:alice", Consistency{Mode: FullyConsistent}); res.Allowed || res.At.Revision != f.st.Head() {
		t.Errorf("fully consistent = %+v, head %d", res, f.st.Head())
	}
	if f.m.Counter("grantd_check_dispatches_total", "", "").Value() == 0 {
		t.Error("checks recorded no dispatches")
	}
}

func TestMinimizeLatencySharesASnapshot(t *testing.T) {
	f := newFixture(t, Options{Quantum: time.Hour})
	f.schema(t)
	first := f.check(t, "doc:plan", "view", "user:zoe", Consistency{})
	f.write(t, "touch doc:plan#viewer@user:zoe")
	again := f.check(t, "doc:plan", "view", "user:zoe", Consistency{Mode: MinimizeLatency})
	if again.Allowed || again.At != first.At {
		t.Fatalf("minimize_latency left the shared snapshot within the quantum: %+v then %+v", first.At, again.At)
	}
	f.e.snapMu.Lock()
	f.e.snapTime = time.Time{}
	f.e.snapMu.Unlock()
	if res := f.check(t, "doc:plan", "view", "user:zoe", Consistency{}); !res.Allowed || res.At.Revision != f.st.Head() {
		t.Fatalf("snapshot did not refresh after the quantum: %+v", res)
	}
}

func TestSnapshotOptionIsUsed(t *testing.T) {
	var at store.Revision
	f := newFixture(t, Options{Snapshot: func() store.Revision { return at }})
	f.schema(t)
	at = f.st.Head()
	f.write(t, "touch doc:plan#viewer@user:zoe")
	if res := f.check(t, "doc:plan", "view", "user:zoe", Consistency{}); res.Allowed || res.At.Revision != at {
		t.Fatalf("minimize_latency did not read the supplied snapshot %d: %+v", at, res)
	}
	// at_least_as_fresh takes the supplied snapshot when it is new enough
	// and the head otherwise.
	old := f.tok.Encode(at)
	if res := f.check(t, "doc:plan", "view", "user:zoe", Consistency{Mode: AtLeastAsFresh, Token: old}); res.At.Revision != at {
		t.Fatalf("fresh-enough shared snapshot not used: %+v", res)
	}
	newer := f.tok.Encode(f.st.Head())
	if res := f.check(t, "doc:plan", "view", "user:zoe", Consistency{Mode: AtLeastAsFresh, Token: newer}); !res.Allowed || res.At.Revision != f.st.Head() {
		t.Fatalf("stale shared snapshot used for a newer token: %+v", res)
	}
}

func TestConsistencyErrors(t *testing.T) {
	f := newFixture(t, Options{})
	f.schema(t)
	w := f.write(t, "touch doc:plan#viewer@user:zoe")
	other, _ := token.NewIssuer(bytes.Repeat([]byte{9}, token.KeySize))
	for _, c := range []struct {
		name string
		c    Consistency
		want error
		msg  string
	}{
		{"unknown mode", Consistency{Mode: "eventually"}, ErrInvalidArgument, `unknown consistency mode "eventually"`},
		{"token without mode", Consistency{Token: w.Token}, ErrInvalidArgument, "consistency.token is only used with at_least_as_fresh or at_exact_snapshot"},
		{"token on full", Consistency{Mode: FullyConsistent, Token: w.Token}, ErrInvalidArgument, "consistency.token is only used with at_least_as_fresh or at_exact_snapshot"},
		{"mode without token", Consistency{Mode: AtLeastAsFresh}, ErrInvalidArgument, "consistency mode at_least_as_fresh needs a token"},
		{"exact without token", Consistency{Mode: AtExactSnapshot}, ErrInvalidArgument, "consistency mode at_exact_snapshot needs a token"},
		{"forged", Consistency{Mode: AtLeastAsFresh, Token: other.Encode(1)}, token.ErrInvalid, "invalid consistency token"},
		{"garbage", Consistency{Mode: AtExactSnapshot, Token: "!!"}, token.ErrInvalid, "invalid consistency token"},
		{"future", Consistency{Mode: AtLeastAsFresh, Token: f.tok.Encode(999)}, ErrInvalidArgument, "token is from a newer revision than this server has"},
	} {
		_, err := f.e.Resolve(c.c)
		if !errors.Is(err, c.want) || err.Error() != c.msg {
			t.Errorf("%s: Resolve = %v, want %v %q", c.name, err, c.want, c.msg)
		}
		// Every read reports the same error.
		_, cerr := f.e.Check(context.Background(), CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
			Subject: subj(t, "user:zoe"), Consistency: c.c})
		_, berr := f.e.CheckBulk(context.Background(), CheckBulkRequest{Consistency: c.c})
		_, lerr := f.e.LookupResources(context.Background(), LookupResourcesRequest{ResourceType: "doc", Permission: "view",
			Subject: subj(t, "user:zoe"), Consistency: c.c})
		_, rerr := f.e.ReadRelationships(context.Background(), ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Consistency: c.c})
		for op, e := range map[string]error{"check": cerr, "bulk": berr, "lookup": lerr, "read": rerr} {
			if e == nil || e.Error() != c.msg {
				t.Errorf("%s: %s = %v, want %q", c.name, op, e, c.msg)
			}
		}
	}
	if wrapped := fmt.Errorf("items[0]: %w", invalid("bad")); !errors.Is(wrapped, ErrInvalidArgument) || wrapped.Error() != "items[0]: bad" {
		t.Errorf("wrapped argument error = %q", wrapped)
	}
}

func TestCheckErrors(t *testing.T) {
	f := newFixture(t, Options{})
	if _, err := f.e.Check(context.Background(), CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
		Subject: subj(t, "user:a")}); !errors.Is(err, store.ErrNoSchema) {
		t.Fatalf("check before a schema = %v", err)
	}
	f.schema(t)
	for _, c := range []struct {
		req  CheckRequest
		want error
	}{
		{CheckRequest{ResourceType: "nope", ResourceID: "a", Permission: "view", Subject: subj(t, "user:a")}, check.ErrUnknownType},
		{CheckRequest{ResourceType: "doc", ResourceID: "a", Permission: "edit", Subject: subj(t, "user:a")}, check.ErrUnknownName},
		{CheckRequest{ResourceType: "doc", ResourceID: "a b", Permission: "view", Subject: subj(t, "user:a")}, store.ErrInvalid},
		{CheckRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", Subject: subj(t, "group:g#admin")}, check.ErrUnknownName},
	} {
		if _, err := f.e.Check(context.Background(), c.req); !errors.Is(err, c.want) {
			t.Errorf("Check(%+v) = %v, want %v", c.req, err, c.want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.Check(ctx, CheckRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", Subject: subj(t, "user:a")}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled check = %v", err)
	}
}

func TestCheckBulk(t *testing.T) {
	f := newFixture(t, Options{})
	f.schema(t)
	w := f.write(t, "touch doc:a#viewer@user:alice", "touch doc:b#owner@user:alice", "touch doc:b#banned@user:alice", "touch doc:c#viewer@user:*")
	items := []CheckItem{
		{ResourceType: "doc", ResourceID: "a", Permission: "view", Subject: subj(t, "user:alice")},
		{ResourceType: "doc", ResourceID: "b", Permission: "view", Subject: subj(t, "user:alice")},
		{ResourceType: "nope", ResourceID: "x", Permission: "view", Subject: subj(t, "user:alice")},
		{ResourceType: "doc", ResourceID: "c", Permission: "view", Subject: subj(t, "user:anyone")},
		{ResourceType: "doc", ResourceID: "b", Permission: "owner", Subject: subj(t, "user:alice")},
	}
	res, err := f.e.CheckBulk(context.Background(), CheckBulkRequest{Items: items, Consistency: Consistency{Mode: AtLeastAsFresh, Token: w.Token}})
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, false, false, true, true}
	for i, r := range res.Results {
		if r.Allowed != want[i] || (i == 2) != (r.Err != nil) {
			t.Errorf("item %d = %+v, want allowed %v", i, r, want[i])
		}
	}
	if !errors.Is(res.Results[2].Err, check.ErrUnknownType) {
		t.Errorf("unknown type item error = %v", res.Results[2].Err)
	}
	// Every item is answered at the one snapshot, the same as a single check.
	for i, it := range items {
		single, err := f.e.Check(context.Background(), CheckRequest{ResourceType: it.ResourceType, ResourceID: it.ResourceID,
			Permission: it.Permission, Subject: it.Subject, Consistency: Consistency{Mode: AtExactSnapshot, Token: res.At.Token}})
		if (err != nil) != (res.Results[i].Err != nil) || single.Allowed != res.Results[i].Allowed {
			t.Errorf("item %d: bulk %+v, single %+v %v", i, res.Results[i], single, err)
		}
	}
	empty, err := f.e.CheckBulk(context.Background(), CheckBulkRequest{Consistency: Consistency{Mode: FullyConsistent}})
	if err != nil || len(empty.Results) != 0 || empty.At.Revision != f.st.Head() {
		t.Fatalf("empty bulk = %+v %v", empty, err)
	}
	if _, err := f.e.CheckBulk(context.Background(), CheckBulkRequest{Items: make([]CheckItem, MaxBulkChecks+1)}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized bulk = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.CheckBulk(ctx, CheckBulkRequest{Items: items[:1]}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled bulk = %v", err)
	}
}

func TestCheckBulkFailsWholeOnExpiredSnapshot(t *testing.T) {
	st, err := store.Open(store.Options{Retention: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{3}, token.KeySize))
	e, _ := New(Options{Store: st, Tokens: tok})
	if _, err := st.WriteSchema(schemaSrc); err != nil {
		t.Fatal(err)
	}
	old := tok.Encode(st.Head())
	for i := range 300 {
		r, _ := store.ParseRelationship(fmt.Sprintf("doc:d%d#viewer@user:u", i))
		if _, err := st.Write([]store.Update{{Op: store.OpTouch, Relationship: r}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err = e.CheckBulk(context.Background(), CheckBulkRequest{Consistency: Consistency{Mode: AtExactSnapshot, Token: old},
		Items: []CheckItem{{ResourceType: "doc", ResourceID: "d1", Permission: "view", Subject: subj(t, "user:u")}}})
	if !errors.Is(err, store.ErrSnapshotExpired) {
		t.Fatalf("bulk at an expired snapshot = %v, want ErrSnapshotExpired", err)
	}
}

func TestLookupResources(t *testing.T) {
	f := newFixture(t, Options{})
	f.schema(t)
	var ops []string
	for i := range 25 {
		ops = append(ops, fmt.Sprintf("touch doc:d%02d#viewer@user:alice", i))
	}
	ops = append(ops, "touch doc:d03#banned@user:alice", "touch doc:zz#viewer@user:bob")
	w := f.write(t, ops...)
	var got []string
	cursor := ""
	pages := 0
	for {
		res, err := f.e.LookupResources(context.Background(), LookupResourcesRequest{ResourceType: "doc", Permission: "view",
			Subject: subj(t, "user:alice"), Consistency: Consistency{Mode: AtLeastAsFresh, Token: w.Token}, Cursor: cursor, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if res.At.Revision < w.Revision {
			t.Fatalf("lookup at %d, older than the write %d", res.At.Revision, w.Revision)
		}
		got = append(got, res.ResourceIDs...)
		pages++
		if res.Cursor == "" {
			break
		}
		cursor = res.Cursor
	}
	if len(got) != 24 || pages != 3 || got[0] != "d00" || got[3] != "d04" {
		t.Fatalf("lookup gave %d ids in %d pages: %v", len(got), pages, got)
	}
	none, err := f.e.LookupResources(context.Background(), LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: subj(t, "user:nobody")})
	if err != nil || none.ResourceIDs == nil || len(none.ResourceIDs) != 0 {
		t.Fatalf("empty lookup = %#v %v", none, err)
	}
	for _, req := range []LookupResourcesRequest{
		{ResourceType: "doc", Permission: "view", Subject: subj(t, "user:a"), Limit: -1},
		{ResourceType: "doc", Permission: "view", Subject: subj(t, "user:a"), Limit: check.MaxLookupLimit + 1},
		{ResourceType: "doc", Permission: "view", Subject: subj(t, "user:a"), Cursor: "not valid"},
	} {
		if _, err := f.e.LookupResources(context.Background(), req); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("LookupResources(%+v) = %v", req, err)
		}
	}
	if _, err := f.e.LookupResources(context.Background(), LookupResourcesRequest{ResourceType: "doc", Permission: "edit", Subject: subj(t, "user:a")}); !errors.Is(err, check.ErrUnknownName) {
		t.Errorf("lookup of an unknown permission = %v", err)
	}
}

func TestExpand(t *testing.T) {
	f := newFixture(t, Options{})
	f.schema(t)
	w := f.write(t, "touch doc:d#viewer@group:eng#member", "touch doc:d#viewer@user:*", "touch doc:d#owner@user:olga",
		"touch doc:d#banned@user:bob", "touch group:eng#member@user:alice")
	res, err := f.e.Expand(context.Background(), ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view",
		Consistency: Consistency{Mode: AtLeastAsFresh, Token: w.Token}})
	if err != nil {
		t.Fatal(err)
	}
	if res.At.Revision < w.Revision || res.At.Token == "" {
		t.Fatalf("expand at %+v, older than the write %d", res.At, w.Revision)
	}
	subjects := func(tr *check.Trace) []string {
		var out []string
		var walk func(n *check.TraceNode)
		walk = func(n *check.TraceNode) {
			if n.Kind == check.KindSubject {
				out = append(out, n.Subject)
			}
			if n.Kind == check.KindRelation && n.Object == "group:eng" {
				out = append(out, "expanded group:eng")
			}
			for _, c := range n.Children {
				walk(c)
			}
		}
		walk(tr.Root)
		return out
	}
	if got := strings.Join(subjects(res.Tree), " "); got != "group:eng#member user:* user:olga user:bob" || res.Tree.Truncated {
		t.Fatalf("one-level subjects %q (truncated %v)", got, res.Tree.Truncated)
	}
	before := f.m.Counter("grantd_check_dispatches_total", "", "").Value()
	res, err = f.e.Expand(context.Background(), ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view",
		Recursive: true, Consistency: Consistency{Mode: AtExactSnapshot, Token: w.Token}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(subjects(res.Tree), " "); got != "expanded group:eng user:alice user:* user:olga user:bob" || res.At.Revision != w.Revision {
		t.Fatalf("recursive subjects %q at %d", got, res.At.Revision)
	}
	if after := f.m.Counter("grantd_check_dispatches_total", "", "").Value(); after-before != 5 {
		t.Fatalf("expand counted %d dispatches, want 5 (view, viewer, group:eng#member, owner, banned)", after-before)
	}
	small, err := f.e.Expand(context.Background(), ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view", Recursive: true, MaxNodes: 3})
	if err != nil || !small.Tree.Truncated || small.Tree.Nodes != 3 {
		t.Fatalf("limited expand = %+v, %v", small.Tree, err)
	}
	for _, req := range []ExpandRequest{
		{ResourceType: "doc", ResourceID: "d", Permission: "view", MaxNodes: -1},
		{ResourceType: "doc", ResourceID: "d", Permission: "view", MaxNodes: check.MaxTraceNodes + 1},
		{ResourceType: "doc", ResourceID: "d", Permission: "view", Consistency: Consistency{Mode: "sometime"}},
	} {
		if _, err := f.e.Expand(context.Background(), req); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("Expand(%+v) = %v", req, err)
		}
	}
	if _, err := f.e.Expand(context.Background(), ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "edit"}); !errors.Is(err, check.ErrUnknownName) {
		t.Errorf("expand of an unknown permission = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.Expand(ctx, ExpandRequest{ResourceType: "doc", ResourceID: "d", Permission: "view"}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled expand = %v", err)
	}
}

func TestReadRelationships(t *testing.T) {
	f := newFixture(t, Options{})
	f.schema(t)
	w := f.write(t, "touch doc:a#viewer@user:x", "touch doc:b#viewer@user:y", "touch doc:c#owner@user:x")
	res, err := f.e.ReadRelationships(context.Background(), ReadRequest{Filter: store.Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "x"},
		Consistency: Consistency{Mode: AtLeastAsFresh, Token: w.Token}, Limit: 1})
	if err != nil || len(res.Relationships) != 1 || res.Relationships[0].String() != "doc:a#viewer@user:x" || res.Cursor == "" {
		t.Fatalf("first page = %+v %v", res, err)
	}
	next, err := f.e.ReadRelationships(context.Background(), ReadRequest{Filter: store.Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "x"},
		Consistency: Consistency{Mode: AtExactSnapshot, Token: res.At.Token}, Cursor: res.Cursor, Limit: 1})
	if err != nil || len(next.Relationships) != 1 || next.Relationships[0].String() != "doc:c#owner@user:x" || next.Cursor != "" {
		t.Fatalf("second page = %+v %v", next, err)
	}
	empty, err := f.e.ReadRelationships(context.Background(), ReadRequest{Filter: store.Filter{ResourceType: "group"}})
	if err != nil || empty.Relationships == nil || len(empty.Relationships) != 0 {
		t.Fatalf("empty read = %#v %v", empty, err)
	}
	for _, req := range []ReadRequest{
		{Filter: store.Filter{ResourceType: "doc"}, Limit: -1},
		{Filter: store.Filter{ResourceType: "doc"}, Limit: store.MaxReadLimit + 1},
		{Filter: store.Filter{ResourceType: "doc"}, Cursor: strings.Repeat("a", maxCursorBytes+1)},
	} {
		if _, err := f.e.ReadRelationships(context.Background(), req); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ReadRelationships(limit %d, cursor %d bytes) = %v", req.Limit, len(req.Cursor), err)
		}
	}
	if _, err := f.e.ReadRelationships(context.Background(), ReadRequest{}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("read without a resource type = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.ReadRelationships(ctx, ReadRequest{Filter: store.Filter{ResourceType: "doc"}}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled read = %v", err)
	}
}

func TestWrite(t *testing.T) {
	f := newFixture(t, Options{})
	rel, _ := store.ParseRelationship("doc:a#viewer@user:x")
	if _, err := f.e.Write(context.Background(), WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: rel}}}); !errors.Is(err, store.ErrNoSchema) {
		t.Fatalf("write before a schema = %v", err)
	}
	f.schema(t)
	w := f.write(t, "create doc:a#viewer@user:x")
	if _, err := f.e.Write(context.Background(), WriteRequest{Updates: []store.Update{{Op: store.OpCreate, Relationship: rel}}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate create = %v", err)
	}
	pre := []store.Precondition{{MustExist: false, Filter: store.Filter{ResourceType: "doc", ResourceID: "a"}}}
	rel2, _ := store.ParseRelationship("doc:a#owner@user:x")
	if _, err := f.e.Write(context.Background(), WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: rel2}}, Preconditions: pre}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("failed precondition = %v", err)
	}
	if f.st.Head() != w.Revision {
		t.Fatalf("a refused write moved the head from %d to %d", w.Revision, f.st.Head())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.Write(ctx, WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: rel2}}}); !errors.Is(err, context.Canceled) || f.st.Head() != w.Revision {
		t.Fatalf("canceled write = %v, head %d", err, f.st.Head())
	}
}

// TestInProcessMatchesConcurrentWriters has callers write and then check
// their own writes with the returned tokens while others write: the
// read-your-writes guarantee the HTTP API gives, in process.
func TestInProcessMatchesConcurrentWriters(t *testing.T) {
	f := newFixture(t, Options{CacheSize: 1000, Quantum: time.Hour})
	f.schema(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for g := range 8 {
		wg.Go(func() {
			for i := range 25 {
				r, _ := store.ParseRelationship(fmt.Sprintf("doc:g%d-%d#viewer@user:u%d", g, i, g))
				w, err := f.e.Write(context.Background(), WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: r}}})
				if err != nil {
					errs <- err
					return
				}
				res, err := f.e.Check(context.Background(), CheckRequest{ResourceType: "doc", ResourceID: r.ResourceID, Permission: "view",
					Subject: store.Subject{Type: "user", ID: r.SubjectID}, Consistency: Consistency{Mode: AtLeastAsFresh, Token: w.At.Token}})
				if err != nil || !res.Allowed {
					errs <- fmt.Errorf("check after own write %s: %+v %v", r, res, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
