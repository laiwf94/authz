package enginetest

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

// Factory returns a new engine that holds schemaSrc and no relationships.
// The engine must be usable until t ends.
type Factory func(t testing.TB, schemaSrc string) engine.Engine

// Run is the Engine contract: every engine.Engine passes it. It covers the
// consistency modes and tokens, the answers of every query on the
// SharingSchema fixture, paging, request limits and their errors, writes,
// preconditions and deletes by filter, cancellation, concurrent
// read-your-writes, and on random graphs that Check, CheckBulk,
// LookupResources, LookupSubjects and a recursive Expand all agree.
//
// Errors are matched with errors.Is against the sentinels the real engine
// uses: engine.ErrInvalidArgument for a request the engine refuses as
// written, token.ErrInvalid, check.ErrUnknownType and check.ErrUnknownName,
// store.ErrInvalid, store.ErrConflict and store.ErrPrecondition.
//
// MinimizeLatency may read a snapshot older than the latest write, so the
// contract reads its own writes with tokens. An engine with a Tokens()
// *token.Issuer method is also asked about a token from a revision it does
// not have yet.
func Run(t *testing.T, newEngine Factory) {
	c := &contract{newEngine: newEngine}
	t.Run("Consistency", c.consistency)
	t.Run("Check", c.check)
	t.Run("CheckBulk", c.checkBulk)
	t.Run("LookupResources", c.lookupResources)
	t.Run("LookupSubjects", c.lookupSubjects)
	t.Run("Expand", c.expand)
	t.Run("ReadRelationships", c.read)
	t.Run("Write", c.write)
	t.Run("DeleteRelationships", c.delete)
	t.Run("Cancelled", c.cancelled)
	t.Run("ConcurrentReadYourWrites", c.concurrent)
	t.Run("RandomGraphs", c.randomGraphs)
}

type contract struct{ newEngine Factory }

// sharing returns a new engine holding the fixture and the snapshot of its
// data.
func (c *contract) sharing(t *testing.T) (engine.Engine, engine.Snapshot) {
	t.Helper()
	e := c.newEngine(t, SharingSchema)
	return e, touch(t, e, SharingRelationships...)
}

var bg = context.Background()

func ok(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t testing.TB, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got error %v, want %v", what, err, target)
	}
}

func exact(s engine.Snapshot) engine.Consistency {
	return engine.Consistency{Mode: engine.AtExactSnapshot, Token: s.Token}
}

func fresh(s engine.Snapshot) engine.Consistency {
	return engine.Consistency{Mode: engine.AtLeastAsFresh, Token: s.Token}
}

func subject(t testing.TB, s string) store.Subject {
	t.Helper()
	sub, err := store.ParseSubject(s, false)
	ok(t, err)
	return sub
}

func relationship(t testing.TB, s string) store.Relationship {
	t.Helper()
	r, err := store.ParseRelationship(s)
	ok(t, err)
	return r
}

func update(t testing.TB, op store.Op, rel string) store.Update {
	return store.Update{Op: op, Relationship: relationship(t, rel)}
}

// allowed checks resource#perm for sub ("type:id#perm", "user:alice").
func allowed(t testing.TB, e engine.Engine, cons engine.Consistency, resourcePerm, sub string) bool {
	t.Helper()
	obj, perm, _ := strings.Cut(resourcePerm, "#")
	typ, id, _ := strings.Cut(obj, ":")
	res, err := e.Check(bg, engine.CheckRequest{ResourceType: typ, ResourceID: id, Permission: perm,
		Subject: subject(t, sub), Consistency: cons})
	ok(t, err)
	return res.Allowed
}

func (c *contract) consistency(t *testing.T) {
	e, s0 := c.sharing(t)
	w1, err := e.Write(bg, engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:memo#viewer@user:vera")}})
	ok(t, err)
	if w1.At.Revision <= s0.Revision {
		t.Fatalf("write at %d after a write at %d", w1.At.Revision, s0.Revision)
	}
	checkMemo := func(cons engine.Consistency) engine.CheckResult {
		t.Helper()
		res, err := e.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "memo", Permission: "view",
			Subject: subject(t, "user:vera"), Consistency: cons})
		ok(t, err)
		return res
	}
	if r := checkMemo(engine.Consistency{Mode: engine.FullyConsistent}); !r.Allowed || r.At.Revision != w1.At.Revision {
		t.Fatalf("fully_consistent after the write: %+v, want allowed at %d", r, w1.At.Revision)
	}
	if r := checkMemo(fresh(w1.At)); !r.Allowed || r.At.Revision < w1.At.Revision {
		t.Fatalf("at_least_as_fresh the write: %+v", r)
	}
	if r := checkMemo(exact(s0)); r.Allowed || r.At != s0 {
		t.Fatalf("at_exact_snapshot before the write: %+v, want denied at %+v", r, s0)
	}
	if r := checkMemo(engine.Consistency{}); r.At.Revision > w1.At.Revision {
		t.Fatalf("minimize_latency read revision %d, newer than the head %d", r.At.Revision, w1.At.Revision)
	}

	w2, err := e.Write(bg, engine.WriteRequest{Updates: []store.Update{update(t, store.OpDelete, "doc:memo#viewer@user:vera")}})
	ok(t, err)
	if r := checkMemo(fresh(w2.At)); r.Allowed {
		t.Fatalf("at_least_as_fresh the delete still allowed: %+v", r)
	}
	if r := checkMemo(exact(w1.At)); !r.Allowed || r.At != w1.At {
		t.Fatalf("at_exact_snapshot of the write after the delete: %+v, want allowed at %+v", r, w1.At)
	}
	// A result's token reads the same snapshot again, from every read.
	lr, err := e.LookupResources(bg, engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view",
		Subject: subject(t, "user:vera"), Consistency: exact(w1.At)})
	ok(t, err)
	if !reflect.DeepEqual(lr.ResourceIDs, []string{"memo", "readme"}) || lr.At != w1.At {
		t.Fatalf("lookup at the write: %+v", lr)
	}
	ls, err := e.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "memo",
		Permission: "view", SubjectType: "user", Consistency: exact(w1.At)})
	ok(t, err)
	if !reflect.DeepEqual(ls.Subjects, []check.FoundSubject{{ID: "vera"}}) || ls.At != w1.At {
		t.Fatalf("lookup subjects at the write: %+v", ls)
	}
	rd, err := e.ReadRelationships(bg, engine.ReadRequest{Filter: store.Filter{ResourceType: "doc", ResourceID: "memo"}, Consistency: exact(w1.At)})
	ok(t, err)
	if len(rd.Relationships) != 1 || rd.At != w1.At {
		t.Fatalf("read at the write: %+v", rd)
	}
	ex, err := e.Expand(bg, engine.ExpandRequest{ResourceType: "doc", ResourceID: "memo", Permission: "viewer", Consistency: exact(w1.At)})
	ok(t, err)
	if len(ex.Tree.Root.Children) != 1 || ex.At != w1.At {
		t.Fatalf("expand at the write: %+v", ex)
	}
	bulk, err := e.CheckBulk(bg, engine.CheckBulkRequest{Consistency: exact(w1.At), Items: []engine.CheckItem{
		{ResourceType: "doc", ResourceID: "memo", Permission: "view", Subject: subject(t, "user:vera")}}})
	ok(t, err)
	if !bulk.Results[0].Allowed || bulk.At != w1.At {
		t.Fatalf("bulk at the write: %+v", bulk)
	}

	tampered := []byte(w1.At.Token)
	tampered[len(tampered)/2] ^= 1
	for _, tc := range []struct {
		name string
		cons engine.Consistency
		want error
	}{
		{"unknown mode", engine.Consistency{Mode: "eventually"}, engine.ErrInvalidArgument},
		{"token without mode", engine.Consistency{Token: w1.At.Token}, engine.ErrInvalidArgument},
		{"token with minimize_latency", engine.Consistency{Mode: engine.MinimizeLatency, Token: w1.At.Token}, engine.ErrInvalidArgument},
		{"token with fully_consistent", engine.Consistency{Mode: engine.FullyConsistent, Token: w1.At.Token}, engine.ErrInvalidArgument},
		{"at_least_as_fresh without token", engine.Consistency{Mode: engine.AtLeastAsFresh}, engine.ErrInvalidArgument},
		{"at_exact_snapshot without token", engine.Consistency{Mode: engine.AtExactSnapshot}, engine.ErrInvalidArgument},
		{"garbage token", engine.Consistency{Mode: engine.AtLeastAsFresh, Token: "not-a-token"}, token.ErrInvalid},
		{"tampered token", engine.Consistency{Mode: engine.AtExactSnapshot, Token: string(tampered)}, token.ErrInvalid},
	} {
		_, err := e.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "memo", Permission: "view",
			Subject: subject(t, "user:vera"), Consistency: tc.cons})
		wantErr(t, tc.name, err, tc.want)
		_, err = e.ReadRelationships(bg, engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Consistency: tc.cons})
		wantErr(t, tc.name+" (read)", err, tc.want)
	}
	if tk, has := e.(interface{ Tokens() *token.Issuer }); has {
		future := tk.Tokens().Encode(w2.At.Revision + 10)
		_, err := e.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "memo", Permission: "view",
			Subject: subject(t, "user:vera"), Consistency: engine.Consistency{Mode: engine.AtLeastAsFresh, Token: future}})
		wantErr(t, "future token", err, engine.ErrInvalidArgument)
	}
}

func (c *contract) check(t *testing.T) {
	e, s := c.sharing(t)
	cons := exact(s)
	for _, tc := range []struct {
		resource string
		yes, no  []string
	}{
		{"doc:plan#view", []string{"user:alice", "user:ed", "user:fiona", "user:olive"}, []string{"user:sam", "user:rex", "user:mallory", "user:nobody"}},
		{"doc:plan#edit", []string{"user:ed", "user:olive"}, []string{"user:alice", "user:rex"}},
		{"doc:plan#review", []string{"user:ed"}, []string{"user:rex", "user:olive"}},
		{"doc:plan#banned", []string{"user:sam"}, []string{"user:alice"}},
		{"doc:readme#view", []string{"user:alice", "user:rex", "user:sam", "user:nobody"}, []string{"user:mallory"}},
		{"doc:draft#view", []string{"user:olive"}, []string{"user:alice"}},
		{"doc:unknown#view", nil, []string{"user:alice"}},
		{"folder:root#view", []string{"user:alice", "user:sam"}, []string{"user:fiona"}},
		{"group:eng#member", []string{"user:alice", "user:sam"}, []string{"user:olive"}},
		// Usersets: stored, nested, through a cycle, and containing themselves.
		{"doc:plan#view", []string{"group:eng#member", "group:sre#member"}, nil},
		{"group:eng#member", []string{"group:eng#member", "group:sre#member"}, nil},
		{"doc:draft#view", nil, []string{"group:eng#member"}},
		// A wildcard never grants a userset.
		{"folder:public#view", []string{"user:anyone"}, []string{"group:eng#member"}},
	} {
		for _, sub := range tc.yes {
			if !allowed(t, e, cons, tc.resource, sub) {
				t.Errorf("%s for %s: denied, want allowed", tc.resource, sub)
			}
		}
		for _, sub := range tc.no {
			if allowed(t, e, cons, tc.resource, sub) {
				t.Errorf("%s for %s: allowed, want denied", tc.resource, sub)
			}
		}
	}
	for _, tc := range []struct {
		name string
		req  engine.CheckRequest
		want error
	}{
		{"unknown type", engine.CheckRequest{ResourceType: "video", ResourceID: "v", Permission: "view", Subject: subject(t, "user:alice")}, check.ErrUnknownType},
		{"unknown permission", engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "delete", Subject: subject(t, "user:alice")}, check.ErrUnknownName},
		{"unknown subject type", engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: store.Subject{Type: "robot", ID: "r"}}, check.ErrUnknownType},
		{"unknown subject relation", engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: store.Subject{Type: "group", ID: "eng", Relation: "owner"}}, check.ErrUnknownName},
		{"bad resource id", engine.CheckRequest{ResourceType: "doc", ResourceID: "a b", Permission: "view", Subject: subject(t, "user:alice")}, store.ErrInvalid},
		{"wildcard subject", engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: store.Subject{Type: "user", ID: "*"}}, store.ErrInvalid},
	} {
		tc.req.Consistency = cons
		_, err := e.Check(bg, tc.req)
		wantErr(t, tc.name, err, tc.want)
	}
}

func (c *contract) checkBulk(t *testing.T) {
	e, s := c.sharing(t)
	items := []engine.CheckItem{
		{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: subject(t, "user:alice")},
		{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: subject(t, "user:sam")},
		{ResourceType: "video", ResourceID: "v", Permission: "view", Subject: subject(t, "user:alice")},
		{ResourceType: "doc", ResourceID: "readme", Permission: "view", Subject: subject(t, "user:nobody")},
		{ResourceType: "doc", ResourceID: "plan", Permission: "rename", Subject: subject(t, "user:alice")},
		{ResourceType: "doc", ResourceID: "plan", Permission: "review", Subject: subject(t, "user:ed")},
	}
	res, err := e.CheckBulk(bg, engine.CheckBulkRequest{Items: items, Consistency: exact(s)})
	ok(t, err)
	if len(res.Results) != len(items) || res.At != s {
		t.Fatalf("bulk: %+v", res)
	}
	want := []bool{true, false, false, true, false, true}
	for i, r := range res.Results {
		if r.Allowed != want[i] {
			t.Errorf("item %d: allowed %v, want %v", i, r.Allowed, want[i])
		}
	}
	wantErr(t, "bulk unknown type", res.Results[2].Err, check.ErrUnknownType)
	wantErr(t, "bulk unknown permission", res.Results[4].Err, check.ErrUnknownName)
	for _, i := range []int{0, 1, 3, 5} {
		ok(t, res.Results[i].Err)
	}

	empty, err := e.CheckBulk(bg, engine.CheckBulkRequest{Consistency: exact(s)})
	ok(t, err)
	if len(empty.Results) != 0 || empty.At != s {
		t.Fatalf("empty bulk: %+v", empty)
	}
	many := make([]engine.CheckItem, engine.MaxBulkChecks+1)
	for i := range many {
		many[i] = items[0]
	}
	_, err = e.CheckBulk(bg, engine.CheckBulkRequest{Items: many})
	wantErr(t, "too many checks", err, engine.ErrInvalidArgument)
	full, err := e.CheckBulk(bg, engine.CheckBulkRequest{Items: many[:engine.MaxBulkChecks], Consistency: exact(s)})
	ok(t, err)
	if len(full.Results) != engine.MaxBulkChecks || !full.Results[engine.MaxBulkChecks-1].Allowed {
		t.Fatalf("a full bulk: %d results", len(full.Results))
	}
	_, err = e.CheckBulk(bg, engine.CheckBulkRequest{Items: items[:1], Consistency: engine.Consistency{Mode: "never"}})
	wantErr(t, "bulk consistency", err, engine.ErrInvalidArgument)
}

// lookupAll pages through a resource lookup with limit, checking that
// every page is within it.
func lookupAll(t testing.TB, e engine.Engine, req engine.LookupResourcesRequest) []string {
	t.Helper()
	all := []string{}
	for pages := 0; ; pages++ {
		if pages > 10_000 {
			t.Fatal("lookup does not end")
		}
		res, err := e.LookupResources(bg, req)
		ok(t, err)
		if req.Limit > 0 && len(res.ResourceIDs) > req.Limit {
			t.Fatalf("page of %d over the limit of %d", len(res.ResourceIDs), req.Limit)
		}
		all = append(all, res.ResourceIDs...)
		if res.Cursor == "" {
			return all
		}
		req.Cursor = res.Cursor
	}
}

// subjectsAll pages through a subject lookup.
func subjectsAll(t testing.TB, e engine.Engine, req engine.LookupSubjectsRequest) []check.FoundSubject {
	t.Helper()
	all := []check.FoundSubject{}
	for pages := 0; ; pages++ {
		if pages > 10_000 {
			t.Fatal("lookup does not end")
		}
		res, err := e.LookupSubjects(bg, req)
		ok(t, err)
		if req.Limit > 0 && len(res.Subjects) > req.Limit {
			t.Fatalf("page of %d over the limit of %d", len(res.Subjects), req.Limit)
		}
		all = append(all, res.Subjects...)
		if res.Cursor == "" {
			return all
		}
		req.Cursor = res.Cursor
	}
}

func (c *contract) lookupResources(t *testing.T) {
	e, s := c.sharing(t)
	for _, tc := range []struct {
		perm, sub string
		want      []string
	}{
		{"view", "user:olive", []string{"draft", "plan", "readme"}},
		{"view", "user:alice", []string{"plan", "readme"}},
		{"view", "user:sam", []string{"readme"}},
		{"view", "user:mallory", []string{}},
		{"view", "group:eng#member", []string{"plan"}},
		{"edit", "user:olive", []string{"draft", "plan"}},
		{"review", "user:rex", []string{}},
	} {
		for _, limit := range []int{0, 1, 2, 3} {
			got := lookupAll(t, e, engine.LookupResourcesRequest{ResourceType: "doc", Permission: tc.perm,
				Subject: subject(t, tc.sub), Consistency: exact(s), Limit: limit})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("doc#%s for %s, limit %d: %v, want %v", tc.perm, tc.sub, limit, got, tc.want)
			}
		}
	}
	after, err := e.LookupResources(bg, engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view",
		Subject: subject(t, "user:olive"), Consistency: exact(s), Cursor: "draft"})
	ok(t, err)
	if !reflect.DeepEqual(after.ResourceIDs, []string{"plan", "readme"}) || after.At != s {
		t.Fatalf("after draft: %+v", after)
	}
	for _, tc := range []struct {
		name string
		req  engine.LookupResourcesRequest
		want error
	}{
		{"negative limit", engine.LookupResourcesRequest{Limit: -1}, engine.ErrInvalidArgument},
		{"limit over the maximum", engine.LookupResourcesRequest{Limit: check.MaxLookupLimit + 1}, engine.ErrInvalidArgument},
		{"bad cursor", engine.LookupResourcesRequest{Cursor: "no spaces"}, engine.ErrInvalidArgument},
		{"unknown type", engine.LookupResourcesRequest{ResourceType: "video"}, check.ErrUnknownType},
		{"unknown permission", engine.LookupResourcesRequest{Permission: "rename"}, check.ErrUnknownName},
	} {
		req := engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: subject(t, "user:alice")}
		if tc.req.ResourceType != "" {
			req.ResourceType = tc.req.ResourceType
		}
		if tc.req.Permission != "" {
			req.Permission = tc.req.Permission
		}
		req.Limit, req.Cursor = tc.req.Limit, tc.req.Cursor
		_, err := e.LookupResources(bg, req)
		wantErr(t, tc.name, err, tc.want)
	}
}

func (c *contract) lookupSubjects(t *testing.T) {
	e, s := c.sharing(t)
	ids := func(ids ...string) []check.FoundSubject {
		out := []check.FoundSubject{}
		for _, id := range ids {
			out = append(out, check.FoundSubject{ID: id})
		}
		return out
	}
	for _, tc := range []struct {
		resource, subType, subRel string
		want                      []check.FoundSubject
	}{
		{"doc:plan#view", "user", "", ids("alice", "ed", "fiona", "olive")},
		{"doc:plan#review", "user", "", ids("ed")},
		{"doc:plan#banned", "user", "", ids("sam")},
		{"doc:draft#view", "user", "", ids("olive")},
		{"doc:unknown#view", "user", "", ids()},
		{"doc:readme#view", "user", "", []check.FoundSubject{{ID: check.Wildcard, Excluded: []string{"mallory"}}}},
		{"folder:public#view", "user", "", []check.FoundSubject{{ID: check.Wildcard, Excluded: []string{}}}},
		{"folder:root#view", "group", "member", ids("eng", "sre")},
		{"group:eng#member", "group", "member", ids("eng", "sre")},
		{"doc:readme#view", "group", "member", ids()},
	} {
		obj, perm, _ := strings.Cut(tc.resource, "#")
		typ, id, _ := strings.Cut(obj, ":")
		for _, limit := range []int{0, 1, 2} {
			got := subjectsAll(t, e, engine.LookupSubjectsRequest{ResourceType: typ, ResourceID: id, Permission: perm,
				SubjectType: tc.subType, SubjectRelation: tc.subRel, Consistency: exact(s), Limit: limit})
			if !equalSubjects(got, tc.want) {
				t.Errorf("%s for %s#%s, limit %d: %+v, want %+v", tc.resource, tc.subType, tc.subRel, limit, got, tc.want)
			}
		}
	}
	after, err := e.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
		SubjectType: "user", Consistency: exact(s), Cursor: "bob"})
	ok(t, err)
	if !equalSubjects(after.Subjects, ids("ed", "fiona", "olive")) || after.At != s {
		t.Fatalf("after bob: %+v", after)
	}
	afterWild, err := e.LookupSubjects(bg, engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "readme", Permission: "view",
		SubjectType: "user", Consistency: exact(s), Cursor: check.Wildcard})
	ok(t, err)
	if len(afterWild.Subjects) != 0 || afterWild.Cursor != "" {
		t.Fatalf("after the wildcard: %+v", afterWild)
	}
	for _, tc := range []struct {
		name string
		req  engine.LookupSubjectsRequest
		want error
	}{
		{"negative limit", engine.LookupSubjectsRequest{Limit: -1}, engine.ErrInvalidArgument},
		{"limit over the maximum", engine.LookupSubjectsRequest{Limit: check.MaxLookupLimit + 1}, engine.ErrInvalidArgument},
		{"bad cursor", engine.LookupSubjectsRequest{Cursor: "no spaces"}, engine.ErrInvalidArgument},
		{"unknown type", engine.LookupSubjectsRequest{ResourceType: "video"}, check.ErrUnknownType},
		{"unknown permission", engine.LookupSubjectsRequest{Permission: "rename"}, check.ErrUnknownName},
		{"unknown subject type", engine.LookupSubjectsRequest{SubjectType: "robot"}, check.ErrUnknownType},
		{"unknown subject relation", engine.LookupSubjectsRequest{SubjectType: "group", SubjectRelation: "owner"}, check.ErrUnknownName},
		{"bad resource id", engine.LookupSubjectsRequest{ResourceID: "a b"}, store.ErrInvalid},
	} {
		req := engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", SubjectType: "user"}
		if tc.req.ResourceType != "" {
			req.ResourceType = tc.req.ResourceType
		}
		if tc.req.ResourceID != "" {
			req.ResourceID = tc.req.ResourceID
		}
		if tc.req.Permission != "" {
			req.Permission = tc.req.Permission
		}
		if tc.req.SubjectType != "" {
			req.SubjectType, req.SubjectRelation = tc.req.SubjectType, tc.req.SubjectRelation
		}
		req.Limit, req.Cursor = tc.req.Limit, tc.req.Cursor
		_, err := e.LookupSubjects(bg, req)
		wantErr(t, tc.name, err, tc.want)
	}
}

func equalSubjects(a, b []check.FoundSubject) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || len(a[i].Excluded) != len(b[i].Excluded) {
			return false
		}
		for j := range a[i].Excluded {
			if a[i].Excluded[j] != b[i].Excluded[j] {
				return false
			}
		}
	}
	return true
}

func (c *contract) expand(t *testing.T) {
	e, s := c.sharing(t)
	expand := func(resource string, recursive bool, max int) *check.Trace {
		t.Helper()
		obj, perm, _ := strings.Cut(resource, "#")
		typ, id, _ := strings.Cut(obj, ":")
		res, err := e.Expand(bg, engine.ExpandRequest{ResourceType: typ, ResourceID: id, Permission: perm,
			Recursive: recursive, MaxNodes: max, Consistency: exact(s)})
		ok(t, err)
		if res.At != s {
			t.Fatalf("expand at %+v, want %+v", res.At, s)
		}
		return res.Tree
	}
	tr := expand("folder:root#viewer", false, 0)
	want := &check.TraceNode{Kind: check.KindRelation, Object: "folder:root", Relation: "viewer", Children: []*check.TraceNode{
		{Kind: check.KindSubject, Object: "folder:root", Relation: "viewer", Subject: "group:eng#member"}}}
	if !reflect.DeepEqual(tr.Root, want) || tr.Nodes != 2 || tr.Truncated {
		t.Fatalf("folder:root#viewer: %+v", tr)
	}
	tr = expand("doc:plan#view", false, 0)
	if tr.Root.Kind != check.KindPermission || tr.Root.Object != "doc:plan" || tr.Root.Relation != "view" ||
		len(tr.Root.Children) != 1 || tr.Root.Children[0].Kind != check.KindExclusion ||
		tr.Root.Children[0].Expr != "viewer + edit + parent->view - banned" {
		t.Fatalf("doc:plan#view root: %+v", tr.Root)
	}
	var leaves []string
	walk(tr.Root, func(n *check.TraceNode) {
		if n.Kind == check.KindSubject {
			leaves = append(leaves, n.Relation+"@"+n.Subject)
		}
	})
	sort.Strings(leaves)
	wantLeaves := []string{"banned@user:sam", "editor@user:ed", "owner@user:olive", "parent@folder:specs#view"}
	if !reflect.DeepEqual(leaves, wantLeaves) {
		t.Fatalf("doc:plan#view leaves: %v, want %v", leaves, wantLeaves)
	}
	if n := count(tr.Root); n != tr.Nodes || tr.Truncated {
		t.Fatalf("doc:plan#view: %d nodes, Nodes %d, truncated %v", n, tr.Nodes, tr.Truncated)
	}
	full := tr.Nodes
	for max := 1; max <= full; max++ {
		tr := expand("doc:plan#view", false, max)
		if tr.Nodes != max || count(tr.Root) != max || tr.Truncated != (max < full) {
			t.Fatalf("max %d of %d: %d nodes, truncated %v", max, full, tr.Nodes, tr.Truncated)
		}
	}
	users := []string{"alice", "ed", "fiona", "mallory", "nobody", "olive", "rex", "sam"}
	for _, resource := range []string{"doc:plan#view", "doc:plan#review", "doc:readme#view", "group:eng#member", "folder:specs#view"} {
		got := solveTree(t, expand(resource, true, check.MaxTraceNodes), users)
		for _, u := range users {
			if want := allowed(t, e, exact(s), resource, "user:"+u); got[u] != want {
				t.Errorf("recursive %s for %s: %v, check says %v", resource, u, got[u], want)
			}
		}
	}
	for _, tc := range []struct {
		name string
		req  engine.ExpandRequest
		want error
	}{
		{"negative max_nodes", engine.ExpandRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", MaxNodes: -1}, engine.ErrInvalidArgument},
		{"max_nodes over the maximum", engine.ExpandRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", MaxNodes: check.MaxTraceNodes + 1}, engine.ErrInvalidArgument},
		{"unknown type", engine.ExpandRequest{ResourceType: "video", ResourceID: "plan", Permission: "view"}, check.ErrUnknownType},
		{"unknown permission", engine.ExpandRequest{ResourceType: "doc", ResourceID: "plan", Permission: "rename"}, check.ErrUnknownName},
		{"bad resource id", engine.ExpandRequest{ResourceType: "doc", ResourceID: "a b", Permission: "view"}, store.ErrInvalid},
	} {
		_, err := e.Expand(bg, tc.req)
		wantErr(t, tc.name, err, tc.want)
	}
}

func walk(n *check.TraceNode, fn func(*check.TraceNode)) {
	fn(n)
	for _, c := range n.Children {
		walk(c, fn)
	}
}

func count(n *check.TraceNode) int {
	total := 0
	walk(n, func(*check.TraceNode) { total++ })
	return total
}

// solveTree reads a recursive, complete expand tree as one equation per
// expanded object#relation, which memo and cut nodes refer back to, and
// solves them by iteration: the users among users that the tree says hold
// its root. user:* stands for all of them. Exclusions only subtract
// relations here, so iterating from nothing reaches the answer.
func solveTree(t testing.TB, tr *check.Trace, users []string) map[string]bool {
	t.Helper()
	if tr.Truncated {
		t.Fatal("cannot solve a truncated tree")
	}
	defs := map[string]*check.TraceNode{}
	walk(tr.Root, func(n *check.TraceNode) {
		if (n.Kind == check.KindRelation || n.Kind == check.KindPermission) && !n.Memo && !n.Cut {
			defs[n.Object+"#"+n.Relation] = n
		}
	})
	cur := map[string]map[string]bool{}
	var eval func(n *check.TraceNode) map[string]bool
	union := func(ns []*check.TraceNode) map[string]bool {
		out := map[string]bool{}
		for _, c := range ns {
			for u := range eval(c) {
				out[u] = true
			}
		}
		return out
	}
	eval = func(n *check.TraceNode) map[string]bool {
		switch n.Kind {
		case check.KindSubject:
			typ, id, _ := strings.Cut(n.Subject, ":")
			switch {
			case typ != "user" || strings.Contains(id, "#"):
				return nil // another type, or a userset of one
			case id == check.Wildcard:
				out := map[string]bool{}
				for _, u := range users {
					out[u] = true
				}
				return out
			}
			return map[string]bool{id: true}
		case check.KindRelation, check.KindPermission:
			if n.Memo || n.Cut {
				return cur[n.Object+"#"+n.Relation]
			}
			return union(n.Children)
		case check.KindIntersection, check.KindExclusion:
			if len(n.Children) != 2 {
				t.Fatalf("%s node with %d children", n.Kind, len(n.Children))
			}
			l, r := eval(n.Children[0]), eval(n.Children[1])
			out := map[string]bool{}
			for u := range l {
				if r[u] == (n.Kind == check.KindIntersection) {
					out[u] = true
				}
			}
			return out
		}
		return union(n.Children) // union and arrow
	}
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for changed, rounds := true, 0; changed; rounds++ {
		if rounds > 10*len(defs)+10 {
			t.Fatal("expand tree equations do not settle")
		}
		changed = false
		for _, k := range keys {
			next := eval(defs[k])
			if !reflect.DeepEqual(next, cur[k]) && !(len(next) == 0 && len(cur[k]) == 0) {
				changed = true
			}
			cur[k] = next
		}
	}
	return eval(tr.Root)
}

func (c *contract) read(t *testing.T) {
	e, s := c.sharing(t)
	readAll := func(f store.Filter, limit int) []string {
		t.Helper()
		var out []string
		req := engine.ReadRequest{Filter: f, Consistency: exact(s), Limit: limit}
		for pages := 0; ; pages++ {
			if pages > 1000 {
				t.Fatal("read does not end")
			}
			res, err := e.ReadRelationships(bg, req)
			ok(t, err)
			if limit > 0 && len(res.Relationships) > limit {
				t.Fatalf("page of %d over the limit of %d", len(res.Relationships), limit)
			}
			if res.At != s {
				t.Fatalf("read at %+v, want %+v", res.At, s)
			}
			for _, r := range res.Relationships {
				out = append(out, r.String())
			}
			if res.Cursor == "" {
				return out
			}
			req.Cursor = res.Cursor
		}
	}
	wantText := func(filter func(string) bool) []string {
		var out []string
		for _, r := range SharingRelationships {
			if filter(r) {
				out = append(out, r)
			}
		}
		sort.Strings(out)
		return out
	}
	for _, tc := range []struct {
		name   string
		filter store.Filter
		want   []string
	}{
		{"one object", store.Filter{ResourceType: "doc", ResourceID: "plan"},
			wantText(func(r string) bool { return strings.HasPrefix(r, "doc:plan#") })},
		{"one relation", store.Filter{ResourceType: "doc", Relation: "reviewer"},
			wantText(func(r string) bool { return strings.Contains(r, "#reviewer@") })},
		{"one subject", store.Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "olive"},
			[]string{"doc:draft#owner@user:olive", "doc:plan#owner@user:olive"}},
		{"usersets", store.Filter{ResourceType: "group", SubjectType: "group", SubjectRelation: "member"},
			[]string{"group:eng#member@group:sre#member", "group:sre#member@group:eng#member"}},
		{"no subject relation", store.Filter{ResourceType: "group", SubjectRelation: store.NoRelation},
			[]string{"group:eng#member@user:alice", "group:sre#member@user:sam"}},
		{"wildcard", store.Filter{ResourceType: "folder", SubjectType: "user", SubjectID: "*"},
			[]string{"folder:public#viewer@user:*"}},
		{"nothing", store.Filter{ResourceType: "user"}, nil},
	} {
		for _, limit := range []int{0, 1, 2, 5} {
			if got := readAll(tc.filter, limit); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s, limit %d: %v, want %v", tc.name, limit, got, tc.want)
			}
		}
	}
	for _, tc := range []struct {
		name string
		req  engine.ReadRequest
		want error
	}{
		{"negative limit", engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Limit: -1}, engine.ErrInvalidArgument},
		{"limit over the maximum", engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Limit: store.MaxReadLimit + 1}, engine.ErrInvalidArgument},
		{"long cursor", engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Cursor: strings.Repeat("c", 1025)}, engine.ErrInvalidArgument},
		{"no resource type", engine.ReadRequest{Filter: store.Filter{}}, store.ErrInvalid},
		{"subject id without type", engine.ReadRequest{Filter: store.Filter{ResourceType: "doc", SubjectID: "alice"}}, store.ErrInvalid},
	} {
		_, err := e.ReadRelationships(bg, tc.req)
		wantErr(t, tc.name, err, tc.want)
	}
}

func (c *contract) write(t *testing.T) {
	e, s := c.sharing(t)
	write := func(pre []store.Precondition, ups ...store.Update) (engine.WriteResult, error) {
		return e.Write(bg, engine.WriteRequest{Updates: ups, Preconditions: pre})
	}
	// Touching what exists changes nothing and makes no revision.
	res, err := write(nil, update(t, store.OpTouch, "doc:plan#owner@user:olive"))
	ok(t, err)
	if res.At != s {
		t.Fatalf("a write that changes nothing: %+v, want the head %+v", res.At, s)
	}
	res, err = write(nil, update(t, store.OpDelete, "doc:plan#owner@user:nobody"))
	ok(t, err)
	if res.At != s {
		t.Fatalf("deleting what does not exist: %+v, want the head %+v", res.At, s)
	}
	_, err = write(nil, update(t, store.OpCreate, "doc:plan#owner@user:olive"))
	wantErr(t, "create of an existing relationship", err, store.ErrConflict)

	// One write is one revision, with all of its updates or none.
	res, err = write(nil, update(t, store.OpCreate, "doc:new#owner@user:nina"), update(t, store.OpDelete, "doc:plan#owner@user:olive"),
		update(t, store.OpTouch, "doc:new#viewer@group:eng#member"))
	ok(t, err)
	if res.At.Revision != s.Revision+1 {
		t.Fatalf("write at %d, want %d", res.At.Revision, s.Revision+1)
	}
	if !allowed(t, e, exact(res.At), "doc:new#view", "user:alice") || allowed(t, e, exact(res.At), "doc:plan#edit", "user:olive") ||
		!allowed(t, e, exact(s), "doc:plan#edit", "user:olive") {
		t.Fatal("the write is not exactly one revision")
	}
	_, err = write(nil, update(t, store.OpTouch, "doc:atomic#owner@user:nina"), update(t, store.OpCreate, "doc:new#owner@user:nina"))
	wantErr(t, "a write with a conflict", err, store.ErrConflict)
	if allowed(t, e, engine.Consistency{Mode: engine.FullyConsistent}, "doc:atomic#view", "user:nina") {
		t.Fatal("a failed write applied some of its updates")
	}

	exists := func(must bool, f store.Filter) []store.Precondition {
		return []store.Precondition{{MustExist: must, Filter: f}}
	}
	_, err = write(exists(true, store.Filter{ResourceType: "doc", ResourceID: "plan", Relation: "owner"}), update(t, store.OpTouch, "doc:guarded#owner@user:gus"))
	wantErr(t, "must_exist that fails", err, store.ErrPrecondition)
	_, err = write(exists(false, store.Filter{ResourceType: "doc", ResourceID: "new"}), update(t, store.OpTouch, "doc:guarded#owner@user:gus"))
	wantErr(t, "must_not_exist that fails", err, store.ErrPrecondition)
	res, err = write(exists(true, store.Filter{ResourceType: "doc", ResourceID: "new", SubjectType: "group"}), update(t, store.OpTouch, "doc:guarded#owner@user:gus"))
	ok(t, err)
	if !allowed(t, e, fresh(res.At), "doc:guarded#view", "user:gus") {
		t.Fatal("a guarded write that held did not apply")
	}

	for _, tc := range []struct {
		name string
		req  engine.WriteRequest
	}{
		{"no updates", engine.WriteRequest{}},
		{"bad op", engine.WriteRequest{Updates: []store.Update{{Op: "upsert", Relationship: relationship(t, "doc:x#owner@user:a")}}}},
		{"duplicate", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#owner@user:a"), update(t, store.OpDelete, "doc:x#owner@user:a")}}},
		{"permission", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#view@user:a")}}},
		{"unknown type", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "video:x#owner@user:a")}}},
		{"subject not allowed", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#owner@group:eng#member")}}},
		{"wildcard not allowed", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#owner@user:*")}}},
		{"invalid relationship", engine.WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: store.Relationship{ResourceType: "doc"}}}}},
		{"too many updates", engine.WriteRequest{Updates: make([]store.Update, store.MaxUpdatesPerWrite+1)}},
		{"bad precondition", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#owner@user:a")},
			Preconditions: []store.Precondition{{Filter: store.Filter{}}}}},
		{"too many preconditions", engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:x#owner@user:a")},
			Preconditions: make([]store.Precondition, store.MaxPreconditions+1)}},
	} {
		_, err := e.Write(bg, tc.req)
		wantErr(t, tc.name, err, store.ErrInvalid)
	}
	// Deleting what the schema does not allow is refused only as a write
	// that changes nothing.
	head, err := e.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: "x", Permission: "view",
		Subject: subject(t, "user:a"), Consistency: engine.Consistency{Mode: engine.FullyConsistent}})
	ok(t, err)
	res, err = write(nil, update(t, store.OpDelete, "doc:x#view@user:a"))
	ok(t, err)
	if res.At != head.At {
		t.Fatalf("a delete of a permission: %+v, want the head %+v", res.At, head.At)
	}
}

func (c *contract) delete(t *testing.T) {
	e := c.newEngine(t, SharingSchema)
	var rels []string
	for i := 0; i < 5; i++ {
		rels = append(rels, fmt.Sprintf("doc:big#viewer@user:u%d", i))
	}
	s := touch(t, e, append(rels, "doc:big#owner@user:olive", "doc:small#viewer@user:u0")...)
	del := func(req engine.DeleteRequest) (engine.DeleteResult, error) { return e.DeleteRelationships(bg, req) }
	viewers := store.Filter{ResourceType: "doc", ResourceID: "big", Relation: "viewer"}
	readAt := func(at engine.Snapshot, f store.Filter) []string {
		t.Helper()
		res, err := e.ReadRelationships(bg, engine.ReadRequest{Filter: f, Consistency: exact(at), Limit: store.MaxReadLimit})
		ok(t, err)
		var out []string
		for _, r := range res.Relationships {
			out = append(out, r.String())
		}
		return out
	}

	_, err := del(engine.DeleteRequest{Filter: viewers, Limit: 3})
	wantErr(t, "more matches than the limit", err, store.ErrPrecondition)
	_, err = del(engine.DeleteRequest{Filter: viewers, Preconditions: []store.Precondition{{MustExist: true,
		Filter: store.Filter{ResourceType: "doc", ResourceID: "big", Relation: "banned"}}}})
	wantErr(t, "a precondition that fails", err, store.ErrPrecondition)
	if got := readAt(s, viewers); len(got) != 5 {
		t.Fatalf("refused deletes changed the data: %v", got)
	}

	r1, err := del(engine.DeleteRequest{Filter: viewers, Limit: 3, AllowPartial: true})
	ok(t, err)
	if r1.Deleted != 3 || !r1.Partial || r1.At.Revision != s.Revision+1 {
		t.Fatalf("first page: %+v", r1)
	}
	if got := readAt(r1.At, viewers); !reflect.DeepEqual(got, rels[3:]) {
		t.Fatalf("after the first page: %v, want %v (the first 3 in text order deleted)", got, rels[3:])
	}
	if got := readAt(s, viewers); !reflect.DeepEqual(got, rels) {
		t.Fatalf("the snapshot before the delete changed: %v", got)
	}
	r2, err := del(engine.DeleteRequest{Filter: viewers, Limit: 2, AllowPartial: true})
	ok(t, err)
	if r2.Deleted != 2 || r2.Partial || r2.At.Revision != r1.At.Revision+1 {
		t.Fatalf("second page, exactly the limit: %+v", r2)
	}
	r3, err := del(engine.DeleteRequest{Filter: viewers})
	ok(t, err)
	if r3.Deleted != 0 || r3.Partial || r3.At != r2.At {
		t.Fatalf("a delete that matches nothing: %+v, want the head %+v", r3, r2.At)
	}
	if got := readAt(r2.At, store.Filter{ResourceType: "doc"}); !reflect.DeepEqual(got, []string{"doc:big#owner@user:olive", "doc:small#viewer@user:u0"}) {
		t.Fatalf("other relationships after the deletes: %v", got)
	}
	r4, err := del(engine.DeleteRequest{Filter: store.Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "olive"},
		Preconditions: []store.Precondition{{MustExist: false, Filter: viewers}}})
	ok(t, err)
	if r4.Deleted != 1 || allowed(t, e, fresh(r4.At), "doc:big#view", "user:olive") {
		t.Fatalf("delete by subject: %+v", r4)
	}

	for _, tc := range []struct {
		name string
		req  engine.DeleteRequest
	}{
		{"no resource type", engine.DeleteRequest{}},
		{"negative limit", engine.DeleteRequest{Filter: viewers, Limit: -1}},
		{"limit over the maximum", engine.DeleteRequest{Filter: viewers, Limit: store.MaxDeletesPerFilter + 1}},
		{"bad precondition", engine.DeleteRequest{Filter: viewers, Preconditions: []store.Precondition{{Filter: store.Filter{ResourceType: "Doc"}}}}},
		{"too many preconditions", engine.DeleteRequest{Filter: viewers, Preconditions: make([]store.Precondition, store.MaxPreconditions+1)}},
	} {
		_, err := del(tc.req)
		wantErr(t, tc.name, err, store.ErrInvalid)
	}
}

func (c *contract) cancelled(t *testing.T) {
	e, s := c.sharing(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	alice := subject(t, "user:alice")
	_, err := e.Check(ctx, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: alice})
	wantErr(t, "Check", err, context.Canceled)
	_, err = e.CheckBulk(ctx, engine.CheckBulkRequest{Items: []engine.CheckItem{{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: alice}}})
	wantErr(t, "CheckBulk", err, context.Canceled)
	_, err = e.LookupResources(ctx, engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view", Subject: alice})
	wantErr(t, "LookupResources", err, context.Canceled)
	_, err = e.LookupSubjects(ctx, engine.LookupSubjectsRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", SubjectType: "user"})
	wantErr(t, "LookupSubjects", err, context.Canceled)
	_, err = e.Expand(ctx, engine.ExpandRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view"})
	wantErr(t, "Expand", err, context.Canceled)
	_, err = e.ReadRelationships(ctx, engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}})
	wantErr(t, "ReadRelationships", err, context.Canceled)
	_, err = e.Write(ctx, engine.WriteRequest{Updates: []store.Update{update(t, store.OpTouch, "doc:late#owner@user:lee")}})
	wantErr(t, "Write", err, context.Canceled)
	_, err = e.DeleteRelationships(ctx, engine.DeleteRequest{Filter: store.Filter{ResourceType: "doc"}, AllowPartial: true})
	wantErr(t, "DeleteRelationships", err, context.Canceled)
	res, err := e.ReadRelationships(bg, engine.ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Consistency: engine.Consistency{Mode: engine.FullyConsistent}, Limit: store.MaxReadLimit})
	ok(t, err)
	if res.At != s || len(res.Relationships) != 9 {
		t.Fatalf("cancelled writes changed the data: at %+v, %d doc relationships", res.At, len(res.Relationships))
	}
}

// concurrent writes from several goroutines, each reading its own writes
// back through the token it got.
func (c *contract) concurrent(t *testing.T) {
	e, _ := c.sharing(t)
	const writers, rounds = 4, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				rel := fmt.Sprintf("doc:c%d#viewer@user:w%d", i, w)
				r, _ := store.ParseRelationship(rel)
				res, err := e.Write(bg, engine.WriteRequest{Updates: []store.Update{{Op: store.OpTouch, Relationship: r}}})
				if err != nil {
					errs <- err
					return
				}
				got, err := e.Check(bg, engine.CheckRequest{ResourceType: "doc", ResourceID: fmt.Sprintf("c%d", i), Permission: "view",
					Subject: store.Subject{Type: "user", ID: fmt.Sprintf("w%d", w)}, Consistency: fresh(res.At)})
				if err == nil && (!got.Allowed || got.At.Revision < res.At.Revision) {
					err = fmt.Errorf("%s not visible at %+v after the write at %d", rel, got.At, res.At.Revision)
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	ids := lookupAll(t, e, engine.LookupResourcesRequest{ResourceType: "doc", Permission: "view",
		Subject: subject(t, "user:w0"), Consistency: engine.Consistency{Mode: engine.FullyConsistent}})
	if len(ids) != rounds+1 { // c0..c24 and readme
		t.Fatalf("w0 sees %d docs, want %d", len(ids), rounds+1)
	}
}

// randomGraph returns random relationships over SharingSchema: groups and
// folders that nest, sometimes in cycles, wildcards, bans, editors through
// groups and reviewers. It is deterministic in seed.
func randomGraph(seed int64) []string {
	rng := rand.New(rand.NewSource(seed))
	users, groups, folders, docs := 6, 2+rng.Intn(4), 2+rng.Intn(4), 6
	u := func() string { return fmt.Sprintf("user:u%d", rng.Intn(users)) }
	g := func() string { return fmt.Sprintf("g%d", rng.Intn(groups)) }
	fo := func() string { return fmt.Sprintf("f%d", rng.Intn(folders)) }
	seen := map[string]bool{}
	var rels []string
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			rels = append(rels, r)
		}
	}
	for i := 0; i < groups*2; i++ {
		add("group:" + g() + "#member@" + u())
		if rng.Intn(2) == 0 {
			add("group:" + g() + "#member@group:" + g() + "#member")
		}
	}
	for i := 0; i < folders*2; i++ {
		if rng.Intn(2) == 0 {
			add("folder:" + fo() + "#parent@folder:" + fo())
		}
		add("folder:" + fo() + "#viewer@" + u())
		switch rng.Intn(8) {
		case 0:
			add("folder:" + fo() + "#viewer@user:*")
		case 1, 2:
			add("folder:" + fo() + "#viewer@group:" + g() + "#member")
		case 3:
			add("folder:" + fo() + "#owner@" + u())
		}
	}
	for i := 0; i < docs; i++ {
		d := fmt.Sprintf("doc:d%d", i)
		for k := 0; k < 4; k++ {
			switch rng.Intn(9) {
			case 0:
				add(d + "#parent@folder:" + fo())
			case 1:
				add(d + "#owner@" + u())
			case 2:
				add(d + "#editor@" + u())
			case 3:
				add(d + "#editor@group:" + g() + "#member")
			case 4:
				add(d + "#viewer@" + u())
			case 5:
				add(d + "#viewer@group:" + g() + "#member")
			case 6:
				add(d + "#banned@" + u())
			case 7:
				add(d + "#reviewer@" + u())
			case 8:
				if rng.Intn(3) == 0 {
					add(d + "#viewer@user:*")
				}
			}
		}
	}
	return rels
}

// randomGraphs: on random data every query agrees with Check.
func (c *contract) randomGraphs(t *testing.T) {
	graphs := 12
	if testing.Short() {
		graphs = 3
	}
	users := []string{"u0", "u1", "u2", "u3", "u4", "u5", "nobody"}
	for seed := int64(0); seed < int64(graphs); seed++ {
		e := c.newEngine(t, SharingSchema)
		s := touch(t, e, randomGraph(seed)...)
		cons := exact(s)
		var objects []string
		for i := 0; i < 6; i++ {
			for _, p := range []string{"view", "edit", "review"} {
				objects = append(objects, fmt.Sprintf("doc:d%d#%s", i, p))
			}
		}
		for i := 0; i < 4; i++ {
			objects = append(objects, fmt.Sprintf("folder:f%d#view", i), fmt.Sprintf("group:g%d#member", i))
		}
		for _, o := range objects {
			obj, perm, _ := strings.Cut(o, "#")
			typ, id, _ := strings.Cut(obj, ":")
			want := map[string]bool{}
			items := make([]engine.CheckItem, len(users))
			for i, u := range users {
				want[u] = allowed(t, e, cons, o, "user:"+u)
				items[i] = engine.CheckItem{ResourceType: typ, ResourceID: id, Permission: perm, Subject: store.Subject{Type: "user", ID: u}}
			}
			bulk, err := e.CheckBulk(bg, engine.CheckBulkRequest{Items: items, Consistency: cons})
			ok(t, err)
			for i, u := range users {
				if bulk.Results[i].Allowed != want[u] || bulk.Results[i].Err != nil {
					t.Errorf("seed %d: bulk %s for %s: %+v, check says %v", seed, o, u, bulk.Results[i], want[u])
				}
			}
			found := subjectsAll(t, e, engine.LookupSubjectsRequest{ResourceType: typ, ResourceID: id, Permission: perm,
				SubjectType: "user", Consistency: cons, Limit: 2})
			for _, u := range users {
				if got := holds(found, u); got != want[u] {
					t.Errorf("seed %d: lookup subjects %s has %s: %v, check says %v (%+v)", seed, o, u, got, want[u], found)
				}
			}
			tree, err := e.Expand(bg, engine.ExpandRequest{ResourceType: typ, ResourceID: id, Permission: perm,
				Recursive: true, MaxNodes: check.MaxTraceNodes, Consistency: cons})
			ok(t, err)
			got := solveTree(t, tree.Tree, users)
			for _, u := range users {
				if got[u] != want[u] {
					t.Errorf("seed %d: recursive expand %s for %s: %v, check says %v", seed, o, u, got[u], want[u])
				}
			}
			groups := subjectsAll(t, e, engine.LookupSubjectsRequest{ResourceType: typ, ResourceID: id, Permission: perm,
				SubjectType: "group", SubjectRelation: "member", Consistency: cons, Limit: 3})
			for i := 0; i < 4; i++ {
				g := fmt.Sprintf("g%d", i)
				if got, want := holds(groups, g), allowed(t, e, cons, o, "group:"+g+"#member"); got != want {
					t.Errorf("seed %d: lookup subjects %s has group:%s#member: %v, check says %v", seed, o, g, got, want)
				}
			}
		}
		for _, u := range users {
			for _, perm := range []string{"view", "review"} {
				ids := lookupAll(t, e, engine.LookupResourcesRequest{ResourceType: "doc", Permission: perm,
					Subject: store.Subject{Type: "user", ID: u}, Consistency: cons, Limit: 2})
				var want []string
				for i := 0; i < 6; i++ {
					if d := fmt.Sprintf("d%d", i); allowed(t, e, cons, "doc:"+d+"#"+perm, "user:"+u) {
						want = append(want, d)
					}
				}
				if want == nil {
					want = []string{}
				}
				if !reflect.DeepEqual(ids, want) {
					t.Errorf("seed %d: lookup doc#%s for %s: %v, check says %v", seed, perm, u, ids, want)
				}
			}
		}
	}
}

// holds reports whether id is among found, directly or through the
// wildcard.
func holds(found []check.FoundSubject, id string) bool {
	for _, f := range found {
		if f.ID == id {
			return true
		}
		if f.ID == check.Wildcard {
			for _, ex := range f.Excluded {
				if ex == id {
					return false
				}
			}
			return true
		}
	}
	return false
}
