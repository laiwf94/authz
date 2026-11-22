package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

func TestExplainAgreesWithCheck(t *testing.T) {
	f := newFixture(t, Options{CacheSize: 100, Quantum: time.Hour})
	f.schema(t)
	w := f.write(t, "touch group:eng#member@user:alice", "touch doc:plan#viewer@group:eng#member",
		"touch doc:plan#owner@user:olga", "touch doc:plan#banned@user:olga")
	fresh := Consistency{Mode: AtLeastAsFresh, Token: w.Token}
	for _, c := range []struct {
		subject string
		want    bool
		role    check.TraceRole
	}{
		{"user:alice", true, check.RoleGrant},
		{"user:olga", false, check.RoleDeny}, // owner, but banned
		{"user:bob", false, check.RoleDeny},
	} {
		req := CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: subj(t, c.subject), Consistency: fresh}
		// Asked twice: the second explain must not be a bare cache hit.
		for range 2 {
			res, tr, err := f.e.Explain(context.Background(), req, 0)
			if err != nil {
				t.Fatalf("explain %s: %v", c.subject, err)
			}
			want := f.check(t, "doc:plan", "view", c.subject, fresh)
			if res.Allowed != c.want || res.Allowed != want.Allowed || res.Permissionship != want.Permissionship {
				t.Fatalf("%s: explain %+v, check %+v, want %v", c.subject, res, want, c.want)
			}
			if res.At.Revision < w.Revision || res.At.Token != f.tok.Encode(res.At.Revision) {
				t.Fatalf("%s: explained at %+v, before the write %d", c.subject, res.At, w.Revision)
			}
			if tr == nil || tr.Root == nil || tr.Root.Object != "doc:plan" || tr.Root.Relation != "view" ||
				tr.Root.Result != c.want || tr.Root.Role != c.role || len(tr.Root.Children) == 0 || tr.Truncated {
				t.Fatalf("%s: trace %+v", c.subject, tr)
			}
		}
	}

	// The node limit bounds the trace but not the answer.
	res, tr, err := f.e.Explain(context.Background(), CheckRequest{ResourceType: "doc", ResourceID: "plan",
		Permission: "view", Subject: subj(t, "user:alice"), Consistency: fresh}, 1)
	if err != nil || !res.Allowed || tr.Nodes != 1 || !tr.Truncated {
		t.Fatalf("explain with one node = %+v %+v %v", res, tr, err)
	}
	if f.m.Counter("grantd_check_dispatches_total", "", "").Value() == 0 {
		t.Error("explains recorded no dispatches")
	}
}

func TestExplainConditional(t *testing.T) {
	f := newFixture(t, Options{})
	if _, err := f.st.WriteSchema(`
caveat office(ip string) { ip == "10.0.0.1" }
definition user {}
definition doc { relation viewer: user with office
  permission view = viewer }`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Write(context.Background(), WriteRequest{Updates: []store.Update{{Op: store.OpTouch,
		Relationship: rel(t, "doc:plan#viewer@user:alice"), Caveat: &store.Caveat{Name: "office"}}}}); err != nil {
		t.Fatal(err)
	}
	req := CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: subj(t, "user:alice"),
		Consistency: Consistency{Mode: FullyConsistent}}
	res, tr, err := f.e.Explain(context.Background(), req, 0)
	if err != nil || res.Allowed || res.Permissionship != check.Conditional || len(res.Missing) != 1 || res.Missing[0] != "ip" ||
		tr.Root.Role != check.RoleConditional {
		t.Fatalf("conditional explain = %+v %+v %v", res, tr, err)
	}
	req.Context = map[string]any{"ip": "10.0.0.1"}
	if res, tr, err := f.e.Explain(context.Background(), req, 0); err != nil || !res.Allowed || tr.Root.Role != check.RoleGrant {
		t.Fatalf("explain with the caveat's context = %+v %+v %v", res, tr, err)
	}
}

func TestExplainErrors(t *testing.T) {
	f := newFixture(t, Options{})
	f.schema(t)
	for _, c := range []struct {
		req  CheckRequest
		want error
	}{
		{CheckRequest{ResourceType: "nope", ResourceID: "a", Permission: "view", Subject: subj(t, "user:a")}, check.ErrUnknownType},
		{CheckRequest{ResourceType: "doc", ResourceID: "a", Permission: "view", Subject: subj(t, "user:a"),
			Consistency: Consistency{Mode: AtLeastAsFresh, Token: "bogus"}}, token.ErrInvalid},
		{CheckRequest{ResourceType: "doc", ResourceID: "a b", Permission: "view", Subject: subj(t, "user:a")}, store.ErrInvalid},
	} {
		if res, tr, err := f.e.Explain(context.Background(), c.req, 0); !errors.Is(err, c.want) || tr != nil || res.Allowed {
			t.Errorf("Explain(%+v) = %+v %v %v, want %v", c.req, res, tr, err, c.want)
		}
	}
}
