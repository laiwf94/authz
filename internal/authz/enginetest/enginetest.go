// Package enginetest holds the contract every engine.Engine meets, as a
// test suite (Run), and the engines tests in other packages use in place
// of a server: Fake, a deterministic in-memory engine held to the same
// contract, and NewLocal, the real engine over an in-memory store.
//
// The gateway (internal/authn) and the MCP proxy (internal/agents) ask
// grantd's engine in the same process; their tests take a Fake seeded
// with the relationships they need:
//
//	e, err := enginetest.NewFake(enginetest.SharingSchema, enginetest.SharingRelationships...)
//	res, err := e.Check(ctx, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan",
//		Permission: "view", Subject: store.Subject{Type: "user", ID: "alice"}})
//
// Fake.Fail and Fake.ExpireBefore make it fail the way a real engine can.
// A new Engine implementation (a remote client, a replica, a cache in
// front of one) proves itself with Run:
//
//	func TestContract(t *testing.T) { enginetest.Run(t, newMyEngine) }
package enginetest

import (
	"bytes"
	"context"
	"testing"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

// SharingSchema is the schema of the contract's fixture: nested groups, a
// folder tree, a wildcard, an exclusion and an intersection.
const SharingSchema = `
definition user {}

definition group {
  relation member: user | group#member
}

definition folder {
  relation parent: folder
  relation owner: user
  relation viewer: user | user:* | group#member
  permission view = viewer + owner + parent->view
}

definition doc {
  relation parent: folder
  relation owner: user
  relation editor: user | group#member
  relation viewer: user | user:* | group#member
  relation reviewer: user
  relation banned: user
  permission edit = owner + editor
  permission view = (viewer + edit + parent->view) - banned
  permission review = reviewer & edit
}
`

// SharingRelationships is the contract's fixture data. Groups eng and sre
// contain each other; folder specs sits under root, which eng can view;
// public is open to everyone. Who holds what:
//
//	doc:plan   view: alice, ed, fiona, olive (sam is banned)
//	           edit: ed, olive; review: ed
//	doc:readme view: everyone but mallory
//	doc:draft  view: olive
var SharingRelationships = []string{
	"group:eng#member@user:alice",
	"group:eng#member@group:sre#member",
	"group:sre#member@user:sam",
	"group:sre#member@group:eng#member",
	"folder:root#viewer@group:eng#member",
	"folder:specs#parent@folder:root",
	"folder:specs#owner@user:fiona",
	"folder:public#viewer@user:*",
	"doc:plan#parent@folder:specs",
	"doc:plan#owner@user:olive",
	"doc:plan#editor@user:ed",
	"doc:plan#reviewer@user:ed",
	"doc:plan#reviewer@user:rex",
	"doc:plan#banned@user:sam",
	"doc:readme#parent@folder:public",
	"doc:readme#banned@user:mallory",
	"doc:draft#owner@user:olive",
}

// NewLocal returns the real engine over a new in-memory store holding
// schemaSrc and relationships, with tokens under TokenKey. opts.Store and
// opts.Tokens are filled in; the rest (cache, quantum, metrics) is used as
// given. The store is closed when t ends.
func NewLocal(t testing.TB, schemaSrc string, opts engine.Options, relationships ...string) *engine.Local {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.WriteSchema(schemaSrc); err != nil {
		t.Fatal(err)
	}
	tok, err := token.NewIssuer(bytes.Clone(TokenKey))
	if err != nil {
		t.Fatal(err)
	}
	opts.Store, opts.Tokens = st, tok
	e, err := engine.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) > 0 {
		touch(t, e, relationships...)
	}
	return e
}

// touch writes relationships in one revision.
func touch(t testing.TB, e engine.Engine, relationships ...string) engine.Snapshot {
	t.Helper()
	ups := make([]store.Update, len(relationships))
	for i, s := range relationships {
		r, err := store.ParseRelationship(s)
		if err != nil {
			t.Fatal(err)
		}
		ups[i] = store.Update{Op: store.OpTouch, Relationship: r}
	}
	res, err := e.Write(context.Background(), engine.WriteRequest{Updates: ups})
	if err != nil {
		t.Fatalf("writing %v: %v", relationships, err)
	}
	return res.At
}
