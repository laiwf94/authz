package store

import (
	"errors"
	"strings"
	"testing"
)

const caveatSchema = `
caveat ip_allowed(allowed cidr, client_ip ipaddress) {
  // Written with comments and spacing the canonical form keeps.
  allowed.containsIP(client_ip)
}

definition user {}

definition doc {
  relation viewer: user | user with ip_allowed
  relation guest: user with ip_allowed
}
`

// A schema with caveats is stored in canonical form, survives a restart,
// and keeps relationships without a caveat out of caveat-only subject
// types. Writing caveated relationships comes with check support.
func TestSchemaWithCaveats(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	if _, err := s.WriteSchema(caveatSchema); err != nil {
		t.Fatal(err)
	}
	sc, src := s.Schema()
	if sc.Caveats["ip_allowed"] == nil || !strings.HasPrefix(src, "caveat ip_allowed(allowed cidr, client_ip ipaddress) {\n  // Written") {
		t.Fatalf("stored schema:\n%s", src)
	}
	if _, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:alice")}}, nil); err != nil {
		t.Fatalf("plain subject type refused: %v", err)
	}
	_, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#guest@user:bob")}}, nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "allowed: user with ip_allowed") {
		t.Fatalf("relationship without the caveat on a caveat-only relation: %v", err)
	}

	// Dropping the plain subject type breaks the stored relationship.
	_, err = s.WriteSchema(strings.Replace(caveatSchema, "relation viewer: user | user with ip_allowed", "relation viewer: user with ip_allowed", 1))
	if !errors.Is(err, ErrPrecondition) {
		t.Fatalf("schema dropping a used subject type: %v", err)
	}
	s.Close()

	s2 := newStore(t, dir)
	sc2, src2 := s2.Schema()
	if src2 != src || sc2.Caveats["ip_allowed"] == nil {
		t.Fatalf("schema after restart:\n%s\nwant:\n%s", src2, src)
	}
	r, err := sc2.Caveats["ip_allowed"].Program.Eval(map[string]any{"allowed": "10.0.0.0/8", "client_ip": "10.0.0.1"})
	if err != nil || r.Value != true {
		t.Fatalf("recovered caveat evaluates to %+v, %v", r, err)
	}
}
