package store

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRelationship(t *testing.T) {
	good := map[string]Relationship{
		"doc:readme#viewer@user:alice":                  {"doc", "readme", "viewer", "user", "alice", ""},
		"doc:a/b.c#viewer@group:eng#member":             {"doc", "a/b.c", "viewer", "group", "eng", "member"},
		"doc:x#viewer@user:*":                           {"doc", "x", "viewer", "user", "*", ""},
		"tenant_1:A-b=c+d|e#owner@user:u_9.Z":           {"tenant_1", "A-b=c+d|e", "owner", "user", "u_9.Z", ""},
		"doc:" + strings.Repeat("a", 128) + "#v@user:x": {"doc", strings.Repeat("a", 128), "v", "user", "x", ""},
	}
	for in, want := range good {
		got, err := ParseRelationship(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s parsed as %+v", in, got)
		}
		if got.String() != in {
			t.Errorf("%s rendered as %s", in, got.String())
		}
	}
	bad := []string{"", "doc:a#viewer", "doc:a@user:x", "doca#viewer@user:x", "doc:a#viewer@userx",
		"doc:a#viewer@user:x#", "Doc:a#viewer@user:x", "doc:#viewer@user:x", "doc:a#Viewer@user:x",
		"doc:a#viewer@User:x", "doc:a#viewer@user:x#M", "doc:a#viewer@user:*#member", "doc:*#viewer@user:x",
		"doc:a b#viewer@user:x", "doc:a#viewer@user:" + strings.Repeat("a", 129), "doc:a#viewer@USER:*",
		"doc:a#viewer@user:x y", "doc:é#viewer@user:x"}
	for _, in := range bad {
		if _, err := ParseRelationship(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted (err=%v)", in, err)
		}
	}
}

func TestParseSubject(t *testing.T) {
	if s, err := ParseSubject("group:eng#member", false); err != nil || s.String() != "group:eng#member" {
		t.Fatalf("%v %v", s, err)
	}
	if _, err := ParseSubject("user:*", false); err == nil {
		t.Fatal("wildcard accepted where not allowed")
	}
	if s, err := ParseSubject("user:*", true); err != nil || s.ID != "*" {
		t.Fatalf("wildcard: %v %v", s, err)
	}
	for _, bad := range []string{"user", "user:", ":x", "user:x#", "user:x#Bad", "user:*#m", "U:*"} {
		if _, err := ParseSubject(bad, true); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Relationship{"doc", "a", "viewer", "user", "x", ""}
	mutations := []func(r *Relationship){
		func(r *Relationship) { r.ResourceType = "" },
		func(r *Relationship) { r.ResourceID = "*" },
		func(r *Relationship) { r.Relation = "Viewer" },
		func(r *Relationship) { r.SubjectType = "1" },
		func(r *Relationship) { r.SubjectID = "" },
		func(r *Relationship) { r.SubjectRelation = "-" },
		func(r *Relationship) { r.SubjectID, r.SubjectRelation = "*", "member" },
	}
	if ok.Validate() != nil {
		t.Fatal("valid relationship rejected")
	}
	for i, m := range mutations {
		r := ok
		m(&r)
		if r.Validate() == nil {
			t.Errorf("mutation %d accepted: %+v", i, r)
		}
	}
	if (Subject{Type: "user", ID: "*"}).Validate() == nil {
		t.Error("wildcard subject passed Validate")
	}
	if (Subject{Type: "user", ID: "x", Relation: "Bad"}).Validate() == nil {
		t.Error("bad subject relation passed Validate")
	}
}

func FuzzParseRelationship(f *testing.F) {
	f.Add("doc:readme#viewer@group:eng#member")
	f.Add("doc:x#viewer@user:*")
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRelationship(s)
		if err != nil {
			return
		}
		if r.Validate() != nil {
			t.Fatalf("parsed but invalid: %q", s)
		}
		back, err := ParseRelationship(r.String())
		if err != nil || back != r {
			t.Fatalf("round trip of %q failed: %v %+v", s, err, back)
		}
	})
}
