package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// POST /v1/lookup/subjects lists who holds a permission on one object, a
// page at a time at one snapshot, with wildcards and the subjects they
// leave out.
func TestLookupSubjects(t *testing.T) {
	h := newHarness(t, 0)
	written := h.setup()
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "group:eng#member@user:bob"},
		{"op": "touch", "relationship": "doc:plan#banned@user:bob"},
	}})
	// At the setup token bob is neither a member nor banned.
	out := h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user",
		"limit": 1, "consistency": map[string]string{"mode": "at_exact_snapshot", "token": written}})
	if got, _ := json.Marshal(out["subjects"]); string(got) != `[{"subject":"user:alice"}]` || out["cursor"] != "alice" || out["looked_up_at"] != written {
		t.Fatalf("first page: %v", out)
	}
	out = h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user",
		"limit": 1, "cursor": "alice", "consistency": map[string]string{"mode": "at_exact_snapshot", "token": written}})
	if got, _ := json.Marshal(out["subjects"]); string(got) != `[{"subject":"user:olga"}]` || out["cursor"] != "" {
		t.Fatalf("second page: %v", out)
	}
	// At the head bob is banned, so not listed.
	out = h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user",
		"consistency": map[string]string{"mode": "fully_consistent"}})
	if got, _ := json.Marshal(out["subjects"]); string(got) != `[{"subject":"user:alice"},{"subject":"user:olga"}]` {
		t.Fatalf("at the head: %s", got)
	}
	out = h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "group",
		"subject_relation": "member"})
	if got, _ := json.Marshal(out["subjects"]); string(got) != `[{"subject":"group:eng#member"}]` {
		t.Fatalf("usersets: %s", got)
	}
	out = h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:none", "permission": "view", "subject_type": "user"})
	if got, _ := json.Marshal(out["subjects"]); string(got) != `[]` {
		t.Fatalf("nobody: %s", got)
	}

	// A wildcard viewer, less the banned.
	h.ok("PUT", "/v1/schema", map[string]any{"schema": strings.Replace(schemaSrc, "relation viewer: user | group#member", "relation viewer: user | group#member | user:*", 1)})
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "doc:plan#viewer@user:*"},
		{"op": "touch", "relationship": "doc:plan#banned@user:mallory"},
	}})
	out = h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user",
		"consistency": map[string]string{"mode": "fully_consistent"}})
	if got, _ := json.Marshal(out["subjects"]); string(got) != `[{"excluded":["user:bob","user:mallory"],"subject":"user:*"}]` || out["cursor"] != "" {
		t.Fatalf("wildcard: %s %v", got, out)
	}

	for _, c := range []struct {
		name string
		body any
		code int
		err  string
	}{
		{"resource", map[string]any{"resource": "doc", "permission": "view", "subject_type": "user"}, 400, "invalid_argument"},
		{"type", map[string]any{"resource": "ghost:a", "permission": "view", "subject_type": "user"}, 400, "invalid_argument"},
		{"permission", map[string]any{"resource": "doc:a", "permission": "nope", "subject_type": "user"}, 400, "invalid_argument"},
		{"subject type", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "ghost"}, 400, "invalid_argument"},
		{"subject relation", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "group", "subject_relation": "nope"}, 400, "invalid_argument"},
		{"limit", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "user", "limit": 1001}, 400, "invalid_argument"},
		{"cursor", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "user", "cursor": "a b"}, 400, "invalid_argument"},
		{"consistency", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "user", "consistency": map[string]string{"mode": "at_least_as_fresh"}}, 400, "invalid_argument"},
		{"unknown field", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x"}, 400, "invalid_argument"},
	} {
		if code, out := h.call("POST", "/v1/lookup/subjects", c.body); code != c.code || errCode(out) != c.err {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if code, out, _ := h.do("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "user"}, ""); code != 401 {
		t.Errorf("no key: %d %v", code, out)
	}
}

func TestLookupSubjectsWithoutSchema(t *testing.T) {
	h := newHarness(t, 0)
	if code, out := h.call("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:a", "permission": "view", "subject_type": "user"}); code != 424 || errCode(out) != "no_schema" {
		t.Fatalf("lookup before a schema: %d %v", code, out)
	}
}
