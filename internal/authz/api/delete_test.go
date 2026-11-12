package api

import (
	"encoding/json"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// POST /v1/relationships/delete removes the relationships matching a
// filter in one revision, up to a limit, once its preconditions hold.
func TestDeleteByFilter(t *testing.T) {
	h := newHarness(t, 0)
	written := h.setup()
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "doc:plan#viewer@user:bob"},
		{"op": "touch", "relationship": "doc:plan#viewer@user:carol"},
	}})
	viewers := map[string]any{"resource_type": "doc", "resource_id": "plan", "relation": "viewer"}

	for _, c := range []struct {
		name string
		body any
		code int
		err  string
	}{
		{"over the limit", map[string]any{"filter": viewers, "limit": 2}, 412, "failed_precondition"},
		{"precondition", map[string]any{"filter": viewers, "preconditions": []map[string]any{
			{"must_exist": false, "filter": map[string]string{"resource_type": "doc", "relation": "owner"}}}}, 412, "failed_precondition"},
		{"no type", map[string]any{"filter": map[string]string{"resource_id": "plan"}}, 400, "invalid_argument"},
		{"limit", map[string]any{"filter": viewers, "limit": 1001}, 400, "invalid_argument"},
		{"unknown field", map[string]any{"filter": viewers, "cursor": "x"}, 400, "invalid_argument"},
	} {
		if code, out := h.call("POST", "/v1/relationships/delete", c.body); code != c.code || errCode(out) != c.err {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if code, out, _ := h.do("POST", "/v1/relationships/delete", map[string]any{"filter": viewers}, ""); code != 401 {
		t.Errorf("no key: %d %v", code, out)
	}

	// Two pages of two in text order: the group userset and bob, then carol.
	out := h.ok("POST", "/v1/relationships/delete", map[string]any{"filter": viewers, "limit": 2, "allow_partial": true,
		"preconditions": []map[string]any{{"must_exist": true, "filter": map[string]string{"resource_type": "doc", "relation": "owner"}}}})
	if out["deleted"] != 2.0 || out["partial"] != true || out["deleted_at"] == "" {
		t.Fatalf("first page: %v", out)
	}
	first := out["deleted_at"].(string)
	read := h.ok("POST", "/v1/relationships/read", map[string]any{"filter": viewers,
		"consistency": map[string]string{"mode": "at_least_as_fresh", "token": first}})
	if got, _ := json.Marshal(read["relationships"]); string(got) != `["doc:plan#viewer@user:carol"]` {
		t.Fatalf("after the first page: %s", got)
	}
	out = h.ok("POST", "/v1/relationships/delete", map[string]any{"filter": viewers, "limit": 2, "allow_partial": true})
	if out["deleted"] != 1.0 || out["partial"] != false {
		t.Fatalf("second page: %v", out)
	}
	last := out["deleted_at"]
	out = h.ok("POST", "/v1/relationships/delete", map[string]any{"filter": viewers})
	if out["deleted"] != 0.0 || out["partial"] != false || out["deleted_at"] != last {
		t.Fatalf("empty delete: %v", out)
	}
	// Alice viewed through the group; the setup snapshot still says so.
	chk := h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice",
		"consistency": map[string]string{"mode": "at_least_as_fresh", "token": last.(string)}})
	if chk["allowed"] != false {
		t.Fatalf("check after the delete: %v", chk)
	}
	chk = h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice",
		"consistency": map[string]string{"mode": "at_exact_snapshot", "token": written}})
	if chk["allowed"] != true {
		t.Fatalf("check at the setup snapshot: %v", chk)
	}
}

func TestDeleteByFilterWithoutSchema(t *testing.T) {
	h := newHarness(t, 0)
	if code, out := h.call("POST", "/v1/relationships/delete", map[string]any{"filter": map[string]string{"resource_type": "doc"}}); code != 424 || errCode(out) != "no_schema" {
		t.Fatalf("delete before a schema: %d %v", code, out)
	}
}

// A delete by filter is audited as a relationships write whose delete
// count is what it removed; a refused one is not audited.
func TestDeleteByFilterAudit(t *testing.T) {
	h := newAuditHarness(t)
	h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": schemaSrc})
	h.do("POST", "/v1/relationships/write", apiKey, "", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "doc:a#viewer@user:x"}, {"op": "touch", "relationship": "doc:b#viewer@user:x"}}})
	if code, _ := h.do("POST", "/v1/relationships/delete", apiKey, "", map[string]any{"filter": map[string]string{"resource_type": "doc"}, "limit": 1}); code != 412 {
		t.Fatalf("over the limit: %d", code)
	}
	code, out := h.do("POST", "/v1/relationships/delete", secondKey, "req-del", map[string]any{
		"filter":        map[string]string{"resource_type": "doc", "subject_type": "user", "subject_id": "x"},
		"preconditions": []map[string]any{{"must_exist": true, "filter": map[string]string{"resource_type": "doc"}}}})
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	recs := h.records()
	if len(recs) != 3 {
		t.Fatalf("%d records, want 3", len(recs))
	}
	r := recs[2]
	var p audit.RelationshipsWritten
	json.Unmarshal(r.Data, &p)
	if r.Event != audit.EventRelationshipsWritten || r.Action != "relationships.delete" || r.Actor != KeyID(secondKey) ||
		!h.logged("req-del", r.CorrelationID) || p != (audit.RelationshipsWritten{Revision: out["deleted_at"].(string), Delete: 2, Preconditions: 1}) {
		t.Fatalf("delete record: %+v %+v", r.Envelope, p)
	}
}
