package api

import (
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// A bulk check of exactly MaxBulkChecks items is accepted and answers every
// item in the order it was sent.
func TestCheckBulkAtLimit(t *testing.T) {
	h := newHarness(t, time.Hour)
	h.setup()
	items := make([]map[string]string, MaxBulkChecks)
	for i := range items {
		subject := "user:alice"
		if i%2 == 1 {
			subject = "user:nobody"
		}
		items[i] = map[string]string{"resource": "doc:memo", "permission": "view", "subject": subject}
	}
	out := h.ok("POST", "/v1/check/bulk", map[string]any{"items": items, "consistency": map[string]string{"mode": "fully_consistent"}})
	res := out["results"].([]any)
	if len(res) != MaxBulkChecks {
		t.Fatalf("%d results, want %d", len(res), MaxBulkChecks)
	}
	for i, r := range res {
		got := r.(map[string]any)
		if want := i%2 == 0; (got["allowed"] == true) != want || got["error"] != nil {
			t.Fatalf("result %d = %v, want allowed=%v", i, got, want)
		}
	}
}

// Items that do not parse are answered with their own error, and the valid
// items around them keep their positions.
func TestCheckBulkUnparseableItemsKeepPositions(t *testing.T) {
	h := newHarness(t, time.Hour)
	h.setup()
	items := []map[string]string{
		{"resource": "memo", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:memo", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:memo", "permission": "view", "subject": "alice"},
		{"resource": "doc:memo", "permission": "view", "subject": "user:nobody"},
		{"resource": "doc:", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice"},
	}
	out := h.ok("POST", "/v1/check/bulk", map[string]any{"items": items, "consistency": map[string]string{"mode": "fully_consistent"}})
	res := out["results"].([]any)
	if len(res) != len(items) {
		t.Fatalf("%d results, want %d", len(res), len(items))
	}
	type want struct {
		failed  bool
		allowed bool
	}
	for i, w := range []want{{true, false}, {false, true}, {true, false}, {false, false}, {true, false}, {false, true}} {
		got := res[i].(map[string]any)
		if failed := got["error"] != nil; failed != w.failed {
			t.Fatalf("result %d = %v, want failed=%v", i, got, w.failed)
		}
		if !w.failed && (got["allowed"] == true) != w.allowed {
			t.Fatalf("result %d = %v, want allowed=%v", i, got, w.allowed)
		}
	}
}

// With AuditChecks, a bulk check whose first item does not parse records
// only the items that were answered, and each record names its own item.
func TestAuditCheckBulkSkipsUnparseableItems(t *testing.T) {
	h := newAuditHarnessWith(t, true)
	if code, out := h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": schemaSrc}); code != 200 {
		t.Fatalf("schema: %d %v", code, out)
	}
	if code, out := h.do("POST", "/v1/relationships/write", apiKey, "", map[string]any{
		"updates": []map[string]string{{"op": "touch", "relationship": "doc:readme#viewer@user:alice"}}}); code != 200 {
		t.Fatalf("write: %d %v", code, out)
	}
	before := len(h.records())
	code, out := h.do("POST", "/v1/check/bulk", apiKey, "", map[string]any{"items": []map[string]string{
		{"resource": "readme", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:readme", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:readme", "permission": "view", "subject": "bob"},
		{"resource": "doc:readme", "permission": "view", "subject": "user:carol"},
	}})
	if code != 200 {
		t.Fatalf("bulk: %d %v", code, out)
	}
	recs := h.records()[before:]
	if len(recs) != 2 {
		t.Fatalf("%d records, want 2: %+v", len(recs), recs)
	}
	if recs[0].Decision != audit.Allow || recs[1].Decision != audit.Deny {
		t.Errorf("decisions %v then %v, want allow then deny", recs[0].Decision, recs[1].Decision)
	}
}
