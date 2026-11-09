package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging/logtest"
)

const traceCheck = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

// With AuditChecks, every answered check is a decision record in the chain:
// the resource, the permission, the result, who was checked, the revision
// it was checked at, the API key and the request's correlation ID. Bulk
// checks write one record per answered item; items that failed, and checks
// that failed as a whole, write none.
func TestAuditCheckDecisions(t *testing.T) {
	h := newAuditHarnessWith(t, true)
	logtest.Check(t).Known(apiKey, secondKey).File(h.path)
	if code, out := h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": schemaSrc}); code != 200 {
		t.Fatalf("schema: %d %v", code, out)
	}
	if code, out := h.do("POST", "/v1/relationships/write", apiKey, "", map[string]any{
		"updates": []map[string]string{{"op": "touch", "relationship": "doc:readme#viewer@user:alice"}}}); code != 200 {
		t.Fatalf("write: %d %v", code, out)
	}
	before := len(h.records())

	code, out := h.do("POST", "/v1/check", secondKey, traceCheck, map[string]any{
		"resource": "doc:readme", "permission": "view", "subject": "user:alice", "consistency": map[string]any{"mode": "fully_consistent"}})
	if code != 200 || out["allowed"] != true {
		t.Fatalf("check: %d %v", code, out)
	}
	checkedAt := out["checked_at"].(string)
	if code, out := h.do("POST", "/v1/check", apiKey, "", map[string]any{
		"resource": "doc:readme", "permission": "view", "subject": "user:bob"}); code != 200 || out["allowed"] != false {
		t.Fatalf("denied check: %d %v", code, out)
	}
	code, out = h.do("POST", "/v1/check/bulk", apiKey, "", map[string]any{"items": []map[string]string{
		{"resource": "doc:readme", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:readme", "permission": "no_such_permission", "subject": "user:alice"},
		{"resource": "doc:readme", "permission": "view", "subject": "user:carol"},
	}})
	if code != 200 {
		t.Fatalf("bulk: %d %v", code, out)
	}
	// Refused before any decision: no record.
	if code, _ := h.do("POST", "/v1/check", apiKey, "", map[string]any{"resource": "readme", "permission": "view", "subject": "user:alice"}); code != 400 {
		t.Fatalf("bad check: %d", code)
	}
	if code, _ := h.do("POST", "/v1/check", "wrong-key-0123456789", "", map[string]any{}); code != 401 {
		t.Fatal("unauthenticated check")
	}

	recs := h.records()[before:]
	type want struct {
		subject, action, principal string
		decision                   audit.Decision
		bulk                       int
	}
	wants := []want{
		{"doc:readme", "view", "user:alice", audit.Allow, 0},
		{"doc:readme", "view", "user:bob", audit.Deny, 0},
		{"doc:readme", "view", "user:alice", audit.Allow, 3},
		{"doc:readme", "view", "user:carol", audit.Deny, 3},
	}
	if len(recs) != len(wants) {
		t.Fatalf("%d records after the writes, want %d: %+v", len(recs), len(wants), recs)
	}
	for i, w := range wants {
		r := recs[i]
		var p audit.CheckDecided
		decodePayload(t, r, &p)
		if r.Event != audit.EventCheckDecided || r.Subject != w.subject || r.Action != w.action || r.Decision != w.decision ||
			p.Principal != w.principal || p.Bulk != w.bulk || p.Revision == "" {
			t.Errorf("record %d: %+v %+v, want %+v", i, r.Envelope, p, w)
		}
		if r.CorrelationID == "" {
			t.Errorf("record %d has no correlation ID", i)
		}
	}
	if recs[0].CorrelationID != "4bf92f3577b34da6a3ce929d0e0e4736" || recs[0].Actor != KeyID(secondKey) || recs[0].Actor == recs[1].Actor {
		t.Errorf("first check: correlation %q actor %q", recs[0].CorrelationID, recs[0].Actor)
	}
	var p0 audit.CheckDecided
	decodePayload(t, recs[0], &p0)
	if p0.Revision != checkedAt {
		t.Errorf("revision %q, want the answer's checked_at %q", p0.Revision, checkedAt)
	}
	if recs[2].CorrelationID != recs[3].CorrelationID || recs[2].CorrelationID == recs[1].CorrelationID {
		t.Errorf("bulk records' correlation IDs: %q %q", recs[2].CorrelationID, recs[3].CorrelationID)
	}
	var mb strings.Builder
	h.m.Write(&mb)
	if want := `grantd_audit_records_total{event="authz.check_decided"} 4`; !strings.Contains(mb.String(), want) {
		t.Errorf("metrics lack %s", want)
	}
}

// A decision whose record cannot be written is not given: the client gets
// 503 and may retry, rather than an answer missing from the chain.
func TestAuditCheckFailsClosed(t *testing.T) {
	h := newAuditHarnessWith(t, true)
	if code, _ := h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": schemaSrc}); code != 200 {
		t.Fatal("schema")
	}
	h.log.Close()
	for _, tc := range []struct {
		path string
		body any
	}{
		{"/v1/check", map[string]any{"resource": "doc:readme", "permission": "view", "subject": "user:alice"}},
		{"/v1/check/bulk", map[string]any{"items": []map[string]string{{"resource": "doc:readme", "permission": "view", "subject": "user:alice"}}}},
	} {
		code, out := h.do("POST", tc.path, apiKey, "", tc.body)
		if code != 503 || errCode(out) != "unavailable" || out["allowed"] != nil || out["results"] != nil {
			t.Fatalf("%s with a broken audit log: %d %v", tc.path, code, out)
		}
	}
	if !strings.Contains(h.logs.String(), `"event":"authz.check_decided"`) {
		t.Errorf("failure not logged:\n%s", h.logs.String())
	}
}

// Without AuditChecks a check writes nothing (TestAuditRecords), and
// AuditChecks without a log is refused.
func TestAuditChecksNeedsALog(t *testing.T) {
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	if _, err := New(Config{Store: st, Tokens: tok, APIKeys: []string{apiKey}, AuditChecks: true}); err == nil ||
		!strings.Contains(err.Error(), "AuditChecks needs an audit log") {
		t.Fatalf("New: %v", err)
	}
}

func decodePayload(t *testing.T, r audit.Record, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Data, v); err != nil {
		t.Fatalf("seq %d: %v", r.Seq, err)
	}
}
