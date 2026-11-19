package api

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Lookups, expand and read over caveated and expiring relationships through
// the HTTP API.
func TestCaveatedLookupsOverHTTP(t *testing.T) {
	h := newHarness(t, time.Millisecond)
	h.ok("PUT", "/v1/schema", map[string]string{"schema": caveatSchemaSrc})
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	w := h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]any{
		{"op": "touch", "relationship": "doc:plan#viewer@user:alice",
			"caveat": map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": "10.0.0.0/8"}}},
		{"op": "touch", "relationship": "doc:plan#viewer@user:bob", "expires_at": future.Format(time.RFC3339)},
		{"op": "touch", "relationship": "doc:memo#viewer@user:alice"},
		{"op": "touch", "relationship": "doc:plan#counter@user:carol",
			"caveat": map[string]any{"name": "big", "context": map[string]any{"limit": 9007199254740993}}},
	}})
	fresh := map[string]any{"mode": "at_least_as_fresh", "token": w["written_at"]}

	// lookup/resources: conditional objects come apart from the others,
	// and the field is absent when there are none.
	out := h.ok("POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:alice", "consistency": fresh})
	if !reflect.DeepEqual(out["resource_ids"], []any{"memo"}) ||
		!reflect.DeepEqual(out["conditional"], []any{map[string]any{"id": "plan", "missing": []any{"client_ip"}}}) {
		t.Fatalf("lookup resources: %v", out)
	}
	out = h.ok("POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:alice", "consistency": fresh,
		"context": map[string]any{"client_ip": "10.2.3.4"}})
	if _, has := out["conditional"]; has || !reflect.DeepEqual(out["resource_ids"], []any{"memo", "plan"}) {
		t.Fatalf("lookup resources with a context: %v", out)
	}

	// lookup/subjects: conditional subjects with their missing parameters;
	// big integers in the context reach the caveat exactly.
	out = h.ok("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user", "consistency": fresh})
	want := []any{map[string]any{"subject": "user:alice", "conditional": true, "missing": []any{"client_ip"}}, map[string]any{"subject": "user:bob"}}
	if !reflect.DeepEqual(out["subjects"], want) {
		t.Fatalf("lookup subjects: %v", out)
	}
	for _, c := range []struct {
		n    string
		want []any
	}{
		{"9007199254740993", []any{map[string]any{"subject": "user:carol"}}},
		{"9007199254740994", []any{}},
	} {
		body := `{"resource":"doc:plan","permission":"count","subject_type":"user","context":{"n":` + c.n + `},"consistency":{"mode":"at_least_as_fresh","token":"` + w["written_at"].(string) + `"}}`
		if out := h.ok("POST", "/v1/lookup/subjects", body); !reflect.DeepEqual(out["subjects"], c.want) {
			t.Fatalf("count with n=%s: %v", c.n, out)
		}
	}
	// A caveat that fails at run time is a 400.
	code, out := h.call("POST", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user", "consistency": fresh,
		"context": map[string]any{"client_ip": 12}})
	if code != 400 || errCode(out) != "invalid_argument" {
		t.Fatalf("failing caveat: %d %v", code, out)
	}

	// expand: each caveated subject names its caveat and stored context.
	out = h.ok("POST", "/v1/expand", map[string]any{"resource": "doc:plan", "permission": "viewer", "consistency": fresh})
	kids := out["tree"].(map[string]any)["children"].([]any)
	if len(kids) != 2 || !reflect.DeepEqual(kids[0].(map[string]any)["caveat"], map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": "10.0.0.0/8"}}) ||
		kids[1].(map[string]any)["caveat"] != nil {
		t.Fatalf("expand: %v", out)
	}

	// read: the caveats and expiries of the page, keyed by relationship.
	out = h.ok("POST", "/v1/relationships/read", map[string]any{"filter": map[string]any{"resource_type": "doc", "resource_id": "plan"}, "consistency": fresh})
	if !reflect.DeepEqual(out["relationships"], []any{"doc:plan#counter@user:carol", "doc:plan#viewer@user:alice", "doc:plan#viewer@user:bob"}) {
		t.Fatalf("read: %v", out)
	}
	if !reflect.DeepEqual(out["caveats"], map[string]any{
		"doc:plan#counter@user:carol": map[string]any{"name": "big", "context": map[string]any{"limit": 9007199254740993.0}},
		"doc:plan#viewer@user:alice":  map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": "10.0.0.0/8"}},
	}) || !reflect.DeepEqual(out["expires_at"], map[string]any{"doc:plan#viewer@user:bob": future.Format(time.RFC3339)}) {
		t.Fatalf("read caveats and expiry: %v", out)
	}
	tok := `,"consistency":{"mode":"at_least_as_fresh","token":"` + w["written_at"].(string) + `"}}`
	raw := h.raw("/v1/relationships/read", `{"filter":{"resource_type":"doc","resource_id":"plan","relation":"counter"}`+tok)
	if !strings.Contains(raw, `"context":{"limit":9007199254740993}`) || strings.Contains(raw, "expires_at") {
		t.Fatalf("read lost digits of the stored context, or reported an expiry: %s", raw)
	}
	// A page with neither has neither field, as before caveats.
	if raw := h.raw("/v1/relationships/read", `{"filter":{"resource_type":"doc","resource_id":"memo"}`+tok); strings.Contains(raw, "caveats") || strings.Contains(raw, "expires_at") {
		t.Fatalf("plain read: %s", raw)
	}
}
