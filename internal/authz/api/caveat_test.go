package api

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

const caveatSchemaSrc = `
caveat ip_allowed(allowed cidr, client_ip ipaddress) { allowed.containsIP(client_ip) }
caveat big(limit int, n int) { n <= limit }
definition user {}
definition doc {
  relation viewer: user | user with ip_allowed
  relation counter: user with big
  permission view = viewer
  permission count = counter
}`

// Caveats and expiry through the HTTP API: writes carry a caveat with its
// stored context and an expires_at, checks carry a context, and an answer
// that depends on parameters nobody supplied is conditional with their
// names.
func TestCaveatsOverHTTP(t *testing.T) {
	h := newHarness(t, time.Millisecond)
	h.ok("PUT", "/v1/schema", map[string]string{"schema": caveatSchemaSrc})
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	w := h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]any{
		{"op": "touch", "relationship": "doc:plan#viewer@user:alice",
			"caveat": map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": "10.0.0.0/8"}}},
		{"op": "touch", "relationship": "doc:plan#viewer@user:bob", "expires_at": future},
		{"op": "touch", "relationship": "doc:plan#viewer@user:old", "expires_at": "2020-01-01T00:00:00Z"},
		// 2^53+1 is not a float64: it must reach the caveat exactly.
		{"op": "touch", "relationship": "doc:plan#counter@user:carol",
			"caveat": map[string]any{"name": "big", "context": map[string]any{"limit": 9007199254740993}}},
	}})
	fresh := map[string]any{"mode": "at_least_as_fresh", "token": w["written_at"]}

	check := func(subject, perm, ctx string) map[string]any {
		t.Helper()
		body := `{"resource":"doc:plan","permission":"` + perm + `","subject":"` + subject + `","consistency":{"mode":"at_least_as_fresh","token":"` + w["written_at"].(string) + `"}`
		if ctx != "" {
			body += `,"context":` + ctx
		}
		return h.ok("POST", "/v1/check", body+"}")
	}
	for _, c := range []struct {
		subject, perm, ctx string
		want               map[string]any
	}{
		{"user:alice", "view", "", map[string]any{"allowed": false, "conditional": true, "missing": []any{"client_ip"}}},
		{"user:alice", "view", `{"client_ip":"10.9.9.9"}`, map[string]any{"allowed": true}},
		{"user:alice", "view", `{"client_ip":"11.0.0.1"}`, map[string]any{"allowed": false}},
		{"user:alice", "view", `null`, map[string]any{"allowed": false, "conditional": true, "missing": []any{"client_ip"}}},
		{"user:bob", "view", "", map[string]any{"allowed": true}},
		{"user:old", "view", "", map[string]any{"allowed": false}},
		{"user:carol", "count", `{"n":9007199254740993}`, map[string]any{"allowed": true}},
		{"user:carol", "count", `{"n":9007199254740994}`, map[string]any{"allowed": false}},
	} {
		out := check(c.subject, c.perm, c.ctx)
		if out["checked_at"] == nil {
			t.Errorf("%s %s: no checked_at in %v", c.subject, c.ctx, out)
		}
		delete(out, "checked_at")
		if !reflect.DeepEqual(out, c.want) {
			t.Errorf("%s %s %s: %v, want %v", c.subject, c.perm, c.ctx, out, c.want)
		}
	}

	// Bulk: each item with its own context, at one snapshot.
	out := h.ok("POST", "/v1/check/bulk", map[string]any{"consistency": fresh, "items": []map[string]any{
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice", "context": map[string]any{"client_ip": "10.0.0.1"}},
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice", "context": map[string]any{"client_ip": 12}},
		{"resource": "doc:plan", "permission": "view", "subject": "user:bob"},
	}})
	res := out["results"].([]any)
	wants := []map[string]any{
		{"allowed": true},
		{"allowed": false, "conditional": true, "missing": []any{"client_ip"}},
		nil, // an error, checked below
		{"allowed": true},
	}
	for i, wnt := range wants {
		got := res[i].(map[string]any)
		if wnt == nil {
			if e, _ := got["error"].(string); !strings.Contains(e, "caveat evaluation failed") || got["allowed"] != false || got["conditional"] != nil {
				t.Errorf("item %d: %v, want a caveat error", i, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, wnt) {
			t.Errorf("item %d: %v, want %v", i, got, wnt)
		}
	}

	// Watch shows the caveat and expiry each touch set.
	wt := h.ok("POST", "/v1/watch", map[string]any{"after": h.api.tokens.Encode(1)})
	changes := wt["changes"].([]any)
	byRel := map[string]map[string]any{}
	for _, c := range changes {
		m := c.(map[string]any)
		byRel[m["relationship"].(string)] = m
	}
	if c := byRel["doc:plan#viewer@user:alice"]["caveat"]; !reflect.DeepEqual(c, map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": "10.0.0.0/8"}}) {
		t.Errorf("watch caveat: %v", c)
	}
	if e := byRel["doc:plan#viewer@user:bob"]["expires_at"]; e != future {
		t.Errorf("watch expires_at %v, want %s", e, future)
	}
	if c := byRel["doc:plan#viewer@user:bob"]; c["caveat"] != nil {
		t.Errorf("watch: caveat on a plain relationship: %v", c)
	}
	if raw := h.raw("/v1/watch", `{"after":"`+h.api.tokens.Encode(1)+`"}`); !strings.Contains(raw, `"context":{"limit":9007199254740993}`) {
		t.Errorf("watch lost digits of the stored context: %s", raw)
	}
}

func TestCaveatRequestErrors(t *testing.T) {
	h := newHarness(t, time.Millisecond)
	h.ok("PUT", "/v1/schema", map[string]string{"schema": caveatSchemaSrc})
	for _, c := range []struct {
		name, path string
		body       any
		code       int
		msg        string
	}{
		{"context not an object", "/v1/check", `{"resource":"doc:plan","permission":"view","subject":"user:alice","context":[1]}`, 400, "context must be a JSON object"},
		{"context too large", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice",
			"context": map[string]any{"pad": strings.Repeat("x", 17<<10)}}, 400, "context is"},
		{"unknown caveat", "/v1/relationships/write", map[string]any{"updates": []map[string]any{{"op": "touch",
			"relationship": "doc:plan#viewer@user:alice", "caveat": map[string]any{"name": "nope"}}}}, 400, "nope"},
		{"unknown field in caveat", "/v1/relationships/write", map[string]any{"updates": []map[string]any{{"op": "touch",
			"relationship": "doc:plan#viewer@user:alice", "caveat": map[string]any{"name": "ip_allowed", "contxt": map[string]any{}}}}}, 400, "contxt"},
		{"plain write to a caveat-only relation", "/v1/relationships/write", map[string]any{"updates": []map[string]any{{"op": "touch",
			"relationship": "doc:plan#counter@user:alice"}}}, 400, "counter"},
		{"bad stored context", "/v1/relationships/write", map[string]any{"updates": []map[string]any{{"op": "touch",
			"relationship": "doc:plan#viewer@user:alice", "caveat": map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": 5}}}}}, 400, "allowed"},
		{"bad expires_at", "/v1/relationships/write", `{"updates":[{"op":"touch","relationship":"doc:plan#viewer@user:alice","expires_at":"tomorrow"}]}`, 400, "invalid JSON body"},
		{"lookup resources context not an object", "/v1/lookup/resources", `{"resource_type":"doc","permission":"view","subject":"user:alice","context":"x"}`, 400, "context must be a JSON object"},
		{"lookup subjects context too large", "/v1/lookup/subjects", map[string]any{"resource": "doc:plan", "permission": "view", "subject_type": "user",
			"context": map[string]any{"pad": strings.Repeat("x", 17<<10)}}, 400, "context is"},
	} {
		code, out := h.call("POST", c.path, c.body)
		if code != c.code {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.code)
			continue
		}
		if c.code == 400 {
			e, _ := out["error"].(map[string]any)
			if msg, _ := e["message"].(string); errCode(out) != "invalid_argument" || !strings.Contains(msg, c.msg) {
				t.Errorf("%s: %v, want invalid_argument mentioning %q", c.name, out, c.msg)
			}
		}
	}

	// A caveat whose evaluation fails is a 400 for the check that hit it.
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]any{{"op": "touch",
		"relationship": "doc:plan#counter@user:carol", "caveat": map[string]any{"name": "big", "context": map[string]any{"limit": 3}}}}})
	code, out := h.call("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "count", "subject": "user:carol",
		"context": map[string]any{"n": "seven"}, "consistency": map[string]any{"mode": "fully_consistent"}})
	if e, _ := out["error"].(map[string]any); code != 400 || errCode(out) != "invalid_argument" || !strings.Contains(e["message"].(string), "caveat evaluation failed") {
		t.Fatalf("failing caveat: %d %v", code, out)
	}
}

// A conditional answer grants nothing: it is recorded as a deny, marked
// conditional with the parameters it was missing.
func TestAuditConditionalDecision(t *testing.T) {
	h := newAuditHarnessWith(t, true)
	if code, out := h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": caveatSchemaSrc}); code != 200 {
		t.Fatalf("schema: %d %v", code, out)
	}
	if code, out := h.do("POST", "/v1/relationships/write", apiKey, "", map[string]any{"updates": []map[string]any{{"op": "touch",
		"relationship": "doc:plan#viewer@user:alice", "caveat": map[string]any{"name": "ip_allowed", "context": map[string]any{"allowed": "10.0.0.0/8"}}}}}); code != 200 {
		t.Fatalf("write: %d %v", code, out)
	}
	before := len(h.records())
	cons := map[string]any{"mode": "fully_consistent"}
	if code, out := h.do("POST", "/v1/check", apiKey, "", map[string]any{"resource": "doc:plan", "permission": "view",
		"subject": "user:alice", "consistency": cons}); code != 200 || out["conditional"] != true {
		t.Fatalf("check: %d %v", code, out)
	}
	if code, out := h.do("POST", "/v1/check/bulk", apiKey, "", map[string]any{"consistency": cons, "items": []map[string]any{
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice", "context": map[string]any{"client_ip": "10.0.0.1"}},
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice"},
	}}); code != 200 {
		t.Fatalf("bulk: %d %v", code, out)
	}
	recs := h.records()[before:]
	type want struct {
		decision    audit.Decision
		conditional bool
		missing     []string
		bulk        int
	}
	wants := []want{{audit.Deny, true, []string{"client_ip"}, 0}, {audit.Allow, false, nil, 2}, {audit.Deny, true, []string{"client_ip"}, 2}}
	if len(recs) != len(wants) {
		t.Fatalf("%d records, want %d", len(recs), len(wants))
	}
	for i, w := range wants {
		var p audit.CheckDecided
		decodePayload(t, recs[i], &p)
		if recs[i].Decision != w.decision || p.Conditional != w.conditional || !reflect.DeepEqual(p.Missing, w.missing) || p.Bulk != w.bulk {
			t.Errorf("record %d: %s %+v, want %+v", i, recs[i].Decision, p, w)
		}
	}
	// A decided check's record has no conditional fields at all.
	if s := string(recs[1].Data); strings.Contains(s, "conditional") || strings.Contains(s, "missing") {
		t.Errorf("allow record carries conditional fields: %s", s)
	}
}

// raw posts body to path and returns the response body as sent.
func (h *harness) raw(path, body string) string {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		h.t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
	}
	return string(b)
}
