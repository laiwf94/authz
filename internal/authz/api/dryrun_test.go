package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// PUT /v1/schema?dry_run=true reports the changes, the affected
// permissions and the relationships a schema would break, and writes and
// audits nothing.
func TestSchemaDryRun(t *testing.T) {
	h := newHarness(t, 0)
	written := h.setup()
	before := h.st.Head()

	// Maps come back with sorted keys. The viewer relation loses its group usersets, owner becomes a
	// permission, and doc gains an editor.
	next := `
definition user {}
definition group { relation member: user | group#member }
definition doc {
  relation editor: user
  permission owner = editor
  relation viewer: user
  relation banned: user
  permission view = (viewer + owner) - banned
}`
	out := h.ok("PUT", "/v1/schema?dry_run=true", map[string]any{"schema": next})
	if out["dry_run"] != true || out["valid"] != false || out["breaking_count"] != 2.0 {
		t.Fatalf("dry run: %v", out)
	}
	if got, _ := json.Marshal(out["breaking_relationships"]); string(got) != `[`+
		`{"reason":"doc#owner is a permission; relationships can only be written to relations","relationship":"doc:plan#owner@user:olga"},`+
		`{"reason":"doc#viewer does not allow group#member (allowed: user)","relationship":"doc:plan#viewer@group:eng#member"}]` {
		t.Fatalf("breaking: %s", got)
	}
	if got, _ := json.Marshal(out["changes"]); strings.ReplaceAll(string(got), `\u003e`, ">") != `[`+
		`{"kind":"added","name":"doc#editor","object":"relation"},`+
		`{"detail":"relation -> permission","kind":"changed","name":"doc#owner","object":"permission"},`+
		`{"detail":"group#member | user -> user","kind":"changed","name":"doc#viewer","object":"relation"}]` {
		t.Fatalf("changes: %s", got)
	}
	if got, _ := json.Marshal(out["affected_permissions"]); string(got) != `["doc#view"]` {
		t.Fatalf("affected: %s", got)
	}
	if !strings.HasPrefix(out["schema"].(string), "definition user {}\n\ndefinition group {") {
		t.Fatalf("schema: %q", out["schema"])
	}
	if out["checked_at"] != written {
		t.Fatalf("checked_at %v, want the last write's token %s", out["checked_at"], written)
	}

	// limit lists fewer but counts all of them.
	out = h.ok("PUT", "/v1/schema?dry_run=1&limit=1", map[string]any{"schema": next})
	if l := out["breaking_relationships"].([]any); len(l) != 1 || out["breaking_count"] != 2.0 {
		t.Fatalf("limit 1: %v", out)
	}

	// A schema that breaks nothing is valid, and an unchanged one has no
	// changes.
	out = h.ok("PUT", "/v1/schema?dry_run=true", map[string]any{"schema": schemaSrc})
	if out["valid"] != true || out["breaking_count"] != 0.0 {
		t.Fatalf("same schema: %v", out)
	}
	if got, _ := json.Marshal([]any{out["changes"], out["affected_permissions"], out["breaking_relationships"]}); string(got) != `[[],[],[]]` {
		t.Fatalf("same schema lists: %s", got)
	}

	for _, c := range []struct {
		name, path string
		body       any
		code       int
		err        string
	}{
		{"bad dry_run", "/v1/schema?dry_run=maybe", map[string]any{"schema": next}, 400, "invalid_argument"},
		{"limit without dry_run", "/v1/schema?limit=5", map[string]any{"schema": next}, 400, "invalid_argument"},
		{"limit 0", "/v1/schema?dry_run=true&limit=0", map[string]any{"schema": next}, 400, "invalid_argument"},
		{"limit too big", "/v1/schema?dry_run=true&limit=1001", map[string]any{"schema": next}, 400, "invalid_argument"},
		{"limit not a number", "/v1/schema?dry_run=true&limit=x", map[string]any{"schema": next}, 400, "invalid_argument"},
		{"does not parse", "/v1/schema?dry_run=true", map[string]any{"schema": "definition doc {"}, 400, "invalid_argument"},
		{"empty", "/v1/schema?dry_run=true", map[string]any{"schema": " "}, 400, "invalid_argument"},
		{"unknown field", "/v1/schema?dry_run=true", map[string]any{"schema": next, "limit": 1}, 400, "invalid_argument"},
		{"the write it previews", "/v1/schema", map[string]any{"schema": next}, 412, "failed_precondition"},
	} {
		if code, out := h.call("PUT", c.path, c.body); code != c.code || errCode(out) != c.err {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if code, out, _ := h.do("PUT", "/v1/schema?dry_run=true", map[string]any{"schema": next}, ""); code != 401 {
		t.Errorf("no key: %d %v", code, out)
	}
	if h.st.Head() != before {
		t.Fatalf("dry runs moved the head from %d to %d", before, h.st.Head())
	}
	if _, src := h.st.Schema(); strings.Contains(src, "editor") {
		t.Fatalf("a dry run wrote the schema:\n%s", src)
	}

	// dry_run=false is an ordinary write.
	if out := h.ok("PUT", "/v1/schema?dry_run=false", map[string]any{"schema": schemaSrc + "\ndefinition team {}"}); out["written_at"] == nil {
		t.Fatalf("dry_run=false: %v", out)
	}
}

// Before any schema is written a dry run adds every definition.
func TestSchemaDryRunFirstSchema(t *testing.T) {
	h := newHarness(t, 0)
	out := h.ok("PUT", "/v1/schema?dry_run=true", map[string]any{"schema": schemaSrc})
	if got, _ := json.Marshal(out["changes"]); out["valid"] != true || string(got) != `[`+
		`{"kind":"added","name":"user","object":"definition"},`+
		`{"kind":"added","name":"group","object":"definition"},`+
		`{"kind":"added","name":"doc","object":"definition"}]` {
		t.Fatalf("first schema: %s %v", got, out)
	}
	if code, out := h.call("GET", "/v1/schema", nil); code == 200 && out["schema"] != "" {
		t.Fatalf("a dry run wrote the first schema: %d %v", code, out)
	}
}

// A dry run is not audited: it changes nothing.
func TestSchemaDryRunIsNotAudited(t *testing.T) {
	h := newAuditHarness(t)
	if code, out := h.do("PUT", "/v1/schema", apiKey, "", map[string]any{"schema": schemaSrc}); code != 200 {
		t.Fatalf("write: %d %v", code, out)
	}
	n := len(h.records())
	if code, out := h.do("PUT", "/v1/schema?dry_run=true", apiKey, "", map[string]any{"schema": schemaSrc + "\ndefinition team {}"}); code != 200 {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if got := len(h.records()); got != n {
		t.Fatalf("a dry run added %d audit records", got-n)
	}
}
