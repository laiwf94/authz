package api

import (
	"encoding/json"
	"testing"
)

// POST /v1/expand answers who holds a permission as a userset tree, at the
// snapshot a token names, one level or recursively, within a node limit.
func TestExpand(t *testing.T) {
	h := newHarness(t, 0)
	written := h.setup()
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "doc:plan#viewer@user:bob"},
	}})
	out := h.ok("POST", "/v1/expand", map[string]any{"resource": "doc:plan", "permission": "view",
		"consistency": map[string]string{"mode": "at_exact_snapshot", "token": written}})
	if out["expanded_at"] != written || out["truncated"] != false || out["nodes"] != float64(8) {
		t.Fatalf("expand at the setup token: %v", out)
	}
	// The viewer written after the token is not in the tree; usersets are
	// leaves without "recursive".
	got, _ := json.Marshal(out["tree"])
	want := `{"children":[{"children":[{"children":[{"children":[{"kind":"subject","object":"doc:plan","relation":"viewer","subject":"group:eng#member"}],"kind":"relation","object":"doc:plan","relation":"viewer"},` +
		`{"children":[{"kind":"subject","object":"doc:plan","relation":"owner","subject":"user:olga"}],"kind":"relation","object":"doc:plan","relation":"owner"}],"expr":"viewer + owner","kind":"union","object":"doc:plan"},` +
		`{"kind":"relation","object":"doc:plan","relation":"banned"}],"expr":"viewer + owner - banned","kind":"exclusion","object":"doc:plan"}],"kind":"permission","object":"doc:plan","relation":"view"}`
	if string(got) != want {
		t.Fatalf("tree\n%s\nwant\n%s", got, want)
	}

	out = h.ok("POST", "/v1/expand", map[string]any{"resource": "doc:plan", "permission": "viewer", "recursive": true,
		"consistency": map[string]string{"mode": "fully_consistent"}})
	got, _ = json.Marshal(out["tree"])
	want = `{"children":[{"children":[{"kind":"subject","object":"group:eng","relation":"member","subject":"user:alice"}],"kind":"relation","object":"group:eng","relation":"member"},` +
		`{"kind":"subject","object":"doc:plan","relation":"viewer","subject":"user:bob"}],"kind":"relation","object":"doc:plan","relation":"viewer"}`
	if string(got) != want || out["expanded_at"] == written {
		t.Fatalf("recursive tree\n%s\nwant\n%s", got, want)
	}

	out = h.ok("POST", "/v1/expand", map[string]any{"resource": "doc:plan", "permission": "view", "max_nodes": 2})
	tree, _ := out["tree"].(map[string]any)
	if out["truncated"] != true || out["nodes"] != float64(2) || tree["children"] == nil {
		t.Fatalf("limited expand: %v", out)
	}

	for _, c := range []struct {
		name string
		body any
		code int
		err  string
	}{
		{"resource", map[string]any{"resource": "doc", "permission": "view"}, 400, "invalid_argument"},
		{"type", map[string]any{"resource": "ghost:a", "permission": "view"}, 400, "invalid_argument"},
		{"permission", map[string]any{"resource": "doc:a", "permission": "nope"}, 400, "invalid_argument"},
		{"max_nodes", map[string]any{"resource": "doc:a", "permission": "view", "max_nodes": -1}, 400, "invalid_argument"},
		{"consistency", map[string]any{"resource": "doc:a", "permission": "view", "consistency": map[string]string{"mode": "at_least_as_fresh"}}, 400, "invalid_argument"},
		{"unknown field", map[string]any{"resource": "doc:a", "permission": "view", "depth": 3}, 400, "invalid_argument"},
	} {
		if code, out := h.call("POST", "/v1/expand", c.body); code != c.code || errCode(out) != c.err {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if code, out, _ := h.do("POST", "/v1/expand", map[string]any{"resource": "doc:a", "permission": "view"}, ""); code != 401 {
		t.Errorf("no key: %d %v", code, out)
	}
}

func TestExpandWithoutSchema(t *testing.T) {
	h := newHarness(t, 0)
	if code, out := h.call("POST", "/v1/expand", map[string]any{"resource": "doc:a", "permission": "view"}); code != 424 || errCode(out) != "no_schema" {
		t.Fatalf("expand before a schema: %d %v", code, out)
	}
}
