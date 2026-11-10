package checkcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sections that write one audit file must rotate it alike; each subcommand
// would refuse to open the file once another had rotated it under other
// limits, so the check refuses the file first.
func TestConfigSharedAuditRotation(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "audit.jsonl")
	doc := func(serveRot, mcpRot map[string]any, mcpLog string) string {
		var m map[string]any
		src, err := os.ReadFile(platformDoc(t, "https://idp.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(src, &m)
		sv := m["serve"].(map[string]any)
		sv["audit_log"] = shared
		for k, v := range serveRot {
			sv[k] = v
		}
		mc := m["mcp"].(map[string]any)
		mc["audit_log"] = mcpLog
		for k, v := range mcpRot {
			mc[k] = v
		}
		b, _ := json.Marshal(m)
		return write(t, "authz.json", string(b))
	}
	same := map[string]any{"audit_rotate_bytes": 1 << 20, "audit_rotate_age": "24h"}
	// The same limits, or another file, pass.
	for _, f := range []string{
		doc(same, same, shared),
		doc(same, same, filepath.Join(dir, ".", "audit.jsonl")),
		doc(same, nil, filepath.Join(dir, "mcp-audit.jsonl")),
		doc(nil, nil, shared),
	} {
		if code, out := runProcess(t, goodEnv(), "-config", f); code != OK || !strings.Contains(out, "config is valid") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	}
	for _, tc := range []struct {
		mcpRot map[string]any
		want   string
	}{
		{nil, "max_bytes=1048576 max_age=24h0m0s, no rotation"},
		{map[string]any{"audit_rotate_bytes": 1 << 20}, "max_bytes=1048576 max_age=24h0m0s, max_bytes=1048576"},
		{map[string]any{"audit_rotate_bytes": 2 << 20, "audit_rotate_age": "24h"}, "max_bytes=2097152 max_age=24h0m0s"},
	} {
		f := doc(same, tc.mcpRot, filepath.Join(dir, "x", "..", "audit.jsonl"))
		code, out := runProcess(t, goodEnv(), "-config", f)
		want := f + ": error: $.mcp.audit_rotate_bytes, $.mcp.audit_rotate_age: serve and mcp write the audit log " + shared + " with different rotation limits ("
		if code != Problems || !strings.Contains(out, want) || !strings.Contains(out, tc.want) || strings.Contains(out, "config is valid") {
			t.Errorf("%v: exit %d:\n%s", tc.mcpRot, code, out)
		}
	}
}
