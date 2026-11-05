package gateway

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// TestAuditRecordsMatchSchemas drives every kind of record the gateway
// writes (allowed, denied, refused and guarded calls, an approval asked for
// and decided, a quarantine and its approval, policy reloads applied and
// rejected) and requires the log to verify against the platform's payload
// schemas, so internal/platform/audit's agents schemas describe what the
// gateway actually writes.
func TestAuditRecordsMatchSchemas(t *testing.T) {
	e := newEnv(t, noToolLimit)
	e.call(aliceKey, "fake.echo", map[string]any{"text": "hi"})
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/creds.txt"})
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/big.txt"})
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "secrets/.env"})
	e.call(bobKey, "fake.read_file", map[string]any{"path": "notes/a.md"})
	e.call(aliceKey, "nosuch.tool", nil)
	e.call(aliceKey, "fake.http_get", map[string]any{"url": "https://evil.example.net/"})

	args := map[string]any{"text": "hello", "language": "de"}
	r := e.call(aliceKey, "fake.translate", args, lang("de"))
	if r.errCode() != mcp.CodeApprovalPending {
		t.Fatalf("want pending: %s", r.raw)
	}
	id := r.errData()["approval_id"].(string)
	if r := e.admin("POST", "/admin/approvals/"+id+"/approve", `{"ttl_seconds":120,"note":"ok"}`); r.status != 200 {
		t.Fatalf("approve: %s", r.raw)
	}
	e.call(aliceKey, "fake.translate", args, lang("de"))

	e.fake.SetRugPull(true)
	e.clk.add(31 * time.Second)
	e.rpc(aliceKey, "tools/list", nil, nil)
	if r := e.call(aliceKey, "fake.translate", args, lang("de")); r.errCode() != mcp.CodeToolQuarantined {
		t.Fatalf("quarantine: %s", r.raw)
	}
	var view struct {
		Tools []struct {
			Tool        string
			PendingHash string `json:"pending_hash"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(e.admin("GET", "/admin/tools", "").raw), &view); err != nil {
		t.Fatal(err)
	}
	pending := ""
	for _, tv := range view.Tools {
		if tv.Tool == "fake.translate" {
			pending = tv.PendingHash
		}
	}
	if r := e.admin("POST", "/admin/tools/fake.translate/approve", `{"hash":"`+pending+`"}`); r.status != 200 {
		t.Fatalf("approve tool: %s", r.raw)
	}

	writePolicy(t, e, `{"version":1,"rules":[{"id":"bob-files","effect":"allow","agents":["bob-bot"],"upstreams":["fake"],"tools":["read_file"]}]}`)
	if err := os.WriteFile(e.policyPath, []byte(`{"version":1,"rules":[{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.admin("POST", "/admin/policy/reload", "")

	seen := map[string]int{}
	for _, rec := range e.auditRecords() {
		seen[rec.Event]++
	}
	for _, ev := range []string{audit.EventToolCall, audit.EventApprovalRequested, audit.EventApprovalDecided,
		audit.EventToolQuarantined, audit.EventToolApproved, audit.EventPolicyApplied, audit.EventPolicyRejected} {
		if seen[ev] == 0 {
			t.Errorf("no %s record was written: %v", ev, seen)
		}
	}
	f, err := os.Open(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := audit.VerifyWith(f, audit.Default()); err != nil {
		t.Fatalf("gateway records do not match the schemas: %v", err)
	}
}
