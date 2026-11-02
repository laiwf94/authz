package gateway

import (
	"bytes"
	"os"
	"testing"
)

// TestOldBinaryLogMatchesDemoRecording records the audit log that the
// toolgate binary wrote for the demo before the move (see
// internal/agents/audit/testdata/README.md) and requires the checked-in demo
// recording, which demo.sh compares every `authz mcp` run with.
func TestOldBinaryLogMatchesDemoRecording(t *testing.T) {
	log, err := os.ReadFile("../audit/testdata/toolgate-demo.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../../toolgate/examples/demo_decisions.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := RecordDecisions(bytes.NewReader(log), &got); err != nil {
		t.Fatal(err)
	}
	if diff := DiffDecisions(want, got.Bytes()); diff != "" {
		t.Fatalf("the old binary's demo log no longer records as demo_decisions.jsonl:\n%s", diff)
	}
}
