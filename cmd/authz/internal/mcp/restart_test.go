package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// chainContinues reports whether the audit chain at head2 carries on from
// head1: the same head, or a longer chain whose first record after head1
// links to it. A restarted gateway can write records before the test reads
// its head, such as tool_quarantined when startup discovery finds a changed
// tool (#247), and those still continue the chain.
func chainContinues(t *testing.T, s *setup, head1, head2 map[string]any) bool {
	t.Helper()
	if head2["head"] == head1["head"] {
		return true
	}
	n1, ok1 := head1["records"].(float64)
	n2, ok2 := head2["records"].(float64)
	if !ok1 || !ok2 || n2 <= n1 {
		return false
	}
	f, err := os.Open(s.env["TOOLGATE_AUDIT_LOG"])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var rec struct {
			Seq  int64  `json:"seq"`
			Prev string `json:"prev"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("audit record: %v", err)
		}
		if rec.Seq == int64(n1)+1 {
			return rec.Prev == fmt.Sprint(head1["head"])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}
