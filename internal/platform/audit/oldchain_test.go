package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
)

// The fixture was written by the toolgate binary before the move to
// internal/agents; see testdata/README.md.
const (
	oldChain        = "testdata/toolgate-demo.jsonl"
	oldChainRecords = 23
	oldChainHead    = "69506072c64dd3d911c5528e3ff06f5fa3c8ba6f2886a44b1dce138d96f5ba95"
	// The head of the same log without its last record.
	oldChainHead22 = "aba7a64581bef16643b6f3bd3dc4795ec0f4f0912219e4275142ea411c2bd366"
)

func readOldChain(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(oldChain)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOldBinaryChainVerifies(t *testing.T) {
	res, err := Verify(bytes.NewReader(readOldChain(t)))
	if err != nil {
		t.Fatalf("a chain written by the old binary no longer verifies: %v", err)
	}
	if res.Records != oldChainRecords || res.Head != oldChainHead || res.TornBytes != 0 {
		t.Fatalf("verify: %+v", res)
	}
	if int(res.Size) != len(readOldChain(t)) {
		t.Fatalf("verified %d of %d bytes", res.Size, len(readOldChain(t)))
	}
}

// TestOldBinaryChainContinues opens the old log the way `authz mcp serve`
// does at start, appends, and checks that the new records extend the old
// chain rather than starting a new one.
func TestOldBinaryChainContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, readOldChain(t), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if seq, head := l.Head(); seq != oldChainRecords || head != oldChainHead {
		t.Fatalf("open: head %d %s", seq, head)
	}
	if err := l.Append("tool_call", map[string]any{"agent": "alice-bot", "decision": "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, readOldChain(t)) {
		t.Fatal("opening the old log changed its bytes")
	}
	all := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var rec Record
	if err := json.Unmarshal([]byte(all[len(all)-1]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Seq != oldChainRecords+1 || rec.Prev != oldChainHead {
		t.Fatalf("new record does not extend the old chain: seq %d prev %s", rec.Seq, rec.Prev)
	}
	if res, err := Verify(bytes.NewReader(data)); err != nil || res.Records != oldChainRecords+1 {
		t.Fatalf("old chain plus new record: %+v %v", res, err)
	}
}

// TestOldBinaryChainTornTail checks the crash case: an old gateway killed
// mid-append leaves part of a line, and the new one cuts it off at start
// and carries on from the last complete record.
func TestOldBinaryChainTornTail(t *testing.T) {
	old := readOldChain(t)
	lines := bytes.SplitAfter(old, []byte("\n"))
	lines = lines[:len(lines)-1] // SplitAfter leaves an empty final element
	last := lines[len(lines)-1]
	torn := append(bytes.Join(lines[:len(lines)-1], nil), last[:len(last)/2]...)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if seq, head := l.Head(); seq != oldChainRecords-1 || head != oldChainHead22 {
		t.Fatalf("open after a torn tail: head %d %s", seq, head)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(old) - len(last); len(data) != want {
		t.Fatalf("torn tail not cut: %d bytes, want %d", len(data), want)
	}
}

// TestOldBinaryRecordFormat re-encodes every old record with the new writer
// and requires the same bytes, so a log that mixes old and new records is
// one format, not two.
func TestOldBinaryRecordFormat(t *testing.T) {
	old := readOldChain(t)
	for i, line := range bytes.Split(bytes.TrimSuffix(old, []byte("\n")), []byte("\n")) {
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if _, err := time.Parse(time.RFC3339Nano, rec.Time); err != nil {
			t.Fatalf("line %d: time %q: %v", i+1, rec.Time, err)
		}
		data, err := jsonrpc.DecodeValue(rec.Data)
		if err != nil {
			t.Fatalf("line %d: data: %v", i+1, err)
		}
		got, err := jsonrpc.Marshal(record{Seq: rec.Seq, Time: rec.Time, Prev: rec.Prev, Event: rec.Event, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, line) {
			t.Fatalf("line %d is encoded differently now:\nold %s\nnew %s", i+1, line, got)
		}
	}
}

// TestOldBinaryChainDamage checks that damage to the old log is found at the
// same line the old binary named (testdata/toolgate-demo-verify.txt).
func TestOldBinaryChainDamage(t *testing.T) {
	old := readOldChain(t)
	tampered := bytes.Replace(old, []byte(`"decision":"deny"`), []byte(`"decision":"allow"`), 1)
	_, err := Verify(bytes.NewReader(tampered))
	var le *LineError
	if !errors.As(err, &le) || le.Line != 3 {
		t.Fatalf("tampered old log: %v", err)
	}
}
