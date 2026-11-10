//go:build unix

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// rotatedLog writes a log of several segments and returns its path, head and
// segment paths.
func rotatedLog(t *testing.T) (string, uint64, string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.OpenWith(path, audit.Options{Schemas: audit.Default(), Rotation: audit.Rotation{MaxBytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		if err := l.Write(audit.Envelope{}, audit.ToolCall{Agent: "bot", Auth: "key", Decision: "allow", Stage: "policy", Tool: fmt.Sprint("t", i)}); err != nil {
			t.Fatal(err)
		}
	}
	seq, head := l.Head()
	l.Close()
	segs, err := audit.Segments(path)
	if err != nil || len(segs) < 3 {
		t.Fatalf("segments %v %v", segs, err)
	}
	return path, seq, head, segs
}

func verifyCmd(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"audit", "verify"}, args...), func(string) string { return "" }, nil, &out, &errb)
	return code, out.String(), errb.String()
}

// audit verify follows a rotated log across its segments and names the one
// that was removed.
func TestAuditVerifySegments(t *testing.T) {
	path, seq, head, segs := rotatedLog(t)
	code, out, _ := verifyCmd(path)
	want := fmt.Sprintf("OK %s: %d records in %d segments, head %s\n", path, seq, len(segs)+1, head)
	if code != 0 || out != want {
		t.Fatalf("exit %d %q, want %q", code, out, want)
	}
	if code, out, _ := verifyCmd("-head", head, path); code != 0 || out != want {
		t.Fatalf("-head: exit %d %q", code, out)
	}
	if code, out, _ := verifyCmd("-head", audit.Genesis, path); code != 1 || !strings.Contains(out, "not the expected head") {
		t.Fatalf("wrong -head: exit %d %q", code, out)
	}

	if err := os.Remove(segs[1]); err != nil {
		t.Fatal(err)
	}
	code, out, _ = verifyCmd(path)
	if code != 1 || !strings.HasPrefix(out, "FAIL "+path+": "+segs[2]+": records ") ||
		!strings.Contains(out, "a segment ("+filepath.Base(segs[1])+") was removed") {
		t.Fatalf("middle segment removed: exit %d %q", code, out)
	}

	// The active file alone, its earlier segments gone: the FAIL line names
	// it once.
	for _, s := range segs {
		os.Remove(s)
	}
	code, out, _ = verifyCmd(path)
	if code != 1 || !strings.HasPrefix(out, "FAIL "+path+": the oldest segment starts at record") {
		t.Fatalf("earlier segments removed: exit %d %q", code, out)
	}

	// The active file removed, segments left: a failed verification.
	path, _, _, _ = rotatedLog(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := verifyCmd(path); code != 1 || !strings.Contains(out, "the active segment is missing") {
		t.Fatalf("active removed: exit %d %q", code, out)
	}

	// No log at all is unreadable input, as before.
	if code, _, errs := verifyCmd(filepath.Join(t.TempDir(), "none.jsonl")); code != 2 || !strings.Contains(errs, "no such file") {
		t.Fatalf("missing: exit %d %q", code, errs)
	}
}
