//go:build unix

package auditcmd

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

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, func(string) string { return "" }, nil, &out, &errb)
	return code, out.String(), errb.String()
}

// writeLog writes n typed records through a log rotating at rot.
func writeLog(t *testing.T, path string, n int, rot audit.Rotation) (uint64, string) {
	t.Helper()
	l, err := audit.OpenWith(path, audit.Options{Schemas: audit.Default(), Rotation: rot})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		var err error
		switch i % 3 {
		case 0:
			err = l.Write(audit.Envelope{}, audit.ToolCall{Agent: "bot", Auth: "key", Decision: "allow", Stage: "policy", Tool: fmt.Sprint("t", i)})
		case 1:
			err = l.Write(audit.Envelope{Subject: "doc:1", Action: "view", Decision: audit.Allow},
				audit.CheckDecided{Principal: "user:alice", Revision: "r1"})
		default:
			err = l.Write(audit.Envelope{Subject: "x.example", Action: "access", Decision: audit.Deny},
				audit.AccessDenied{Reason: "unknown_app", Host: "x.example"})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	seq, head := l.Head()
	l.Close()
	return seq, head
}

func TestUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		err  string
	}{
		{nil, Usage, "usage: authz audit verify"},
		{[]string{"-h"}, OK, "usage: authz audit verify"},
		{[]string{"-x"}, Usage, "flag provided but not defined"},
		{[]string{"nope"}, Usage, `unknown command "nope"`},
		{[]string{"verify"}, Usage, "usage: authz audit verify [-head HASH] [-key KEY [-checkpoint NOTE]] FILE"},
		{[]string{"verify", "a", "b"}, Usage, "usage: authz audit verify [-head HASH] [-key KEY [-checkpoint NOTE]] FILE"},
		{[]string{"verify", "-h"}, OK, "-head HASH"},
		{[]string{"verify", "-x", "f"}, Usage, "flag provided but not defined"},
	} {
		code, out, errs := run(tc.args...)
		if code != tc.code || out != "" || !strings.Contains(errs, tc.err) {
			t.Errorf("%q: exit %d, out %q, err %q; want exit %d and %q", tc.args, code, out, errs, tc.code, tc.err)
		}
	}
}

func TestVerifyOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	seq, head := writeLog(t, path, 9, audit.Rotation{})
	want := fmt.Sprintf("OK %s: %d records, head %s\n", path, seq, head)
	if code, out, _ := run("verify", path); code != OK || out != want {
		t.Fatalf("exit %d %q, want %q", code, out, want)
	}
	if code, out, _ := run("verify", "-head", head, path); code != OK || out != want {
		t.Fatalf("-head: exit %d %q", code, out)
	}
	if code, out, _ := run("verify", "-head", audit.Genesis, path); code != Failed || !strings.Contains(out, "not the expected head") {
		t.Fatalf("wrong -head: exit %d %q", code, out)
	}
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	os.WriteFile(empty, nil, 0o600)
	if code, out, _ := run("verify", empty); code != OK || out != fmt.Sprintf("OK %s: 0 records, head %s\n", empty, audit.Genesis) {
		t.Fatalf("empty: exit %d %q", code, out)
	}
	if code, _, errs := run("verify", filepath.Join(t.TempDir(), "none.jsonl")); code != Usage || !strings.Contains(errs, "authz: open") {
		t.Fatalf("missing: exit %d %q", code, errs)
	}
}

// The platform's check reads every segment as one chain and names the one
// that was removed.
func TestVerifySegments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	seq, head := writeLog(t, path, 60, audit.Rotation{MaxBytes: audit.MinRotateBytes})
	segs, err := audit.Segments(path)
	if err != nil || len(segs) < 3 {
		t.Fatalf("segments %v %v", segs, err)
	}
	want := fmt.Sprintf("OK %s: %d records in %d segments, head %s\n", path, seq, len(segs)+1, head)
	if code, out, _ := run("verify", "-head", head, path); code != OK || out != want {
		t.Fatalf("exit %d %q, want %q", code, out, want)
	}
	if err := os.Remove(segs[1]); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run("verify", path)
	if code != Failed || !strings.Contains(out, "FAIL "+path+": "+segs[2]+": records") || !strings.Contains(out, filepath.Base(segs[1])+") was removed") {
		t.Fatalf("middle segment removed: exit %d %q", code, out)
	}
	// The newest segment alone is not a whole log.
	for _, s := range segs {
		os.Remove(s)
	}
	if code, out, _ := run("verify", path); code != Failed || !strings.Contains(out, "were removed") {
		t.Fatalf("only the active segment: exit %d %q", code, out)
	}
}

// Unlike "authz mcp audit verify", the platform's check holds every record
// to its event type's schema.
func TestVerifySchemas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append("tool_call", map[string]any{"agent": "bot"}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	code, out, _ := run("verify", path)
	if code != Failed || !strings.HasPrefix(out, "FAIL "+path+": line 1: ") {
		t.Fatalf("exit %d %q", code, out)
	}
	var o, e bytes.Buffer
	if code := Verify("authz mcp", path, "", nil, &o, &e); code != OK || !strings.HasPrefix(o.String(), "OK ") {
		t.Fatalf("chain only: exit %d %q %q", code, o.String(), e.String())
	}
}

// chainError keeps the segment's path when it is another file's.
func TestChainError(t *testing.T) {
	se := &audit.SegmentError{Path: "a.1", Err: fmt.Errorf("x")}
	if got := chainError("a", se).Error(); got != "a.1: x" {
		t.Fatal(got)
	}
	if got := chainError("a.1", se).Error(); got != "x" {
		t.Fatal(got)
	}
}
