package mcp

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// oldChainDir holds an audit log written by the toolgate binary before it
// became `authz mcp`, and what that binary's `audit verify` printed for it
// and for damaged copies (see its README.md).
const oldChainDir = "../../../../internal/agents/audit/testdata"

// verifyCase is one command from toolgate-demo-verify.txt.
type verifyCase struct {
	args   []string
	stdout string
	exit   int
}

// readVerifyTranscript parses blocks of
//
//	$ toolgate audit verify ARGS...
//	stdout lines
//	exit N
func readVerifyTranscript(t *testing.T, path string) []verifyCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const prompt = "$ toolgate audit verify "
	var cases []verifyCase
	for _, block := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		lines := strings.Split(block, "\n")
		if len(lines) < 2 || !strings.HasPrefix(lines[0], prompt) || !strings.HasPrefix(lines[len(lines)-1], "exit ") {
			t.Fatalf("malformed transcript block:\n%s", block)
		}
		exit, err := strconv.Atoi(strings.TrimPrefix(lines[len(lines)-1], "exit "))
		if err != nil {
			t.Fatal(err)
		}
		var out string
		if body := lines[1 : len(lines)-1]; len(body) > 0 {
			out = strings.Join(body, "\n") + "\n"
		}
		cases = append(cases, verifyCase{strings.Fields(strings.TrimPrefix(lines[0], prompt)), out, exit})
	}
	return cases
}

// damagedCopies makes the copies described in the testdata README from the
// old log's exact bytes.
func damagedCopies(t *testing.T, old []byte) map[string][]byte {
	t.Helper()
	lines := bytes.SplitAfter(old, []byte("\n"))
	lines = lines[:len(lines)-1]
	if len(lines) < 6 {
		t.Fatalf("old log has %d lines", len(lines))
	}
	join := func(ls ...[]byte) []byte { return bytes.Join(ls, nil) }
	last := lines[len(lines)-1]
	swapped := append([][]byte(nil), lines...)
	swapped[4], swapped[5] = swapped[5], swapped[4]
	tampered := bytes.Replace(old, []byte(`"decision":"deny"`), []byte(`"decision":"allow"`), 1)
	if bytes.Equal(tampered, old) {
		t.Fatal("old log has no denial to tamper with")
	}
	return map[string][]byte{
		"toolgate-demo.jsonl": old,
		"tampered.jsonl":      tampered,
		"dropped-last.jsonl":  join(lines[:len(lines)-1]...),
		"torn.jsonl":          append(join(lines[:len(lines)-1]...), last[:len(last)/2]...),
		"swapped.jsonl":       join(swapped...),
		"dropped-first.jsonl": join(lines[1:]...),
	}
}

// TestOldBinaryAuditVerify runs `authz mcp audit verify` on the log the old
// binary wrote and on each damaged copy, and requires exactly what the old
// binary printed and the same exit status.
func TestOldBinaryAuditVerify(t *testing.T) {
	old, err := os.ReadFile(filepath.Join(oldChainDir, "toolgate-demo.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cases := readVerifyTranscript(t, filepath.Join(oldChainDir, "toolgate-demo-verify.txt"))
	if len(cases) != 8 {
		t.Fatalf("transcript has %d commands, want 8", len(cases))
	}
	dir := t.TempDir()
	files := damagedCopies(t, old)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The old binary printed the file names as given, so run from the same
	// directory with the same relative names.
	t.Chdir(dir)
	used := map[string]bool{}
	for _, c := range cases {
		used[c.args[len(c.args)-1]] = true
		var stdout bytes.Buffer
		code := Run(context.Background(), append([]string{"audit", "verify"}, c.args...), func(string) string { return "" }, nil, &stdout, io.Discard)
		if code != c.exit || stdout.String() != c.stdout {
			t.Errorf("authz mcp audit verify %s:\n got exit %d: %q\nwant exit %d: %q",
				strings.Join(c.args, " "), code, stdout.String(), c.exit, c.stdout)
		}
	}
	for name := range files {
		if !used[name] {
			t.Errorf("transcript never verifies %s", name)
		}
	}
}
