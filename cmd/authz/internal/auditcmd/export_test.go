//go:build unix

package auditcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// export hands out a checkpoint once the log verifies against it and
// records it; a writer with retention then removes the segments it covers,
// and verify says so.
func TestExport(t *testing.T) {
	dir := t.TempDir()
	keyFile, vkey := keygen(t, dir, "audit.example")
	path := filepath.Join(dir, "audit.jsonl")
	signedLog(t, path, keyFile, 120, audit.Rotation{MaxBytes: audit.MinRotateBytes})
	segs, _ := audit.Segments(path)
	if len(segs) < 4 {
		t.Fatalf("%d segments; the test needs more", len(segs))
	}

	// Usage errors.
	for _, args := range [][]string{
		{"export", path},
		{"export", "-key", vkey},
		{"export", "-key", "not a key", path},
		{"export", "-key", vkey, "-checkpoint", filepath.Join(dir, "missing"), path},
	} {
		if code, _, _ := run(args...); code != Usage {
			t.Errorf("%q: exit %d, want %d", args, code, Usage)
		}
	}
	// Another key's checkpoint, or a log cut since, is not exported.
	_, other := keygen(t, dir, "audit.other")
	if code, out, errs := run("export", "-key", other, path); code != Failed || out != "" || !strings.Contains(errs, "FAIL") {
		t.Fatalf("other key: %d %q %q", code, out, errs)
	}
	if _, err := os.Stat(audit.ExportedPath(path)); err == nil {
		t.Fatal("a refused export was recorded")
	}

	note := filepath.Join(dir, "saved.checkpoint")
	code, out, errs := run("export", "-key", vkey, "-out", note, path)
	if code != OK || out != "" || !strings.Contains(errs, "recorded as exported") {
		t.Fatalf("export: %d %q %q", code, out, errs)
	}
	saved, _ := os.ReadFile(note)
	recorded, _ := os.ReadFile(audit.ExportedPath(path))
	cp, _ := os.ReadFile(audit.CheckpointPath(path))
	if string(saved) != string(cp) || string(recorded) != string(cp) {
		t.Fatal("the exported, recorded and newest checkpoints differ")
	}
	// -out never replaces a file.
	if code, _, _ := run("export", "-key", vkey, "-out", note, path); code != Usage {
		t.Fatalf("export over an existing file: %d", code)
	}
	// To standard output.
	if code, out, _ := run("export", "-key", vkey, path); code != OK || out != string(cp) {
		t.Fatalf("export to stdout: %d %q", code, out)
	}

	// A writer with retention now removes what the export covers.
	b, _ := os.ReadFile(keyFile)
	s, err := audit.ParseSigner(string(b))
	if err != nil {
		t.Fatal(err)
	}
	var retainErr error
	l, err := audit.OpenWith(path, audit.Options{Schemas: audit.Default(), Rotation: audit.Rotation{MaxBytes: audit.MinRotateBytes},
		Signer: s, CheckpointEvery: time.Hour, Retention: audit.Retention{MaxBytes: 2 * audit.MinRetainBytes},
		OnRetainError: func(err error) { retainErr = err }})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil || retainErr != nil {
		t.Fatal(err, retainErr)
	}
	left, _ := audit.Segments(path)
	if len(left) >= len(segs) || len(left) == 0 {
		t.Fatalf("%d segments left of %d", len(left), len(segs))
	}
	code, out, _ = run("verify", "-key", vkey, path)
	if code != OK || !strings.Contains(out, "removed by retention") || !strings.Contains(out, "checkpoint signed by audit.example") {
		t.Fatalf("verify after retention: %d %q", code, out)
	}
	// The auditor's saved checkpoint is still covered.
	if code, out, _ := run("verify", "-key", vkey, "-checkpoint", note, path); code != OK {
		t.Fatalf("verify against the exported checkpoint: %d %q", code, out)
	}
	// With every rotated-out segment gone the base still leads verify.
	for _, p := range left {
		os.Remove(p)
	}
	if code, out, _ := run("verify", path); code != Failed || !strings.Contains(out, "missing between the records retention removed") {
		t.Fatalf("verify with the segments after the base removed: %d %q", code, out)
	}
}
