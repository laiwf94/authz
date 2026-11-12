//go:build unix

package auditcmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// keygen makes a key with "authz audit keygen" and returns the signing
// key's file and the public key it printed.
func keygen(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	keyFile := filepath.Join(dir, name+".key")
	code, out, errs := run("keygen", "-out", keyFile, name)
	if code != OK || errs != "" {
		t.Fatalf("keygen: %d %q %q", code, out, errs)
	}
	return keyFile, strings.TrimSpace(out)
}

// signedLog appends n records to the log at path, signing with the key in
// keyFile, and closes it, which signs the final state.
func signedLog(t *testing.T, path, keyFile string, n int, rot audit.Rotation) {
	t.Helper()
	b, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := audit.ParseSigner(string(b))
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.OpenWith(path, audit.Options{Schemas: audit.Default(), Rotation: rot, Signer: s})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := l.Write(audit.Envelope{Subject: "x.example", Action: "access", Decision: audit.Deny},
			audit.AccessDenied{Reason: "unknown_app", Host: "x.example"}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	keyFile, vkey := keygen(t, dir, "audit.example")
	fi, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", fi.Mode())
	}
	b, _ := os.ReadFile(keyFile)
	s, err := audit.ParseSigner(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if s.Verifier().String() != vkey || !strings.HasPrefix(vkey, "audit.example+") {
		t.Fatalf("printed %q, not the key's public half", vkey)
	}
	// The private key is never printed.
	if strings.Contains(vkey, "PRIVATE") {
		t.Fatal("keygen printed the signing key")
	}
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"keygen", "name"}, "usage: authz audit keygen -out FILE NAME"},
		{[]string{"keygen", "-out", filepath.Join(dir, "k")}, "usage: authz audit keygen -out FILE NAME"},
		{[]string{"keygen", "-out", keyFile, "again"}, "file exists"},
		{[]string{"keygen", "-out", filepath.Join(dir, "k2"), "a b"}, "key name"},
		{[]string{"keygen", "-out", filepath.Join(dir, "none", "k"), "n"}, "no such file"},
		{[]string{"keygen", "-x"}, "flag provided but not defined"},
	} {
		code, out, errs := run(tc.args...)
		if code != Usage || out != "" || !strings.Contains(errs, tc.err) {
			t.Errorf("%q: exit %d, out %q, err %q; want %q", tc.args, code, out, errs, tc.err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "k2")); !os.IsNotExist(err) {
		t.Fatal("a refused keygen left a file")
	}
	if code, _, errs := run("keygen", "-h"); code != OK || !strings.Contains(errs, "keygen makes an Ed25519 key") {
		t.Fatalf("keygen -h: %d %q", code, errs)
	}
}

func TestVerifyCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	keyFile, vkey := keygen(t, dir, "audit.example")
	signedLog(t, path, keyFile, 9, audit.Rotation{})

	code, out, errs := run("verify", "-key", vkey, path)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != OK || errs != "" || len(lines) != 2 || !strings.HasPrefix(lines[0], "OK "+path+": 9 records, head ") ||
		!strings.HasPrefix(lines[1], "OK "+path+": checkpoint signed by audit.example at ") || !strings.HasSuffix(lines[1], " covers 9 of the 9 records") {
		t.Fatalf("verify -key: %d %q %q", code, out, errs)
	}
	// The key from a file.
	pubFile := filepath.Join(dir, "audit.pub")
	if err := os.WriteFile(pubFile, []byte(vkey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("verify", "-key", pubFile, path); code != OK || !strings.Contains(out, "covers 9 of the 9") {
		t.Fatalf("verify -key FILE: %d %q", code, out)
	}

	// An auditor keeps this checkpoint; the log grows and rotates.
	saved := filepath.Join(dir, "saved.checkpoint")
	b, _ := os.ReadFile(audit.CheckpointPath(path))
	if err := os.WriteFile(saved, b, 0o600); err != nil {
		t.Fatal(err)
	}
	signedLog(t, path, keyFile, 40, audit.Rotation{MaxBytes: 4096})
	if segs, _ := audit.Segments(path); len(segs) == 0 {
		t.Fatal("no rotation")
	}
	code, out, _ = run("verify", "-key", vkey, "-checkpoint", saved, path)
	if code != OK || !strings.Contains(out, " segments, head ") || !strings.Contains(out, "covers 9 of the ") {
		t.Fatalf("old checkpoint, rotated log: %d %q", code, out)
	}
	// The newest checkpoint, written on Close, covers every record: 49
	// written and a segment start record for each rotation.
	if code, out, _ := run("verify", "-key", vkey, path); code != OK ||
		!regexp.MustCompile(`covers (\d+) of the (\d+) records\n$`).MatchString(out) ||
		regexp.MustCompile(`covers (\d+) of`).FindStringSubmatch(out)[1] != regexp.MustCompile(`of the (\d+) records`).FindStringSubmatch(out)[1] {
		t.Fatalf("newest checkpoint, rotated log: %d %q", code, out)
	}

	// Another key's signature.
	_, otherKey := keygen(t, dir, "other.example")
	if code, out, _ := run("verify", "-key", otherKey, path); code != Failed || !strings.Contains(out, "is not signed by other.example+") {
		t.Fatalf("other key: %d %q", code, out)
	}
	// A changed checkpoint.
	changed := strings.Replace(string(b), "\n9\n", "\n8\n", 1)
	if err := os.WriteFile(saved, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("verify", "-key", vkey, "-checkpoint", saved, path); code != Failed || !strings.Contains(out, "does not verify") {
		t.Fatalf("changed checkpoint: %d %q", code, out)
	}
}

func TestVerifyCheckpointCatchesRewrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	keyFile, vkey := keygen(t, dir, "audit.example")
	signedLog(t, path, keyFile, 6, audit.Rotation{})
	saved := filepath.Join(dir, "saved.checkpoint")
	b, _ := os.ReadFile(audit.CheckpointPath(path))
	os.WriteFile(saved, b, 0o600)

	// The newest records cut: the chain is intact, the checkpoint is not
	// covered.
	whole, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(whole), "\n")
	os.WriteFile(path, []byte(strings.Join(lines[:4], "")), 0o600)
	code, out, _ := run("verify", "-key", vkey, "-checkpoint", saved, path)
	if code != Failed || !strings.Contains(out, "the log has 4 records, but the checkpoint signed at ") || !strings.Contains(out, "covers 6: records were removed from its end") {
		t.Fatalf("cut log: %d %q", code, out)
	}
	// Without -key the cut goes unnoticed, which is what checkpoints are for.
	if code, _, _ := run("verify", path); code != OK {
		t.Fatalf("cut log without -key: %d", code)
	}

	// The whole log rewritten with as many records: a valid chain, not
	// the one signed.
	os.Remove(path)
	os.Remove(audit.CheckpointPath(path))
	writeLog(t, path, 6, audit.Rotation{})
	code, out, _ = run("verify", "-key", vkey, "-checkpoint", saved, path)
	if code != Failed || !strings.Contains(out, "record 6 is not the one the checkpoint signed") {
		t.Fatalf("rewritten log: %d %q", code, out)
	}
	writeLog(t, path, 3, audit.Rotation{})
	code, out, _ = run("verify", "-key", vkey, "-checkpoint", saved, path)
	if code != Failed || !strings.Contains(out, "record 6 is not the one the checkpoint signed") {
		t.Fatalf("rewritten, longer log: %d %q", code, out)
	}
	// A broken chain fails as without -key.
	whole, _ = os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(whole), `"x.example"`, `"y.example"`, 1)), 0o600)
	if code, out, _ := run("verify", "-key", vkey, "-checkpoint", saved, path); code != Failed || strings.Contains(out, "OK") {
		t.Fatalf("broken chain: %d %q", code, out)
	}
}

func TestVerifyCheckpointUsage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	keyFile, vkey := keygen(t, dir, "audit.example")
	writeLog(t, path, 2, audit.Rotation{})
	skey, _ := os.ReadFile(keyFile)
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"verify", "-checkpoint", "x", path}, "-checkpoint needs -key"},
		{[]string{"verify", "-key", "nope+1234+abc", path}, "-key: audit: public key"},
		{[]string{"verify", "-key", filepath.Join(dir, "missing"), path}, "no such file"},
		{[]string{"verify", "-key", strings.TrimSpace(string(skey)), path}, "that is a signing key"},
		// The log was written without a key: there is no checkpoint.
		{[]string{"verify", "-key", vkey, path}, "audit.jsonl.checkpoint: no such file"},
	} {
		code, out, errs := run(tc.args...)
		if code != Usage || out != "" || !strings.Contains(errs, tc.err) {
			t.Errorf("%q: exit %d, out %q, err %q; want %q", tc.args[:len(tc.args)-1], code, out, errs, tc.err)
		}
		if strings.Contains(errs, "PRIVATE") {
			t.Errorf("an error repeats the signing key: %q", errs)
		}
	}
	// A missing log is a usage error with -key too.
	signedLog(t, path+"2", keyFile, 1, audit.Rotation{})
	os.Rename(path+"2.checkpoint", filepath.Join(dir, "cp"))
	if code, _, errs := run("verify", "-key", vkey, "-checkpoint", filepath.Join(dir, "cp"), filepath.Join(dir, "gone")); code != Usage || !strings.Contains(errs, "no such file") {
		t.Fatalf("missing log: %d %q", code, errs)
	}
}
