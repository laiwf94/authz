//go:build unix

package auditcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
)

func runIn(stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, func(string) string { return "" }, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func proveTo(t *testing.T, file string, args ...string) audit.Proof {
	t.Helper()
	code, out, errs := run(append([]string{"prove"}, args...)...)
	if code != OK || errs != "" {
		t.Fatalf("prove %v: %d %q %q", args, code, out, errs)
	}
	var p audit.Proof
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if file != "" {
		if err := os.WriteFile(file, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// An operator proves records of a rotated log with authz audit prove; an
// auditor holding only the public key checks the proofs, and a consistency
// proof from a checkpoint they kept earlier.
func TestProve(t *testing.T) {
	dir := t.TempDir()
	keyFile, vkey := keygen(t, dir, "audit.example")
	path := filepath.Join(dir, "audit.jsonl")
	signedLog(t, path, keyFile, 10, audit.Rotation{MaxBytes: 4096})
	early := filepath.Join(dir, "early.checkpoint")
	note, err := os.ReadFile(audit.CheckpointPath(path))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(early, note, 0o600)
	old, err := audit.PeekCheckpoint(note)
	if err != nil {
		t.Fatal(err)
	}
	signedLog(t, path, keyFile, 40, audit.Rotation{MaxBytes: 4096})
	if segs, _ := audit.Segments(path); len(segs) < 2 {
		t.Fatalf("%d segments", len(segs))
	}
	cr, err := audit.VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}

	pf := filepath.Join(dir, "proof.json")
	p := proveTo(t, pf, "-record", "7", path)
	if p.Size != cr.Records || p.Checkpoint == "" {
		t.Fatalf("proof for %d records, log of %d; checkpoint %q", p.Size, cr.Records, p.Checkpoint)
	}
	code, out, errs := run("prove", "-check", pf, "-key", vkey)
	if code != OK || !strings.HasPrefix(out, "OK "+pf+": record 7 (authn.access_denied at ") ||
		!strings.Contains(out, " is in the "+strconv.FormatUint(cr.Records, 10)+" records signed by audit.example at ") ||
		!strings.Contains(out, "\n"+p.Entry+"\n") || errs != "" {
		t.Fatalf("check: %d %q %q", code, out, errs)
	}
	// From standard input, as piped from GET /admin/audit/proof.
	b, _ := os.ReadFile(pf)
	if code, out, _ := runIn(string(b), "prove", "-check", "-", "-key", vkey); code != OK || !strings.HasPrefix(out, "OK -: record 7") {
		t.Fatalf("check from stdin: %d %q", code, out)
	}

	// Against the earlier checkpoint the auditor kept.
	pOld := filepath.Join(dir, "old-proof.json")
	po := proveTo(t, pOld, "-record", "3", "-size", strconv.FormatUint(old.Size, 10), path)
	if po.Checkpoint != "" {
		t.Fatal("a proof for an earlier size carries the newest checkpoint")
	}
	if code, out, _ := run("prove", "-check", pOld, "-key", vkey); code != Failed || !strings.Contains(out, "carries no checkpoint") {
		t.Fatalf("check without a checkpoint: %d %q", code, out)
	}
	if code, out, _ := run("prove", "-check", pOld, "-key", vkey, "-checkpoint", early); code != OK {
		t.Fatalf("check against the early checkpoint: %d %q", code, out)
	}
	if code, out, _ := run("prove", "-check", pf, "-key", vkey, "-checkpoint", early); code != Failed || !strings.Contains(out, "the proof is for") {
		t.Fatalf("check against a checkpoint of another size: %d %q", code, out)
	}

	// The log grew consistently from the early checkpoint.
	cf := filepath.Join(dir, "cons.json")
	proveTo(t, cf, "-from", strconv.FormatUint(old.Size, 10), path)
	code, out, _ = run("prove", "-check", cf, "-key", vkey, "-old", early)
	if want := "OK " + cf + ": the " + strconv.FormatUint(cr.Records, 10) + " records signed by audit.example at "; code != OK || !strings.HasPrefix(out, want) ||
		!strings.Contains(out, " extend the "+strconv.FormatUint(old.Size, 10)+" signed at ") {
		t.Fatalf("consistency: %d %q", code, out)
	}
	if code, _, errs := run("prove", "-check", cf, "-key", vkey); code != Usage || !strings.Contains(errs, "needs -old") {
		t.Fatalf("consistency without -old: %d %q", code, errs)
	}
	// A consistency proof from another size than the earlier checkpoint's.
	cf2 := filepath.Join(dir, "cons2.json")
	proveTo(t, cf2, "-from", "2", path)
	if code, out, _ := run("prove", "-check", cf2, "-key", vkey, "-old", early); code != Failed || !strings.Contains(out, "earlier checkpoint covers") {
		t.Fatalf("consistency from another size: %d %q", code, out)
	}
	if code, _, errs := run("prove", "-check", pf, "-key", vkey, "-old", early); code != Usage || !strings.Contains(errs, "-old is for consistency") {
		t.Fatalf("-old with an inclusion proof: %d %q", code, errs)
	}

	// A record changed in the proof, or a proof signed by another key.
	var tp map[string]any
	json.Unmarshal(b, &tp)
	tp["entry"] = strings.Replace(tp["entry"].(string), `"deny"`, `"allow"`, 1)
	tb, _ := json.Marshal(tp)
	tf := filepath.Join(dir, "tampered.json")
	os.WriteFile(tf, tb, 0o600)
	if code, out, _ := run("prove", "-check", tf, "-key", vkey); code != Failed || !strings.Contains(out, "leaf hash") {
		t.Fatalf("tampered entry: %d %q", code, out)
	}
	delete(tp, "leaf_hash")
	tb, _ = json.Marshal(tp)
	os.WriteFile(tf, tb, 0o600)
	if code, out, _ := run("prove", "-check", tf, "-key", vkey); code != Failed || !strings.Contains(out, "is not in the tree") {
		t.Fatalf("tampered entry without its hash: %d %q", code, out)
	}
	_, other := keygen(t, dir, "other.example")
	if code, out, _ := run("prove", "-check", pf, "-key", other); code != Failed || !strings.Contains(out, "checkpoint in the proof") {
		t.Fatalf("another key: %d %q", code, out)
	}
	os.WriteFile(tf, []byte(`{"kind":"inclusion","surprise":1}`), 0o600)
	if code, out, _ := run("prove", "-check", tf, "-key", vkey); code != Failed || !strings.Contains(out, "not a proof") {
		t.Fatalf("unknown field: %d %q", code, out)
	}
	os.WriteFile(tf, append(b, b...), 0o600)
	if code, out, _ := run("prove", "-check", tf, "-key", vkey); code != Failed || !strings.Contains(out, "more than one") {
		t.Fatalf("two proofs: %d %q", code, out)
	}
}

func TestProveUsage(t *testing.T) {
	dir := t.TempDir()
	keyFile, vkey := keygen(t, dir, "audit.example")
	path := filepath.Join(dir, "audit.jsonl")
	signedLog(t, path, keyFile, 5, audit.Rotation{})
	for _, tc := range []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"prove", path}, Usage, "usage: authz audit prove"},
		{[]string{"prove", "-record", "1", "-from", "1", path}, Usage, "usage: authz audit prove"},
		{[]string{"prove", "-record", "1"}, Usage, "usage: authz audit prove"},
		{[]string{"prove", "-record", "1", "-key", vkey, path}, Usage, "usage: authz audit prove"},
		{[]string{"prove", "-record", "6", path}, Usage, "record 6 is not one of records 1 to 5"},
		{[]string{"prove", "-from", "6", path}, Usage, "must start from 1 to 5"},
		{[]string{"prove", "-record", "1", "-size", "9", path}, Failed, "the log has 5 records, not 9"},
		{[]string{"prove", "-record", "1", filepath.Join(dir, "missing")}, Usage, "no such file"},
		{[]string{"prove", "-check", "x.json"}, Usage, "-check needs -key"},
		{[]string{"prove", "-check", "x.json", "-record", "1", "-key", vkey}, Usage, "-check takes no FILE"},
		{[]string{"prove", "-check", filepath.Join(dir, "missing"), "-key", vkey}, Usage, "no such file"},
		{[]string{"prove", "-check", "x.json", "-key", "PRIVATE+KEY+x"}, Usage, "-key"},
		{[]string{"prove", "-bogus"}, Usage, "flag provided but not defined"},
		{[]string{"prove", "-h"}, OK, "usage:"},
	} {
		code, out, errs := run(tc.args...)
		if code != tc.code || !strings.Contains(out+errs, tc.out) {
			t.Errorf("%v: %d %q %q, want %d %q", tc.args, code, out, errs, tc.code, tc.out)
		}
	}
	// A broken chain is not proved.
	b, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(b, []byte(`"deny"`), []byte(`"allow"`), 1), 0o600)
	if code, out, _ := run("prove", "-record", "1", path); code != Failed || !strings.HasPrefix(out, "FAIL "+path) {
		t.Errorf("broken chain: %d %q", code, out)
	}
	// A log without a checkpoint is proved for all its records, unsigned.
	plain := filepath.Join(dir, "plain.jsonl")
	writeLog(t, plain, 3, audit.Rotation{})
	p := proveTo(t, "", "-record", "2", plain)
	if p.Size != 3 || p.Checkpoint != "" {
		t.Errorf("unsigned log: %+v", p)
	}
}
