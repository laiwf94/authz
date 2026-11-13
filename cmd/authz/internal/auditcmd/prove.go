package auditcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

const proveUsage = `usage: authz audit prove -record N|-from M [-size S] FILE
       authz audit prove -check PROOF -key KEY [-checkpoint NOTE] [-old NOTE]`

// maxProofBytes bounds a proof read by -check: a record of at most
// audit.MaxLineBytes, escaped, and 64 hashes.
const maxProofBytes = 8 << 20

func proveCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit prove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	record := fs.Uint64("record", 0, "prove that record N is in the log")
	from := fs.Uint64("from", 0, "prove that the log extends its first M records")
	size := fs.Uint64("size", 0, "prove for the first S records (default: the newest checkpoint's)")
	checkFile := fs.String("check", "", "check the proof in this file (- for standard input)")
	key := fs.String("key", "", "public key the checkpoints are signed with, or a file holding it")
	cpPath := fs.String("checkpoint", "", "signed checkpoint of the proof's size (default: the proof's own)")
	oldPath := fs.String("old", "", "earlier signed checkpoint a consistency proof starts from")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if *checkFile != "" {
		if fs.NArg() != 0 || *record != 0 || *from != 0 || *size != 0 {
			fmt.Fprintln(stderr, "authz audit prove: -check takes no FILE, -record, -from or -size\n"+proveUsage)
			return Usage
		}
		if *key == "" {
			fmt.Fprintln(stderr, "authz audit prove: -check needs -key, the public key the checkpoints are signed with")
			return Usage
		}
		return checkProof(*checkFile, *key, *cpPath, *oldPath, stdin, stdout, stderr)
	}
	if fs.NArg() != 1 || (*record == 0) == (*from == 0) || *key != "" || *cpPath != "" || *oldPath != "" {
		fmt.Fprintln(stderr, proveUsage)
		return Usage
	}
	path := fs.Arg(0)
	var out bytes.Buffer
	cr, code := check("authz audit prove", path, "", audit.Default(), &out, stderr)
	if code != OK {
		stdout.Write(out.Bytes())
		return code
	}
	// The newest checkpoint names the size to prove for, and goes with a
	// proof of that size; it is not verified here, the auditor does that.
	note, _ := os.ReadFile(audit.CheckpointPath(path))
	cp, cpErr := audit.PeekCheckpoint(note)
	if *size == 0 {
		*size = cr.Records
		if cpErr == nil && cp.Size <= cr.Records {
			*size = cp.Size
		}
	}
	if *size > cr.Records {
		fmt.Fprintf(stdout, "FAIL %s: the log has %d records, not %d\n", path, cr.Records, *size)
		return Failed
	}
	var p audit.Proof
	var err error
	if *record != 0 {
		p, err = audit.ProveInclusion(path, *record, *size)
	} else {
		p, err = audit.ProveConsistency(path, *from, *size)
	}
	if errors.Is(err, audit.ErrProofRange) {
		fmt.Fprintln(stderr, "authz audit prove:", strings.TrimPrefix(err.Error(), "audit: "))
		return Usage
	}
	if err != nil {
		fmt.Fprintf(stdout, "FAIL %s: %s\n", path, strings.TrimPrefix(err.Error(), "audit: "))
		return Failed
	}
	if cpErr == nil && cp.Size == p.Size && cp.Root == p.Root {
		p.Checkpoint = string(note)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "authz audit prove:", err)
		return Usage
	}
	stdout.Write(append(b, '\n'))
	return OK
}

func checkProof(proofPath, key, cpPath, oldPath string, stdin io.Reader, stdout, stderr io.Writer) int {
	v, err := readVerifier(key)
	if err != nil {
		fmt.Fprintln(stderr, "authz audit prove: -key:", err)
		return Usage
	}
	var raw []byte
	if proofPath == "-" {
		if stdin == nil {
			stdin = strings.NewReader("")
		}
		raw, err = io.ReadAll(io.LimitReader(stdin, maxProofBytes+1))
	} else {
		raw, err = readLimited(proofPath)
	}
	if err == nil && len(raw) > maxProofBytes {
		err = fmt.Errorf("%s is larger than %d bytes", proofPath, maxProofBytes)
	}
	if err != nil {
		fmt.Fprintln(stderr, "authz audit prove:", err)
		return Usage
	}
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stdout, "FAIL %s: %s\n", proofPath, strings.TrimPrefix(fmt.Sprintf(format, args...), "audit: "))
		return Failed
	}
	var p audit.Proof
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fail("not a proof: %v", err)
	}
	if dec.More() {
		return fail("not a proof: more than one JSON value")
	}
	if p.Kind == audit.ProofConsistency && oldPath == "" {
		fmt.Fprintln(stderr, "authz audit prove: a consistency proof needs -old, the earlier checkpoint it starts from")
		return Usage
	}
	note := []byte(p.Checkpoint)
	what := "checkpoint in the proof"
	if cpPath != "" {
		if note, err = readLimited(cpPath); err != nil {
			fmt.Fprintln(stderr, "authz audit prove:", err)
			return Usage
		}
		what = cpPath
	} else if len(note) == 0 {
		return fail("the proof carries no checkpoint; give -checkpoint, a signed checkpoint of %d records", p.Size)
	}
	cp, err := audit.OpenCheckpoint(note, v)
	if err != nil {
		return fail("%s: %v", what, err)
	}
	var old *audit.Checkpoint
	if oldPath != "" {
		if p.Kind != audit.ProofConsistency {
			fmt.Fprintln(stderr, "authz audit prove: -old is for consistency proofs")
			return Usage
		}
		msg, err := readLimited(oldPath)
		if err != nil {
			fmt.Fprintln(stderr, "authz audit prove:", err)
			return Usage
		}
		oc, err := audit.OpenCheckpoint(msg, v)
		if err != nil {
			return fail("%s: %v", oldPath, err)
		}
		old = &oc
	}
	if err := p.Check(cp, old); err != nil {
		return fail("%v", err)
	}
	signed := fmt.Sprintf("signed by %s at %s", cp.Origin, cp.Time.Format(time.RFC3339))
	if p.Kind == audit.ProofConsistency {
		fmt.Fprintf(stdout, "OK %s: the %d records %s extend the %d signed at %s\n",
			proofPath, cp.Size, signed, old.Size, old.Time.Format(time.RFC3339))
		return OK
	}
	var r audit.Record
	_ = json.Unmarshal([]byte(p.Entry), &r) // Check parsed it
	fmt.Fprintf(stdout, "OK %s: record %d (%s at %s) is in the %d records %s\n%s\n",
		proofPath, p.Record, r.Event, r.Time, cp.Size, signed, p.Entry)
	return OK
}

// readLimited reads a file of at most maxProofBytes.
func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxProofBytes+1))
	if err == nil && len(b) > maxProofBytes {
		err = fmt.Errorf("%s is larger than %d bytes", path, maxProofBytes)
	}
	return b, err
}
