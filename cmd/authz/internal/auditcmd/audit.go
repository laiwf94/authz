// Package auditcmd implements "authz audit": tools for the platform's one
// hash-chained audit log, which authz serve, authz gateway and authz mcp
// write, together or apart.
//
//	authz audit verify [-head HASH] [-key KEY [-checkpoint NOTE]] FILE
//	                                        check the chain across every segment of FILE,
//	                                        and against a signed checkpoint
//	authz audit prove -record N|-from M [-size S] FILE
//	                                        print an RFC 6962 inclusion or consistency proof
//	authz audit prove -check PROOF -key KEY [-checkpoint NOTE] [-old NOTE]
//	                                        check one with only the public key
//	authz audit keygen -out FILE NAME      make a checkpoint signing key
package auditcmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// Summary is the one-line description shown in "authz help".
const Summary = "verify the platform's audit log across its segments and against signed checkpoints, and prove records are in it"

// Exit codes of "authz audit".
const (
	OK     = 0 // the chain verified
	Failed = 1 // the chain is broken, a segment is missing, or the head differs
	Usage  = 2 // bad flags or arguments, or a file that cannot be read
)

const usage = `usage: authz audit verify [-head HASH] [-key KEY [-checkpoint NOTE]] FILE
       authz audit prove -record N|-from M [-size S] FILE
       authz audit prove -check PROOF -key KEY [-checkpoint NOTE] [-old NOTE]
       authz audit keygen -out FILE NAME

verify checks the hash chain of the audit log that authz serve
(GRANTD_AUDIT_LOG), authz gateway (WICKET_AUDIT_LOG) and authz mcp
(AUTHZ_MCP_AUDIT_LOG) write, and every record against its event type's
schema. A log rotated by audit_rotate_bytes or audit_rotate_age is checked
across all its segments (FILE.<first record number> beside FILE) as one
chain, and a segment that was removed, renamed, reordered or replaced is
named.

  -head HASH        the hash the last record must have, from GET
                    /admin/audit/head or an earlier run; without it or
                    -key, records cut from the end of the newest segment
                    cannot be told from a log that ended there
  -key KEY          the public key of AUTHZ_AUDIT_SIGNING_KEY, as keygen
                    printed it (NAME+HASH+KEY), or a file holding it: the
                    checkpoint must be signed by it, and the log must still
                    hold every record the checkpoint covers, unchanged
  -checkpoint NOTE  the signed checkpoint to check against, such as one
                    saved from GET /admin/audit/checkpoint; default
                    FILE.checkpoint, the newest one the log wrote

Prints "OK FILE: N records[ in K segments], head HASH", then with -key
"OK FILE: checkpoint signed by NAME at TIME covers M of the N records",
or "FAIL FILE: reason". Exit codes: 0 verified, 1 failed, 2 usage error or
unreadable file. "authz mcp audit verify" is the MCP gateway's check, kept
as toolgate had it: the chain only, not the schemas.

prove prints, as JSON, an RFC 6962 proof over the records of FILE, checked
by verify first: with -record N that record N is in the log (the proof
carries the record), with -from M that the log extends its first M records,
the size of an earlier checkpoint. It is for the tree of the records the
newest checkpoint FILE.checkpoint covers, which it carries, or, with -size S,
for the first S records. GET /admin/audit/proof serves the same from a
running authz mcp.

prove -check PROOF checks a proof (a file, or - for standard input) with
only the public key, without the log:

  -key KEY          the public key, as for verify
  -checkpoint NOTE  the signed checkpoint to check against, of the proof's
                    size; default the one the proof carries
  -old NOTE         for a consistency proof, the earlier checkpoint the
                    auditor kept, of the size the proof starts from: needed

Prints "OK PROOF: record N (EVENT at TIME) is in the M records signed by
NAME at TIME" and the record, or "OK PROOF: the M records signed by NAME at
TIME extend the K signed at TIME", or "FAIL PROOF: reason", with the exit
codes of verify.

keygen makes an Ed25519 key named NAME for signing checkpoints. The
signing key goes to FILE, created with mode 0600 (an existing file is not
replaced): point AUTHZ_AUDIT_SIGNING_KEY_FILE at it, or put its contents in
AUTHZ_AUDIT_SIGNING_KEY. The public key, the one auditors verify with, is
printed.
`

// Run is the "authz audit" subcommand.
func Run(_ context.Context, args []string, _ func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	switch fs.Arg(0) {
	case "verify":
		return verifyCmd(fs.Args()[1:], stdout, stderr)
	case "prove":
		return proveCmd(fs.Args()[1:], stdin, stdout, stderr)
	case "keygen":
		return keygenCmd(fs.Args()[1:], stdout, stderr)
	case "":
		fmt.Fprint(stderr, usage)
	default:
		fmt.Fprintf(stderr, "authz audit: unknown command %q\n%s", fs.Arg(0), usage)
	}
	return Usage
}

func verifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	head := fs.String("head", "", "expected hash of the last record")
	key := fs.String("key", "", "public key the checkpoint is signed with, or a file holding it")
	cpPath := fs.String("checkpoint", "", "signed checkpoint (default FILE.checkpoint)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: authz audit verify [-head HASH] [-key KEY [-checkpoint NOTE]] FILE")
		return Usage
	}
	path := fs.Arg(0)
	if *key == "" {
		if *cpPath != "" {
			fmt.Fprintln(stderr, "authz audit verify: -checkpoint needs -key, the public key it is signed with")
			return Usage
		}
		return Verify("authz", path, *head, audit.Default(), stdout, stderr)
	}
	v, err := readVerifier(*key)
	if err != nil {
		fmt.Fprintln(stderr, "authz audit verify: -key:", err)
		return Usage
	}
	if *cpPath == "" {
		*cpPath = audit.CheckpointPath(path)
	}
	msg, err := os.ReadFile(*cpPath)
	if err != nil {
		fmt.Fprintln(stderr, "authz audit verify:", err)
		return Usage
	}
	cp, err := audit.OpenCheckpoint(msg, v)
	if err != nil {
		fmt.Fprintf(stdout, "FAIL %s: checkpoint %s: %s\n", path, *cpPath, strings.TrimPrefix(err.Error(), "audit: "))
		return Failed
	}
	var out bytes.Buffer
	cr, code := check("authz", path, *head, audit.Default(), &out, stderr)
	if code == OK {
		if err := cr.Covers(cp); err != nil {
			fmt.Fprintf(stdout, "FAIL %s: checkpoint %s: %v\n", path, *cpPath, err)
			return Failed
		}
		fmt.Fprintf(&out, "OK %s: checkpoint signed by %s at %s covers %d of the %d records\n",
			path, cp.Origin, cp.Time.Format(time.RFC3339), cp.Size, cr.Records)
	}
	stdout.Write(out.Bytes())
	return code
}

// readVerifier reads a public key given as text or as a file holding it.
func readVerifier(s string) (*audit.Verifier, error) {
	v, err := audit.ParseVerifier(s)
	if err == nil || strings.HasPrefix(s, "PRIVATE+KEY+") {
		return v, err
	}
	b, ferr := os.ReadFile(s)
	if ferr != nil {
		if strings.Contains(s, "+") {
			return nil, err
		}
		return nil, ferr
	}
	return audit.ParseVerifier(string(b))
}

func keygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	out := fs.String("out", "", "file for the signing key")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() != 1 || *out == "" {
		fmt.Fprintln(stderr, "usage: authz audit keygen -out FILE NAME")
		return Usage
	}
	skey, vkey, err := audit.GenerateKey(rand.Reader, fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "authz audit keygen:", strings.TrimPrefix(err.Error(), "audit: "))
		return Usage
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "authz audit keygen:", err)
		return Usage
	}
	if _, err := f.WriteString(skey + "\n"); err != nil {
		f.Close()
		os.Remove(*out)
		fmt.Fprintln(stderr, "authz audit keygen:", err)
		return Usage
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		os.Remove(*out)
		fmt.Fprintln(stderr, "authz audit keygen:", err)
		return Usage
	}
	fmt.Fprintln(stdout, vkey)
	return OK
}

// Verify checks the log at path, across its segments when it was rotated,
// prints the outcome and returns the exit code: OK, Failed, or Usage when
// the file cannot be opened. s, if set, checks every record's envelope and
// payload too. head, if set, is the hash the last record must have. prog
// prefixes errors that are not about the chain.
func Verify(prog, path, head string, s *audit.Schemas, stdout, stderr io.Writer) int {
	_, code := check(prog, path, head, s, stdout, stderr)
	return code
}

// check is Verify, also returning the verified log.
func check(prog, path, head string, s *audit.Schemas, stdout, stderr io.Writer) (audit.ChainResult, int) {
	segs, _ := audit.Segments(path)
	var cr audit.ChainResult
	var in string
	if len(segs) == 0 {
		// A log that was never rotated is the one file, checked and
		// printed as toolgate did.
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(stderr, prog+":", err)
			return cr, Usage
		}
		var res audit.Result
		if s != nil {
			res, err = audit.VerifyWith(f, s)
		} else {
			res, err = audit.Verify(f)
		}
		f.Close()
		if err != nil {
			fmt.Fprintf(stdout, "FAIL %s: %v\n", path, err)
			return cr, Failed
		}
		if res.Records > 0 && res.Start != audit.Genesis {
			// A later segment without the ones before it.
			_, err = audit.VerifyChain(path, s)
			if err == nil {
				err = errors.New("the segments before this one are missing")
			}
			fmt.Fprintf(stdout, "FAIL %s: %v\n", path, chainError(path, err))
			return cr, Failed
		}
		cr = audit.ChainResult{Segments: []audit.SegmentResult{{Path: path, Result: res}}, Records: res.Records, Head: res.Head}
	} else {
		var err error
		if cr, err = audit.VerifyChain(path, s); err != nil {
			fmt.Fprintf(stdout, "FAIL %s: %v\n", path, chainError(path, err))
			return cr, Failed
		}
		in = fmt.Sprintf(" in %d segments", len(cr.Segments))
	}
	if head != "" && head != cr.Head {
		fmt.Fprintf(stdout, "FAIL %s: chain is intact but ends at %s, not the expected head %s (records were removed from the end or the last one was changed)\n",
			path, cr.Head, head)
		return cr, Failed
	}
	fmt.Fprintf(stdout, "OK %s: %d records%s, head %s\n", path, cr.Records, in, cr.Head)
	return cr, OK
}

// chainError drops the segment's path from an error about the file the
// user named, which the FAIL line already shows.
func chainError(path string, err error) error {
	var se *audit.SegmentError
	if errors.As(err, &se) && se.Path == path {
		return se.Err
	}
	return err
}
