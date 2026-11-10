// Package auditcmd implements "authz audit": tools for the platform's one
// hash-chained audit log, which authz serve, authz gateway and authz mcp
// write, together or apart.
//
//	authz audit verify [-head HASH] FILE   check the chain across every segment of FILE
package auditcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// Summary is the one-line description shown in "authz help".
const Summary = "verify the platform's audit log across its segments"

// Exit codes of "authz audit".
const (
	OK     = 0 // the chain verified
	Failed = 1 // the chain is broken, a segment is missing, or the head differs
	Usage  = 2 // bad flags or arguments, or a file that cannot be read
)

const usage = `usage: authz audit verify [-head HASH] FILE

Checks the hash chain of the audit log that authz serve (GRANTD_AUDIT_LOG),
authz gateway (WICKET_AUDIT_LOG) and authz mcp (AUTHZ_MCP_AUDIT_LOG) write,
and every record against its event type's schema. A log rotated by
audit_rotate_bytes or audit_rotate_age is checked across all its segments
(FILE.<first record number> beside FILE) as one chain, and a segment that
was removed, renamed, reordered or replaced is named.

  -head HASH  the hash the last record must have, from GET /admin/audit/head
              or an earlier run; without it, records cut from the end of the
              newest segment cannot be told from a log that ended there

Prints "OK FILE: N records[ in K segments], head HASH", or "FAIL FILE: reason".
Exit codes: 0 verified, 1 failed, 2 usage error or unreadable file.
"authz mcp audit verify" is the MCP gateway's check, kept as toolgate had it:
the chain only, not the schemas.
`

// Run is the "authz audit" subcommand.
func Run(_ context.Context, args []string, _ func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
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
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: authz audit verify [-head HASH] FILE")
		return Usage
	}
	return Verify("authz", fs.Arg(0), *head, audit.Default(), stdout, stderr)
}

// Verify checks the log at path, across its segments when it was rotated,
// prints the outcome and returns the exit code: OK, Failed, or Usage when
// the file cannot be opened. s, if set, checks every record's envelope and
// payload too. head, if set, is the hash the last record must have. prog
// prefixes errors that are not about the chain.
func Verify(prog, path, head string, s *audit.Schemas, stdout, stderr io.Writer) int {
	segs, _ := audit.Segments(path)
	var records uint64
	var last, in string
	if len(segs) == 0 {
		// A log that was never rotated is the one file, checked and
		// printed as toolgate did.
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(stderr, prog+":", err)
			return Usage
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
			return Failed
		}
		if res.Records > 0 && res.Start != audit.Genesis {
			// A later segment without the ones before it.
			_, err = audit.VerifyChain(path, s)
			if err == nil {
				err = errors.New("the segments before this one are missing")
			}
			fmt.Fprintf(stdout, "FAIL %s: %v\n", path, chainError(path, err))
			return Failed
		}
		records, last = res.Records, res.Head
	} else {
		res, err := audit.VerifyChain(path, s)
		if err != nil {
			fmt.Fprintf(stdout, "FAIL %s: %v\n", path, chainError(path, err))
			return Failed
		}
		records, last = res.Records, res.Head
		in = fmt.Sprintf(" in %d segments", len(res.Segments))
	}
	if head != "" && head != last {
		fmt.Fprintf(stdout, "FAIL %s: chain is intact but ends at %s, not the expected head %s (records were removed from the end or the last one was changed)\n",
			path, last, head)
		return Failed
	}
	fmt.Fprintf(stdout, "OK %s: %d records%s, head %s\n", path, records, in, last)
	return OK
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
