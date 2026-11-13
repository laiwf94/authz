package auditcmd

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

const queryUsage = "usage: authz audit query [-full] [-limit N] [-count] [-read-only] FILE [TERM...]"

// queryCmd is "authz audit query": the records of FILE that every TERM
// matches, one JSON line each, on standard output.
func queryCmd(args []string, now func() time.Time, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	full := fs.Bool("full", false, "read every record instead of skipping by the time indexes")
	limit := fs.Uint64("limit", 0, "stop after N matching records")
	count := fs.Bool("count", false, "print the number of matching records instead of the records")
	readOnly := fs.Bool("read-only", false, "never write time index files")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, queryUsage)
		return Usage
	}
	path := fs.Arg(0)
	f, err := audit.ParseFilterTerms(fs.Args()[1:], now())
	if err != nil {
		fmt.Fprintln(stderr, "authz audit query:", strings.TrimPrefix(err.Error(), "audit: "))
		return Usage
	}
	w := bufio.NewWriterSize(stdout, 64<<10)
	res, err := audit.Query(path, audit.QueryOptions{Filter: f, Schemas: audit.Default(), Full: *full, Limit: *limit, ReadOnly: *readOnly},
		func(_ *audit.Record, line []byte) error {
			if *count {
				return nil
			}
			w.Write(line)
			return w.WriteByte('\n')
		})
	if *count && err == nil {
		fmt.Fprintln(w, res.Matched)
	}
	if ferr := w.Flush(); err == nil && ferr != nil {
		fmt.Fprintln(stderr, "authz audit query:", ferr)
		return Usage
	}
	if err != nil {
		// A broken chain or segment; anything else, such as a missing
		// file, is a usage error, as for verify.
		var se *audit.SegmentError
		if errors.As(err, &se) {
			fmt.Fprintf(stderr, "FAIL %s: %v\n", path, chainError(path, err))
			return Failed
		}
		fmt.Fprintln(stderr, "authz audit query:", strings.TrimPrefix(err.Error(), "audit: "))
		return Usage
	}
	var b strings.Builder
	fmt.Fprintf(&b, "authz audit query: %d of %d records matched", res.Matched, res.Records)
	switch {
	case res.Stopped:
		fmt.Fprintf(&b, "; stopped at the limit after reading %d", res.Read)
	case res.Skipped > 0:
		fmt.Fprintf(&b, "; %d read with the chain checked, %d outside the times skipped by the time index (authz audit verify reads them)", res.Read, res.Skipped)
	default:
		fmt.Fprintf(&b, "; chain checked, head %s", res.Head)
	}
	fmt.Fprintln(stderr, b.String())
	return OK
}
