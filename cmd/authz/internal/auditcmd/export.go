package auditcmd

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// exportCmd is "authz audit export": it checks the log and its checkpoint
// as verify -key does, hands the checkpoint out and records it as exported
// beside the log, so that the writers' retention may remove the segments
// it covers.
func exportCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	key := fs.String("key", "", "public key the checkpoint is signed with, or a file holding it")
	cpPath := fs.String("checkpoint", "", "signed checkpoint to export (default FILE.checkpoint)")
	outPath := fs.String("out", "", "file to write the checkpoint to (default standard output)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() != 1 || *key == "" {
		fmt.Fprintln(stderr, "usage: authz audit export -key KEY [-checkpoint NOTE] [-out FILE] FILE")
		return Usage
	}
	path := fs.Arg(0)
	v, err := readVerifier(*key)
	if err != nil {
		fmt.Fprintln(stderr, "authz audit export: -key:", err)
		return Usage
	}
	if *cpPath == "" {
		*cpPath = audit.CheckpointPath(path)
	}
	msg, err := os.ReadFile(*cpPath)
	if err != nil {
		fmt.Fprintln(stderr, "authz audit export:", err)
		return Usage
	}
	cp, err := audit.OpenCheckpoint(msg, v)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL %s: checkpoint %s: %s\n", path, *cpPath, strings.TrimPrefix(err.Error(), "audit: "))
		return Failed
	}
	// Only a checkpoint of this log, as it is on disk, is exported.
	var out bytes.Buffer
	cr, code := check("authz", path, "", audit.Default(), &out, stderr)
	if code != OK {
		stderr.Write(out.Bytes())
		return code
	}
	if err := cr.Covers(cp); err != nil {
		fmt.Fprintf(stderr, "FAIL %s: checkpoint %s: %v\n", path, *cpPath, err)
		return Failed
	}
	// The checkpoint leaves first: it is recorded as exported only once
	// it was written where the caller asked.
	if *outPath != "" {
		f, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			fmt.Fprintln(stderr, "authz audit export:", err)
			return Usage
		}
		_, werr := f.Write(msg)
		if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
			os.Remove(*outPath)
			fmt.Fprintln(stderr, "authz audit export:", err)
			return Usage
		}
	} else if _, err := stdout.Write(msg); err != nil {
		fmt.Fprintln(stderr, "authz audit export:", err)
		return Usage
	}
	if err := audit.MarkExported(path, msg, v); err != nil {
		fmt.Fprintln(stderr, "authz audit export:", strings.TrimPrefix(err.Error(), "audit: "))
		return Failed
	}
	fmt.Fprintf(stderr, "OK %s: checkpoint of %d records signed by %s at %s recorded as exported in %s\n",
		path, cp.Size, cp.Origin, cp.Time.Format(time.RFC3339), audit.ExportedPath(path))
	return OK
}
