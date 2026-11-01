//go:build ignore

// suite-counts checks that a test suite still runs every case it ran before
// a move. It reads `go test -json` on standard input and compares the passed
// tests, subtests and fuzz seeds with a baseline file (see
// internal/suitecount).
//
//	set -o pipefail
//	go test -json ./internal/authn/... | go run scripts/suite-counts.go BASELINE
//
// It prints the attack, property, fuzz and unit case counts and exits 0 when
// every baseline case passed, 1 when one did not or a package failed, and 2
// on a usage or read error. -map old=new rewrites package paths in the
// baseline and the run (the longest prefix wins), so a baseline recorded in
// the old tree can be checked against the new one. -write records the
// baseline from the run instead, applying the same mappings; the cases it
// writes are the passed ones. -v lists every added case.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/laiwf94/authz/internal/importrewrite"
	"github.com/laiwf94/authz/internal/suitecount"
)

type mapsFlag []importrewrite.Mapping

func (m *mapsFlag) String() string {
	parts := make([]string, len(*m))
	for i, mp := range *m {
		parts[i] = mp.From + "=" + mp.To
	}
	return strings.Join(parts, ", ")
}

func (m *mapsFlag) Set(s string) error {
	mp, err := importrewrite.ParseMapping(s)
	if err != nil {
		return err
	}
	*m = append(*m, mp)
	return nil
}

func main() {
	var maps mapsFlag
	write := flag.Bool("write", false, "record BASELINE from the run instead of comparing")
	header := flag.String("header", "", "comment written at the top of the baseline with -write")
	verbose := flag.Bool("v", false, "list every case added since the baseline")
	flag.Var(&maps, "map", "old=new package path prefix (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go test -json PKGS | go run scripts/suite-counts.go [-v] [-write [-header text]] [-map old=new ...] BASELINE")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	var rw *importrewrite.Rewriter
	if len(maps) > 0 {
		var err error
		if rw, err = importrewrite.New(maps...); err != nil {
			fail(2, err)
		}
	}
	mapPkg := func(p string) string {
		if rw == nil {
			return p
		}
		np, _ := rw.Path(p)
		return np
	}

	run, err := suitecount.Read(os.Stdin)
	if err != nil {
		fail(2, fmt.Errorf("reading go test -json: %w", err))
	}
	mapped := &suitecount.Run{Cases: map[suitecount.Case]suitecount.Status{}}
	for c, s := range run.Cases {
		mapped.Cases[suitecount.Case{Package: mapPkg(c.Package), Name: c.Name}] = s
	}
	for _, p := range run.Failed {
		mapped.Failed = append(mapped.Failed, mapPkg(p))
	}

	if *write {
		if len(mapped.Failed) > 0 {
			fail(1, fmt.Errorf("not recording a baseline from a failing run: %s", strings.Join(mapped.Failed, ", ")))
		}
		passed := mapped.Passed()
		if len(passed) == 0 {
			fail(1, fmt.Errorf("no passed cases in the input"))
		}
		var buf bytes.Buffer
		if err := suitecount.Format(&buf, *header, passed); err != nil {
			fail(2, err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			fail(2, err)
		}
		fmt.Fprintf(os.Stderr, "suite-counts: wrote %d case(s) to %s\n", len(passed), path)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		fail(2, err)
	}
	base, err := suitecount.Parse(f)
	f.Close()
	if err != nil {
		fail(2, fmt.Errorf("%s: %w", path, err))
	}
	for i := range base {
		base[i].Package = mapPkg(base[i].Package)
	}
	rep := suitecount.Compare(base, mapped)
	rep.Write(os.Stdout, *verbose)
	if !rep.OK() {
		fmt.Fprintf(os.Stderr, "suite-counts: %d baseline case(s) missing, %d package(s) failed\n", len(rep.Missing), len(rep.Failed))
		os.Exit(1)
	}
}

func fail(code int, err error) {
	fmt.Fprintln(os.Stderr, "suite-counts:", err)
	os.Exit(code)
}
