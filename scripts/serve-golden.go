//go:build ignore

// serve-golden plays the authorization API's end-to-end scenario
// (internal/authz/golden) against a server binary and compares the
// transcript with the recording, then runs examples/demo.sh, the README's
// walk-through, against a fresh server and compares its output too.
//
//	go run scripts/serve-golden.go [-update] [-keep DIR] -- COMMAND [ARG...]
//
// COMMAND is started once per phase with GRANTD_* variables set, e.g.
// `/tmp/authz serve`. The recordings were made from the grantd binary built
// at 41d9bf0, the last commit before the move, with -update, and -keep wrote
// the data directory that grantd left after the fresh phase into
// internal/authz/golden/testdata/grantd-data, which the tests restart
// `authz serve` on. It exits 0 when both match, 1 when either differs and 2
// on a usage or setup error.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/laiwf94/authz/internal/authz/golden"
)

const (
	transcriptFile = "internal/authz/golden/testdata/serve.golden"
	demoFile       = "internal/authz/golden/testdata/demo.golden"
)

func main() {
	update := flag.Bool("update", false, "write the recordings instead of comparing")
	keep := flag.String("keep", "", "copy the data directory after the fresh phase into `DIR`")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/serve-golden.go [-update] [-keep DIR] -- COMMAND [ARG...]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	start := golden.Exec(flag.Args()...)

	data, err := os.MkdirTemp("", "serve-golden-")
	if err != nil {
		fail(2, err)
	}
	defer os.RemoveAll(data)
	var opt golden.Options
	if *keep != "" {
		opt.AfterFresh = func(dir string) error { return copyDir(dir, *keep) }
	}
	got, err := golden.Run(start, data, opt)
	if err != nil {
		os.Stderr.Write(got)
		fail(1, err)
	}
	failed := compare(transcriptFile, got, *update)

	// The README's walk-through, in memory, as an operator runs it.
	srv, err := start(golden.Env("127.0.0.1:0", ""))
	if err != nil {
		fail(1, err)
	}
	cmd := exec.Command("bash", "examples/demo.sh")
	cmd.Env = append(os.Environ(), "GRANTD_URL="+srv.URL, "GRANTD_API_KEY="+golden.APIKey)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	runErr := cmd.Run()
	if _, err := srv.Stop(); err != nil {
		fail(1, err)
	}
	if runErr != nil {
		os.Stderr.Write(out.Bytes())
		fail(1, fmt.Errorf("examples/demo.sh: %v", runErr))
	}
	if compare(demoFile, out.Bytes(), *update) {
		failed = true
	}
	if failed {
		os.Exit(1)
	}
}

func compare(path string, got []byte, update bool) (failed bool) {
	if update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			fail(2, err)
		}
		fmt.Printf("%s: written (%d bytes)\n", path, len(got))
		return false
	}
	want, err := os.ReadFile(path)
	if err != nil {
		fail(2, err)
	}
	if d := golden.Diff(want, got); d != "" {
		fmt.Printf("%s: differs at %s\n", path, d)
		return true
	}
	fmt.Printf("%s: matches (%d bytes)\n", path, len(got))
	return false
}

func copyDir(from, to string) error {
	if err := os.MkdirAll(to, 0o755); err != nil {
		return err
	}
	ents, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			return fmt.Errorf("%s: not a regular file", e.Name())
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func fail(code int, err error) {
	fmt.Fprintln(os.Stderr, "serve-golden:", err)
	os.Exit(code)
}
