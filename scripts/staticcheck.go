//go:build ignore

// staticcheck runs staticcheck over the module and fails on every finding
// that scripts/staticcheck-allow.txt does not list. Run it through
// scripts/staticcheck.sh, which pins the staticcheck version and the Go
// toolchain.
//
//	go run scripts/staticcheck.go [-allow FILE] -- STATICCHECK [ARGS...]
//
// STATICCHECK is the staticcheck binary and its arguments, for example
// `staticcheck ./...`; -f json is added in front of the arguments. The
// allow list may only name _test.go files, and only lines whose text is
// unchanged since the entry was written (gate.ParseLintAllow): the week 1
// moves froze the bodies of the moved test files, so a finding in one of them
// is listed rather than fixed until the freeze ends. Any other finding, any
// compile error and any allow entry that matches nothing fail the run.
// Exit status: 0 clean, 1 findings or stale entries, 2 usage or run error.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/laiwf94/authz/internal/gate"
)

func main() {
	allowPath := flag.String("allow", "", "allow list of accepted findings in test files")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/staticcheck.go [-allow FILE] -- STATICCHECK [ARGS...]")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	var allow []gate.LintAllowed
	if *allowPath != "" {
		f, err := os.Open(*allowPath)
		if err != nil {
			fail(err)
		}
		allow, err = gate.ParseLintAllow(f)
		f.Close()
		if err != nil {
			fail(fmt.Errorf("%s: %v", *allowPath, err))
		}
	}
	root, err := os.Getwd()
	if err != nil {
		fail(err)
	}

	cmd := exec.Command(args[0], append([]string{"-f", "json"}, args[1:]...)...)
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, os.Stderr
	runErr := cmd.Run()
	var exit *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exit) && exit.ExitCode() == 1:
		// staticcheck exits 1 when it reports findings.
	default:
		fail(fmt.Errorf("%s: %v", strings.Join(args, " "), runErr))
	}
	findings, err := gate.ParseFindings(&stdout, root)
	if err != nil {
		fail(err)
	}
	if runErr != nil && len(findings) == 0 {
		fail(fmt.Errorf("%s exited 1 without a finding", args[0]))
	}

	rejected, accepted, stale := gate.FilterLint(findings, allow)
	for _, f := range rejected {
		fmt.Println(f)
	}
	for _, a := range stale {
		fmt.Printf("%s:%d: allow entry matches no finding: %s\n", *allowPath, a.Line, a)
	}
	fmt.Printf("staticcheck: %d finding(s), %d allowed in frozen test files, %d stale allow entr(ies)\n",
		len(rejected), len(accepted), len(stale))
	if len(rejected) > 0 || len(stale) > 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "staticcheck:", err)
	os.Exit(2)
}
