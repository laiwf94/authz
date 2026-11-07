//go:build ignore

// testbody-diff proves that the week 1 moves changed nothing in any test
// file but its import block and package clause. Run it through
// scripts/testbody-diff.sh, which adds the default revisions.
//
//	go run scripts/testbody-diff.go [-v] [-allow FILE] [-merge FILE] BASE [HEAD]
//
// Every _test.go file of BASE is paired with its path in HEAD (an entry of
// the -merge list, git's rename detection, or the same path) and compared outside its imports and package
// clause, declaration by declaration (see internal/testbody). It then prints
// the test functions per old package before and after the move. It exits 0
// when every old test file is still there with its old declarations and
// tests unchanged, 1 when one is not, and 2 on a usage or git error. HEAD defaults to HEAD; -v
// also lists clean and added files. -allow names a list of changed lines a
// move had to make (testbody.ParseAllow); an entry that matches nothing fails
// the run too. -merge names a list of old test files paired explicitly with
// their new home (testbody.ParseMerges), for packages that collapsed into
// one; an entry whose files are not there fails the run with status 2.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/laiwf94/authz/internal/testbody"
)

func main() {
	verbose := flag.Bool("v", false, "list clean and added files too")
	allowFile := flag.String("allow", "", "file of changed lines the moves had to make")
	mergeFile := flag.String("merge", "", "file of old test files merged into one new file")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/testbody-diff.go [-v] [-allow FILE] [-merge FILE] BASE [HEAD]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 || flag.NArg() > 2 {
		flag.Usage()
		os.Exit(2)
	}
	base, head := flag.Arg(0), "HEAD"
	if flag.NArg() == 2 {
		head = flag.Arg(1)
	}
	for _, rev := range []string{base, head} {
		if _, err := git("rev-parse", "--verify", "--quiet", rev+"^{commit}"); err != nil {
			fail(2, fmt.Errorf("%s is not a commit here (a shallow clone needs fetch-depth: 0): %w", rev, err))
		}
	}

	oldFiles, err := files(base)
	if err != nil {
		fail(2, err)
	}
	newFiles, err := files(head)
	if err != nil {
		fail(2, err)
	}
	out, err := git("diff", "--find-renames", "--name-status", "-z", base, head, "--", "*_test.go")
	if err != nil {
		fail(2, err)
	}
	renames, err := testbody.ParseRenames(out)
	if err != nil {
		fail(2, fmt.Errorf("git diff: %w", err))
	}
	if *mergeFile != "" {
		f, err := os.Open(*mergeFile)
		if err != nil {
			fail(2, err)
		}
		merges, err := testbody.ParseMerges(f)
		f.Close()
		if err == nil {
			err = testbody.ApplyMerges(renames, merges, oldFiles, newFiles)
		}
		if err != nil {
			fail(2, fmt.Errorf("%s: %w", *mergeFile, err))
		}
	}
	pairs := testbody.Pairs(oldFiles, newFiles, renames)
	read := func(rev string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) { return git("show", rev+":"+p) }
	}
	rep, err := testbody.Compare(pairs, read(base), read(head))
	if err != nil {
		fail(2, err)
	}
	if *allowFile != "" {
		f, err := os.Open(*allowFile)
		if err != nil {
			fail(2, err)
		}
		list, err := testbody.ParseAllow(f)
		f.Close()
		if err != nil {
			fail(2, fmt.Errorf("%s: %w", *allowFile, err))
		}
		rep.Allow(list)
	}
	fmt.Printf("testbody-diff: %s..%s\n", short(base), short(head))
	rep.Write(os.Stdout, *verbose)
	if !rep.OK() {
		fmt.Fprintln(os.Stderr, "testbody-diff: test files changed outside import blocks and package clauses, tests went missing, or an allow entry is stale")
		os.Exit(1)
	}
}

func files(rev string) ([]string, error) {
	out, err := git("ls-tree", "-r", "-z", "--name-only", rev)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00"), nil
}

func short(rev string) string {
	out, err := git("rev-parse", "--short", rev)
	if err != nil {
		return rev
	}
	return strings.TrimSpace(string(out))
}

func git(args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func fail(code int, err error) {
	fmt.Fprintln(os.Stderr, "testbody-diff:", err)
	os.Exit(code)
}
