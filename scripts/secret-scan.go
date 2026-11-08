//go:build ignore

// secret-scan fails every test whose output, logs or audit records carry a
// key, token or password. It reads `go test -json` from standard input, run
// with -tags secretscan so every log line and audit record the platform
// writes is scanned in the test process (internal/platform/logging,
// secretscan.go) and each finding is printed as a logging.ScanMarker line:
//
//	go test -tags secretscan -json ./... | go run scripts/secret-scan.go -allow scripts/secretscan-allow.txt
//
// It also scans every line of test output itself (t.Log, and what the code
// under test writes to stdout and stderr) with logging.Scan. A finding is
// attributed to the test go test attributes the line to. -allow names a
// file of "PACKAGE TEST RULE" lines (TEST may be "*") for output whose job
// is to carry such a value; an entry that matches nothing fails the run, so
// the list cannot go stale. It prints the output of failed tests and the
// package summaries, and exits 1 when a test failed, a finding is not
// allowed or an allow entry is unused, 2 on a usage or input error.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/laiwf94/authz/internal/platform/logging"
)

type event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

type allowEntry struct {
	pkg, test, rule string
	used            bool
}

type finding struct {
	pkg, test, rule, where, excerpt string
}

func main() {
	allowPath := flag.String("allow", "", "file of allowed findings: PACKAGE TEST RULE")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: go test -tags secretscan -json ./... | go run scripts/secret-scan.go [-allow FILE]")
		os.Exit(2)
	}
	var allow []*allowEntry
	if *allowPath != "" {
		var err error
		if allow, err = readAllow(*allowPath); err != nil {
			fmt.Fprintln(os.Stderr, "secret-scan:", err)
			os.Exit(2)
		}
	}
	code, err := run(os.Stdin, os.Stdout, allow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secret-scan:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func readAllow(path string) ([]*allowEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*allowEntry
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("%s:%d: want PACKAGE TEST RULE", path, i+1)
		}
		known := false
		for _, r := range logging.Rules() {
			known = known || r == f[2]
		}
		if !known {
			return nil, fmt.Errorf("%s:%d: unknown rule %q", path, i+1, f[2])
		}
		out = append(out, &allowEntry{pkg: f[0], test: f[1], rule: f[2]})
	}
	return out, nil
}

func run(r io.Reader, w io.Writer, allow []*allowEntry) (int, error) {
	type key struct{ pkg, test string }
	outputs := map[key]*strings.Builder{}
	var findings []finding
	failed, events := 0, 0
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	for {
		var e event
		if err := dec.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			return 0, fmt.Errorf("reading go test -json: %w", err)
		}
		events++
		k := key{e.Package, e.Test}
		switch e.Action {
		case "output":
			b := outputs[k]
			if b == nil {
				b = &strings.Builder{}
				outputs[k] = b
			}
			b.WriteString(e.Output)
		case "pass", "skip", "fail":
			b := outputs[k]
			delete(outputs, k)
			text := ""
			if b != nil {
				text = b.String()
			}
			findings = append(findings, scan(e.Package, e.Test, text)...)
			if e.Action == "fail" {
				failed++
				fmt.Fprint(w, text)
			} else if e.Test == "" {
				fmt.Fprint(w, lastLine(text))
			}
		}
	}
	if events == 0 {
		return 0, fmt.Errorf("no go test -json events on standard input")
	}
	// Output never closed by an action (a crashed test binary).
	for k, b := range outputs {
		findings = append(findings, scan(k.pkg, k.test, b.String())...)
	}

	var bad []finding
	for _, f := range findings {
		ok := false
		for _, a := range allow {
			if a.pkg == f.pkg && (a.test == "*" || a.test == f.test) && a.rule == f.rule {
				a.used, ok = true, true
			}
		}
		if !ok {
			bad = append(bad, f)
		}
	}
	sort.Slice(bad, func(i, j int) bool {
		if bad[i].pkg != bad[j].pkg {
			return bad[i].pkg < bad[j].pkg
		}
		return bad[i].test < bad[j].test
	})
	for _, f := range bad {
		fmt.Fprintf(w, "secret in %s %s: %s: %s: %s\n", f.pkg, f.test, f.where, f.rule, f.excerpt)
	}
	stale := 0
	for _, a := range allow {
		if !a.used {
			stale++
			fmt.Fprintf(w, "allow entry matched nothing: %s %s %s\n", a.pkg, a.test, a.rule)
		}
	}
	fmt.Fprintf(w, "secret scan: %d finding(s), %d allowed entr(ies), %d stale, %d failed test(s)\n",
		len(bad), len(allow)-stale, stale, failed)
	if len(bad) > 0 || stale > 0 || failed > 0 {
		return 1, nil
	}
	return 0, nil
}

// scan reads the findings the test process printed and scans the rest of
// the test's output itself.
func scan(pkg, test, text string) []finding {
	var out []finding
	var rest strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		if i := strings.Index(line, logging.ScanMarker); i >= 0 {
			// "SECRET-SCAN: <source> <rule>: <excerpt>"
			f := strings.Fields(strings.TrimSpace(line[i+len(logging.ScanMarker):]))
			if len(f) >= 2 {
				out = append(out, finding{pkg: pkg, test: test, where: f[0],
					rule: strings.TrimSuffix(f[1], ":"), excerpt: strings.Join(f[2:], " ")})
				continue
			}
		}
		rest.WriteString(line)
	}
	for _, f := range logging.Scan([]byte(rest.String())) {
		out = append(out, finding{pkg: pkg, test: test, where: fmt.Sprintf("output line %d", f.Line),
			rule: f.Rule, excerpt: f.Excerpt})
	}
	return out
}

func lastLine(s string) string {
	s = strings.TrimRight(s, "\n")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return ""
	}
	return s + "\n"
}
