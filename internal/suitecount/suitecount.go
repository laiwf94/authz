// Package suitecount proves that a test suite still runs every case it ran
// before a move. It reads the event stream of `go test -json`, keeps the
// final result of every test, subtest and fuzz seed, and compares the passed
// cases with a baseline recorded from the old tree.
//
// A baseline is a sorted text file with one case per line, the package
// import path and the full test name separated by a tab. A case in the
// baseline that did not pass (it failed, was skipped or is no longer there)
// fails the comparison. New cases are allowed and reported, so a suite can
// grow but never silently shrink.
//
// Cases are grouped by their top-level test name into the suites the roadmap
// names: attack (a name containing "Attack"), property (TestProperty*), fuzz
// (Fuzz*, whose subtests are the replayed seed corpus) and unit (the rest).
package suitecount

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Status is the final result of one case.
type Status string

// Results go test reports for a test.
const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Case names one test, subtest or fuzz seed.
type Case struct {
	Package string
	Name    string
}

// Suite returns the suite the case belongs to: attack, property, fuzz or
// unit, decided by its top-level test name.
func (c Case) Suite() string {
	top, _, _ := strings.Cut(c.Name, "/")
	switch {
	case strings.HasPrefix(top, "Fuzz"):
		return "fuzz"
	case strings.HasPrefix(top, "TestProperty"):
		return "property"
	case strings.Contains(top, "Attack"):
		return "attack"
	default:
		return "unit"
	}
}

// Suites lists the suite names in report order.
var Suites = []string{"attack", "property", "fuzz", "unit"}

// Run is the outcome of one `go test -json` stream.
type Run struct {
	// Cases holds the final status of every case that reported one.
	Cases map[Case]Status
	// Failed lists packages that failed as a whole: a build failure, a
	// failing test, a panic or a timeout. Sorted.
	Failed []string
}

// event is the subset of test2json's TestEvent this package reads.
type event struct {
	Action     string
	Package    string
	Test       string
	ImportPath string
}

// Read parses a `go test -json` stream. Lines that are not JSON objects (a
// build error printed by an older toolchain, say) are ignored, because the
// package result that follows them is what matters.
func Read(r io.Reader) (*Run, error) {
	run := &Run{Cases: map[Case]Status{}}
	failed := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		switch e.Action {
		case "build-fail":
			failed[e.ImportPath] = true
		case string(Pass), string(Fail), string(Skip):
			if e.Package == "" {
				continue
			}
			if e.Test == "" {
				if e.Action == string(Fail) {
					failed[e.Package] = true
				}
				continue
			}
			run.Cases[Case{e.Package, e.Test}] = Status(e.Action)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for p := range failed {
		run.Failed = append(run.Failed, p)
	}
	sort.Strings(run.Failed)
	return run, nil
}

// Passed returns the cases that passed, sorted.
func (r *Run) Passed() []Case {
	var out []Case
	for c, s := range r.Cases {
		if s == Pass {
			out = append(out, c)
		}
	}
	sortCases(out)
	return out
}

func sortCases(cs []Case) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Package != cs[j].Package {
			return cs[i].Package < cs[j].Package
		}
		return cs[i].Name < cs[j].Name
	})
}

// Format writes cases as a baseline file under a comment header.
func Format(w io.Writer, header string, cases []Case) error {
	sorted := append([]Case(nil), cases...)
	sortCases(sorted)
	bw := bufio.NewWriter(w)
	for _, l := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
		if header == "" {
			break
		}
		fmt.Fprintf(bw, "# %s\n", l)
	}
	for _, c := range sorted {
		fmt.Fprintf(bw, "%s\t%s\n", c.Package, c.Name)
	}
	return bw.Flush()
}

// Parse reads a baseline file. Blank lines and lines starting with # are
// ignored; a duplicate or malformed line is an error.
func Parse(r io.Reader) ([]Case, error) {
	var out []Case
	seen := map[Case]bool{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pkg, name, ok := strings.Cut(line, "\t")
		if !ok || pkg == "" || name == "" || strings.ContainsAny(pkg, " \t") || strings.Contains(name, "\t") {
			return nil, fmt.Errorf("line %d: want \"package<TAB>test name\", got %q", n, line)
		}
		c := Case{pkg, name}
		if seen[c] {
			return nil, fmt.Errorf("line %d: duplicate case %s %s", n, pkg, name)
		}
		seen[c] = true
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("baseline has no cases")
	}
	return out, nil
}

// Missing is a baseline case that did not pass.
type Missing struct {
	Case
	// Status is fail or skip, or "" when the case did not run at all.
	Status Status
}

// Counts is the number of cases in one suite before and now.
type Counts struct {
	Baseline, Now int
}

// Report is the comparison of a run with a baseline.
type Report struct {
	Missing []Missing
	Added   []Case
	Failed  []string
	// Suites counts passed cases per suite, restricted to the packages the
	// baseline covers, so unrelated packages in the same run do not inflate
	// the numbers.
	Suites map[string]Counts
}

// OK reports whether every baseline case passed and no package failed.
func (r *Report) OK() bool { return len(r.Missing) == 0 && len(r.Failed) == 0 }

// Compare checks a run against a baseline.
func Compare(baseline []Case, run *Run) *Report {
	rep := &Report{Suites: map[string]Counts{}, Failed: append([]string(nil), run.Failed...)}
	inBase := map[Case]bool{}
	pkgs := map[string]bool{}
	for _, c := range baseline {
		inBase[c] = true
		pkgs[c.Package] = true
		n := rep.Suites[c.Suite()]
		n.Baseline++
		rep.Suites[c.Suite()] = n
		if s := run.Cases[c]; s != Pass {
			rep.Missing = append(rep.Missing, Missing{c, s})
		}
	}
	for _, c := range run.Passed() {
		if !pkgs[c.Package] {
			continue
		}
		n := rep.Suites[c.Suite()]
		n.Now++
		rep.Suites[c.Suite()] = n
		if !inBase[c] {
			rep.Added = append(rep.Added, c)
		}
	}
	sort.Slice(rep.Missing, func(i, j int) bool {
		a, b := rep.Missing[i].Case, rep.Missing[j].Case
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Name < b.Name
	})
	return rep
}

// Write prints the report: the per-suite table, then every missing case and
// the number of added ones (each listed when verbose is set).
func (r *Report) Write(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "%-9s %8s %8s\n", "suite", "baseline", "now")
	var tb, tn int
	for _, s := range Suites {
		c := r.Suites[s]
		tb += c.Baseline
		tn += c.Now
		fmt.Fprintf(w, "%-9s %8d %8d\n", s, c.Baseline, c.Now)
	}
	fmt.Fprintf(w, "%-9s %8d %8d\n", "total", tb, tn)
	for _, p := range r.Failed {
		fmt.Fprintf(w, "FAIL package %s\n", p)
	}
	for _, m := range r.Missing {
		why := "did not run"
		if m.Status != "" {
			why = string(m.Status)
		}
		fmt.Fprintf(w, "MISSING %s %s (%s)\n", m.Package, m.Name, why)
	}
	fmt.Fprintf(w, "%d case(s) added since the baseline\n", len(r.Added))
	if verbose {
		for _, c := range r.Added {
			fmt.Fprintf(w, "added %s %s\n", c.Package, c.Name)
		}
	}
}
