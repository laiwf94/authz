package testbody

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// FileResult is the comparison of one old test file with its new home.
type FileResult struct {
	Pair
	// Changes lists the body lines that differ and are not allowed. Empty
	// for a clean move.
	Changes []Change
	// Allowed lists the differing lines an allow list accepted.
	Allowed []Change
	// OldTests and NewTests are the test functions on each side.
	OldTests, NewTests []string
	// OldPackage and NewPackage are the package clauses on each side.
	OldPackage, NewPackage string
}

// Clean reports whether the file moved with an unchanged body and the same
// tests. A file that is gone is never clean; an added file always is.
func (r FileResult) Clean() bool {
	if r.Old == "" {
		return true
	}
	return r.New != "" && len(r.Changes) == 0 && equal(r.OldTests, r.NewTests)
}

// PackageCount is the test count of one old package directory before the
// move and of the same tests after it.
type PackageCount struct {
	OldDir string
	// NewDirs are the directories the package's test files moved to.
	NewDirs []string
	// Before counts the test functions in the old directory, Moved counts
	// those still present in the files they moved to, and Added counts the
	// tests in files added to the new directories since.
	Before, Moved, Added int
	// Missing lists old tests not found after the move, as "file: Name".
	Missing []string
}

// OK reports whether every test of the package survived the move.
func (c PackageCount) OK() bool { return c.Before == c.Moved && len(c.Missing) == 0 }

// Report is the outcome of comparing two trees.
type Report struct {
	Files    []FileResult
	Packages []PackageCount
	// Stale lists allow-list entries that matched no change.
	Stale []Allowed
}

// OK reports whether every old test file moved cleanly and every package
// kept its tests.
func (r *Report) OK() bool {
	if len(r.Stale) > 0 {
		return false
	}
	for _, f := range r.Files {
		if !f.Clean() {
			return false
		}
	}
	for _, p := range r.Packages {
		if !p.OK() {
			return false
		}
	}
	return true
}

// Compare reads each pair from the old and new trees and compares them.
func Compare(pairs []Pair, readOld, readNew func(path string) ([]byte, error)) (*Report, error) {
	rep := &Report{}
	newTests := map[string]int{} // new dir -> tests in added files
	for _, p := range pairs {
		res := FileResult{Pair: p}
		var oldF, newF *File
		if p.Old != "" {
			src, err := readOld(p.Old)
			if err != nil {
				return nil, fmt.Errorf("old %s: %w", p.Old, err)
			}
			if oldF, err = Parse(p.Old, src); err != nil {
				return nil, fmt.Errorf("old %w", err)
			}
			res.OldTests, res.OldPackage = oldF.Tests, oldF.Package
		}
		if p.New != "" {
			src, err := readNew(p.New)
			if err != nil {
				return nil, fmt.Errorf("new %s: %w", p.New, err)
			}
			if newF, err = Parse(p.New, src); err != nil {
				return nil, fmt.Errorf("new %w", err)
			}
			res.NewTests, res.NewPackage = newF.Tests, newF.Package
		}
		if oldF != nil && newF != nil {
			res.Changes = Diff(oldF.Body, newF.Body)
		}
		if p.Old == "" {
			newTests[path.Dir(p.New)] += len(res.NewTests)
		}
		rep.Files = append(rep.Files, res)
	}

	byDir := map[string]*PackageCount{}
	var dirs []string
	for _, f := range rep.Files {
		if f.Old == "" {
			continue
		}
		dir := path.Dir(f.Old)
		pc := byDir[dir]
		if pc == nil {
			pc = &PackageCount{OldDir: dir}
			byDir[dir] = pc
			dirs = append(dirs, dir)
		}
		pc.Before += len(f.OldTests)
		have := map[string]int{}
		for _, t := range f.NewTests {
			have[t]++
		}
		for _, t := range f.OldTests {
			if have[t] > 0 {
				have[t]--
				pc.Moved++
			} else {
				pc.Missing = append(pc.Missing, f.Old+": "+t)
			}
		}
		if f.New != "" {
			nd := path.Dir(f.New)
			if !contains(pc.NewDirs, nd) {
				pc.NewDirs = append(pc.NewDirs, nd)
			}
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		pc := byDir[d]
		sort.Strings(pc.NewDirs)
		for _, nd := range pc.NewDirs {
			pc.Added += newTests[nd]
		}
		rep.Packages = append(rep.Packages, *pc)
	}
	return rep, nil
}

// maxShown bounds the changed lines printed per file.
const maxShown = 40

// Write prints the per-file results and the per-package test counts. With
// verbose it lists clean and added files too; otherwise only problems and
// the totals.
func (r *Report) Write(w io.Writer, verbose bool) {
	var clean, changed, gone, added, lines, allowed int
	for _, f := range r.Files {
		switch {
		case f.Old == "":
			added++
			if verbose {
				fmt.Fprintf(w, "added   %s (%d tests)\n", f.New, len(f.NewTests))
			}
		case f.New == "":
			gone++
			fmt.Fprintf(w, "GONE    %s (%d tests)\n", f.Old, len(f.OldTests))
		case f.Clean():
			clean++
			allowed += len(f.Allowed)
			if verbose || len(f.Allowed) > 0 {
				note := ""
				if len(f.Allowed) > 0 {
					note = fmt.Sprintf(" (%d allowed line(s))", len(f.Allowed))
				}
				fmt.Fprintf(w, "clean   %s -> %s%s%s\n", f.Old, f.New, pkgNote(f), note)
			}
			if verbose {
				writeChanges(w, f, f.Allowed)
			}
		default:
			changed++
			lines += len(f.Changes)
			allowed += len(f.Allowed)
			fmt.Fprintf(w, "CHANGED %s -> %s%s: %d line(s)\n", f.Old, f.New, pkgNote(f), len(f.Changes))
			writeChanges(w, f, f.Changes)
			if !equal(f.OldTests, f.NewTests) {
				fmt.Fprintf(w, "        tests: %s -> %s\n", strings.Join(f.OldTests, " "), strings.Join(f.NewTests, " "))
			}
		}
	}

	for _, a := range r.Stale {
		fmt.Fprintf(w, "STALE   allow entry on line %d matches no change: %s\n", a.Line, a)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Test functions per package (Test, Benchmark, Fuzz, Example):")
	tw := 0
	for _, p := range r.Packages {
		tw = max(tw, len(p.OldDir))
	}
	var before, moved, addedTests int
	for _, p := range r.Packages {
		mark := "ok  "
		if !p.OK() {
			mark = "FAIL"
		}
		to := strings.Join(p.NewDirs, ", ")
		if to == "" {
			to = "(gone)"
		}
		extra := ""
		if p.Added > 0 {
			extra = fmt.Sprintf(" (+%d in added files)", p.Added)
		}
		fmt.Fprintf(w, "%s %-*s %4d -> %4d  %s%s\n", mark, tw, p.OldDir, p.Before, p.Moved, to, extra)
		for _, m := range p.Missing {
			fmt.Fprintf(w, "     missing %s\n", m)
		}
		before += p.Before
		moved += p.Moved
		addedTests += p.Added
	}
	fmt.Fprintf(w, "\n%d file(s) clean, %d changed (%d line(s)), %d gone, %d added; %d allowed line(s), %d stale allow entr(ies)\n",
		clean, changed, lines, gone, added, allowed, len(r.Stale))
	fmt.Fprintf(w, "%d package(s): %d test(s) before, %d after the move, %d in added files\n",
		len(r.Packages), before, moved, addedTests)
}

func writeChanges(w io.Writer, f FileResult, changes []Change) {
	for i, c := range changes {
		if i == maxShown {
			fmt.Fprintf(w, "        ... %d more\n", len(changes)-maxShown)
			break
		}
		file := f.Old
		if c.Op == Insert {
			file = f.New
		}
		fmt.Fprintf(w, "        %c %s:%d: %s\n", c.Op, file, c.Line.N, c.Line.Text)
	}
}

func pkgNote(f FileResult) string {
	if f.OldPackage == f.NewPackage {
		return ""
	}
	return fmt.Sprintf(" [package %s -> %s]", f.OldPackage, f.NewPackage)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
