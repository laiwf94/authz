// Package testbody proves that moving test files changed nothing but their
// import blocks and package clauses. It backs scripts/testbody-diff.sh,
// which compares every _test.go file of the pre-merge tree with its new
// home after the week 1 moves.
//
// Each file is reduced to its body: the lines of the package clause and of
// every import declaration (with the import's doc comment) are removed, and
// blank lines before the first other declaration are dropped, so regrouping
// imports does not count as a change. Everything else, comments included, is
// compared line by line. Test functions (Test, Benchmark, Fuzz and Example,
// not TestMain) are counted from the syntax tree, so the old tree does not
// have to build.
package testbody

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Line is one line of a file body with its line number in the original file.
type Line struct {
	N    int
	Text string
}

// File is a parsed test file.
type File struct {
	// Package is the name in the package clause.
	Package string
	// Body is every line outside the package clause and import blocks.
	Body []Line
	// Tests lists the top-level test, benchmark, fuzz and example functions
	// in source order.
	Tests []string
}

// Parse reduces a Go source file to its body and lists its tests.
func Parse(name string, src []byte) (*File, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	line := func(p token.Pos) int { return fset.Position(p).Line }

	removed := map[int]bool{}
	drop := func(from, to token.Pos) {
		for n := line(from); n <= line(to); n++ {
			removed[n] = true
		}
	}
	drop(f.Package, f.Name.End())
	header := -1 // last line before the first declaration that is not an import
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if ok && gd.Tok == token.IMPORT {
			start := gd.Pos()
			if gd.Doc != nil {
				start = gd.Doc.Pos()
			}
			drop(start, gd.End())
			continue
		}
		start := d.Pos()
		switch d := d.(type) {
		case *ast.GenDecl:
			if d.Doc != nil {
				start = d.Doc.Pos()
			}
		case *ast.FuncDecl:
			if d.Doc != nil {
				start = d.Doc.Pos()
			}
		}
		header = line(start) - 1
		break
	}
	lines := strings.Split(string(src), "\n")
	if header < 0 {
		// Nothing but imports: the whole file is header.
		header = len(lines)
	}
	// A file ending in a newline splits into a final empty element that is
	// not a line.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}

	out := &File{Package: f.Name.Name}
	for i, text := range lines {
		n := i + 1
		if removed[n] {
			continue
		}
		if n <= header && strings.TrimSpace(text) == "" {
			continue
		}
		out.Body = append(out.Body, Line{N: n, Text: strings.TrimSuffix(text, "\r")})
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name == "TestMain" {
			continue
		}
		if IsTestName(fd.Name.Name) {
			out.Tests = append(out.Tests, fd.Name.Name)
		}
	}
	return out, nil
}

// IsTestName reports whether go test treats a top-level function with this
// name as a test, benchmark, fuzz target or example: the prefix followed by
// nothing or by a character that is not a lower-case letter.
func IsTestName(name string) bool {
	for _, prefix := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if len(name) == len(prefix) {
			return true
		}
		r, _ := utf8.DecodeRuneInString(name[len(prefix):])
		return !unicode.IsLower(r)
	}
	return false
}

// Op is the kind of a changed line.
type Op byte

// Line operations in a diff.
const (
	Delete Op = '-'
	Insert Op = '+'
)

// Change is one line that is only in the old body (Delete) or only in the
// new one (Insert).
type Change struct {
	Op   Op
	Line Line
}

func (c Change) String() string {
	return fmt.Sprintf("%c%d: %s", c.Op, c.Line.N, c.Line.Text)
}

// maxCells bounds the table of the line diff. Past it the differing middle
// of the two bodies is reported whole, which over-reports but never hides a
// change.
const maxCells = 16 << 20

// Diff returns the lines that differ between two bodies, as a minimal
// sequence of deletions and insertions in file order. Equal bodies give nil.
func Diff(a, b []Line) []Change {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre].Text == b[pre].Text {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf].Text == b[len(b)-1-suf].Text {
		suf++
	}
	a, b = a[pre:len(a)-suf], b[pre:len(b)-suf]
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	var out []Change
	if (len(a)+1)*(len(b)+1) > maxCells {
		for _, l := range a {
			out = append(out, Change{Delete, l})
		}
		for _, l := range b {
			out = append(out, Change{Insert, l})
		}
		return out
	}
	// lcs[i][j] is the length of the longest common subsequence of a[i:]
	// and b[j:].
	w := len(b) + 1
	lcs := make([]int32, (len(a)+1)*w)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i].Text == b[j].Text {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else {
				lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i].Text == b[j].Text:
			i, j = i+1, j+1
		case j == len(b) || (i < len(a) && lcs[(i+1)*w+j] >= lcs[i*w+j+1]):
			out = append(out, Change{Delete, a[i]})
			i++
		default:
			out = append(out, Change{Insert, b[j]})
			j++
		}
	}
	return out
}

// Pair links a test file in the old tree to its path in the new one. New is
// empty when the file is gone; Old is empty when the file was added.
type Pair struct {
	Old, New string
}

// Pairs matches the test files of two trees. oldFiles and newFiles list
// every file of each tree; renames maps old paths to new ones as git's
// rename detection found them. A file that keeps its path and is not
// renamed pairs with itself. Only _test.go files are returned, old files
// first in path order, then added files in path order.
func Pairs(oldFiles, newFiles []string, renames map[string]string) []Pair {
	inNew := map[string]bool{}
	for _, p := range newFiles {
		inNew[p] = true
	}
	used := map[string]bool{}
	var out []Pair
	olds := testFiles(oldFiles)
	for _, p := range olds {
		to, ok := renames[p]
		if !ok && inNew[p] {
			to = p
		}
		if to != "" && !inNew[to] {
			to = ""
		}
		if to != "" {
			used[to] = true
		}
		out = append(out, Pair{Old: p, New: to})
	}
	for _, p := range testFiles(newFiles) {
		if !used[p] {
			out = append(out, Pair{New: p})
		}
	}
	return out
}

func testFiles(files []string) []string {
	var out []string
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// ParseRenames reads the output of `git diff -M --name-status -z` and
// returns the renames it lists, old path to new path.
func ParseRenames(out []byte) (map[string]string, error) {
	fields := strings.Split(string(out), "\x00")
	if n := len(fields); n > 0 && fields[n-1] == "" {
		fields = fields[:n-1]
	}
	renames := map[string]string{}
	for i := 0; i < len(fields); {
		status := fields[i]
		if status == "" {
			return nil, fmt.Errorf("empty status at field %d", i)
		}
		paths := 1
		if status[0] == 'R' || status[0] == 'C' {
			paths = 2
		}
		if i+paths >= len(fields) {
			return nil, fmt.Errorf("status %q: missing path", status)
		}
		if status[0] == 'R' {
			renames[fields[i+1]] = fields[i+2]
		}
		i += 1 + paths
	}
	return renames, nil
}
