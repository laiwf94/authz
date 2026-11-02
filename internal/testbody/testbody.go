// Package testbody proves that moving test files changed nothing but their
// import blocks and package clauses. It backs scripts/testbody-diff.sh,
// which compares every _test.go file of the pre-merge tree with its new
// home after the week 1 moves.
//
// The package clause and every import declaration (with its doc comment) are
// removed. What is left is compared declaration by declaration: every
// top-level declaration of the old file, with its doc comment, must be in the
// new file with the same key (its kind and name) and the same lines, and the
// comments and blank lines outside declarations must be the same apart from
// blank lines. Declarations added since are allowed, so the suites can grow
// after the move, except init and TestMain, which run before every old test.
// Test functions (Test, Benchmark, Fuzz and Example, not TestMain) are
// counted from the syntax tree, so the old tree does not have to build.
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

// Line is one line of a file with its line number in the original file.
type Line struct {
	N    int
	Text string
}

// Decl is one top-level declaration other than an import, with its doc
// comment.
type Decl struct {
	// Key names the declaration: "func Name", "method Recv.Name", or the
	// token and spec names of a const, var or type declaration, such as
	// "var a,b".
	Key   string
	Lines []Line
}

// File is a parsed test file.
type File struct {
	// Package is the name in the package clause.
	Package string
	// Decls are the top-level declarations other than imports, in source
	// order.
	Decls []Decl
	// Outside holds the non-blank lines outside the package clause, the
	// import declarations and Decls: build constraints, the package doc
	// and free-standing comments.
	Outside []Line
	// Tests lists the top-level test, benchmark, fuzz and example functions
	// in source order.
	Tests []string
}

// Parse reduces a Go source file to its declarations and lists its tests.
func Parse(name string, src []byte) (*File, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	line := func(p token.Pos) int { return fset.Position(p).Line }

	lines := strings.Split(string(src), "\n")
	// A file ending in a newline splits into a final empty element that is
	// not a line.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	text := func(n int) string { return strings.TrimSuffix(lines[n-1], "\r") }

	used := map[int]bool{}
	span := func(from, to token.Pos) []Line {
		var out []Line
		for n := line(from); n <= line(to); n++ {
			used[n] = true
			out = append(out, Line{N: n, Text: text(n)})
		}
		return out
	}
	span(f.Package, f.Name.End())

	out := &File{Package: f.Name.Name}
	for _, d := range f.Decls {
		var doc *ast.CommentGroup
		var key string
		switch d := d.(type) {
		case *ast.GenDecl:
			doc = d.Doc
			if d.Tok == token.IMPORT {
				key = ""
				break
			}
			key = d.Tok.String() + " " + specNames(d)
		case *ast.FuncDecl:
			doc = d.Doc
			if d.Recv != nil && len(d.Recv.List) > 0 {
				key = "method " + types(d.Recv.List[0].Type) + "." + d.Name.Name
			} else {
				key = "func " + d.Name.Name
				if IsTestName(d.Name.Name) && d.Name.Name != "TestMain" {
					out.Tests = append(out.Tests, d.Name.Name)
				}
			}
		default:
			key = fmt.Sprintf("decl %T", d)
		}
		start := d.Pos()
		if doc != nil {
			start = doc.Pos()
		}
		ls := span(start, d.End())
		if key != "" {
			out.Decls = append(out.Decls, Decl{Key: key, Lines: ls})
		}
	}
	for i := range lines {
		n := i + 1
		if !used[n] && strings.TrimSpace(text(n)) != "" {
			out.Outside = append(out.Outside, Line{N: n, Text: text(n)})
		}
	}
	return out, nil
}

func specNames(d *ast.GenDecl) string {
	var names []string
	for _, s := range d.Specs {
		switch s := s.(type) {
		case *ast.TypeSpec:
			names = append(names, s.Name.Name)
		case *ast.ValueSpec:
			for _, n := range s.Names {
				names = append(names, n.Name)
			}
		}
	}
	return strings.Join(names, ",")
}

// types renders a receiver type: T, *T, T[K] or *T[K].
func types(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return "*" + types(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return types(e.X)
	case *ast.IndexListExpr:
		return types(e.X)
	case *ast.ParenExpr:
		return types(e.X)
	}
	return fmt.Sprintf("%T", e)
}

// runsFirst names the declarations that run before every test of the
// package, so adding one can change how the old tests behave.
var runsFirst = map[string]bool{"func init": true, "func TestMain": true}

// CompareFiles returns the lines in which the new file differs from the old
// one outside imports and the package clause, and the keys of the
// declarations it adds. A declaration that changed gives its line diff, one
// that is gone gives all its lines as deletions, and an added init or
// TestMain gives all its lines as insertions. Declarations with the same
// key (several init functions, var _ = ...) are paired in order.
func CompareFiles(old, new *File) (changes []Change, added []string) {
	byKey := map[string][]int{}
	for i, d := range new.Decls {
		byKey[d.Key] = append(byKey[d.Key], i)
	}
	paired := make([]bool, len(new.Decls))
	for _, d := range old.Decls {
		idx := byKey[d.Key]
		if len(idx) == 0 {
			changes = append(changes, Diff(d.Lines, nil)...)
			continue
		}
		byKey[d.Key] = idx[1:]
		paired[idx[0]] = true
		changes = append(changes, Diff(d.Lines, new.Decls[idx[0]].Lines)...)
	}
	for i, d := range new.Decls {
		if paired[i] {
			continue
		}
		if runsFirst[d.Key] {
			changes = append(changes, Diff(nil, d.Lines)...)
		} else {
			added = append(added, d.Key)
		}
	}
	changes = append(changes, Diff(old.Outside, new.Outside)...)
	return changes, added
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
