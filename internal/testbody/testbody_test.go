package testbody

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

const before = `// Copyright notice.

//go:build !windows

package main

import (
	"testing"

	"github.com/laiwf94/grantd/internal/store"
)

// helper is shared.
func helper() int { return 1 }

func TestA(t *testing.T) { _ = store.X }

func TestMain(m *testing.M) {}

func Testing(t *testing.T) {}

func BenchmarkB(b *testing.B) {}

func FuzzC(f *testing.F) {}

func Example() {}

func Example_second() {}

func (s suite) TestMethod(t *testing.T) {}
`

func keys(f *File) []string {
	var out []string
	for _, d := range f.Decls {
		out = append(out, d.Key)
	}
	return out
}

func TestParse(t *testing.T) {
	f, err := Parse("a_test.go", []byte(before))
	if err != nil {
		t.Fatal(err)
	}
	if f.Package != "main" {
		t.Errorf("package = %q", f.Package)
	}
	wantTests := []string{"TestA", "BenchmarkB", "FuzzC", "Example", "Example_second"}
	if !reflect.DeepEqual(f.Tests, wantTests) {
		t.Errorf("tests = %v, want %v", f.Tests, wantTests)
	}
	wantKeys := []string{"func helper", "func TestA", "func TestMain", "func Testing", "func BenchmarkB", "func FuzzC", "func Example", "func Example_second", "method suite.TestMethod"}
	if got := keys(f); !reflect.DeepEqual(got, wantKeys) {
		t.Errorf("keys = %v", got)
	}
	if got := f.Decls[0].Lines; !reflect.DeepEqual(got, []Line{{13, "// helper is shared."}, {14, "func helper() int { return 1 }"}}) {
		t.Errorf("helper lines = %v", got)
	}
	if want := []Line{{1, "// Copyright notice."}, {3, "//go:build !windows"}}; !reflect.DeepEqual(f.Outside, want) {
		t.Errorf("outside = %v", f.Outside)
	}
}

func TestParseKeys(t *testing.T) {
	src := `package p

import "testing"

const a, b = 1, 2

var (
	_ = 1
	c int
)

type (
	T[K any] struct{}
	U        int
)

func (T[K]) M()     {}
func (*U) N()       {}
func (u *(U)) O()   {}
func init()         {}
func TestX(*testing.T) {}
`
	f, err := Parse("p.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"const a,b", "var _,c", "type T,U", "method T.M", "method *U.N", "method *U.O", "func init", "func TestX"}
	if got := keys(f); !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
	if types(&ast.ArrayType{Elt: ast.NewIdent("x")}) != "*ast.ArrayType" {
		t.Error("types fallback")
	}
}

func TestMoveIsClean(t *testing.T) {
	// The package clause changes, the import path changes, the imports are
	// regrouped into two blocks with a comment, the blank lines around them
	// move and the line endings change: none of that is a body change.
	after := strings.Replace(before, "package main", "package serve // moved", 1)
	after = strings.Replace(after, `import (
	"testing"

	"github.com/laiwf94/grantd/internal/store"
)
`, `import "testing"


// store moved under internal/authz.
import (
	"github.com/laiwf94/authz/internal/authz/store"
)
`, 1)
	a, err := Parse("a", []byte(before))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("b", []byte(strings.ReplaceAll(after, "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if d, added := CompareFiles(a, b); d != nil || added != nil {
		t.Errorf("diff = %v, added = %v", d, added)
	}
	if b.Package != "serve" {
		t.Errorf("package = %q", b.Package)
	}
}

func TestBodyChanges(t *testing.T) {
	for name, tc := range map[string]struct {
		from, to string
		want     string
	}{
		"string literal":   {`store.X`, `store.Y`, "-16 +16"},
		"doc comment":      {`// helper is shared.`, `// helper is shared!`, "-13 +13"},
		"line inserted":    {"{ _ = store.X }", "{\n\tt.Skip()\n\t_ = store.X\n}", "-16 +16 +17 +18 +19"},
		"blank in a func":  {"func FuzzC(f *testing.F) {}", "func FuzzC(f *testing.F) {\n\n}", "-24 +24 +25 +26"},
		"build tag":        {`//go:build !windows`, `//go:build linux`, "-3 +3"},
		"free comment":     {"func Example() {}\n", "func Example() {}\n\n// stray\n", "+28"},
		"test removed":     {"func BenchmarkB(b *testing.B) {}\n", "", "-22"},
		"test renamed":     {"func BenchmarkB(", "func BenchmarkBB(", "-22"},
		"init added":       {"func Example() {}\n", "func Example() {}\n\nfunc init() { println() }\n", "+28"},
		"TestMain added":   {"func TestMain(m *testing.M) {}\n", "func TestMain(m *testing.M) {}\nfunc TestMain(m *testing.M) {}\n", "+19"},
		"moved and edited": {"func helper() int { return 1 }", "func helper() int { return 2 }", "-14 +14"},
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := Parse("a", []byte(before))
			b, err := Parse("b", []byte(strings.Replace(before, tc.from, tc.to, 1)))
			if err != nil {
				t.Fatal(err)
			}
			d, _ := CompareFiles(a, b)
			var got []string
			for _, c := range d {
				got = append(got, fmt.Sprintf("%c%d", c.Op, c.Line.N))
			}
			if g := strings.Join(got, " "); g != tc.want {
				t.Errorf("changes = %q, want %q (%v)", g, tc.want, d)
			}
		})
	}
}

func TestDeclarationsAdded(t *testing.T) {
	// New tests, helpers and types may follow the move, anywhere in the
	// file; old declarations may be reordered.
	after := strings.Replace(before, "func TestA(t *testing.T) { _ = store.X }\n", `// TestNew is new.
func TestNew(t *testing.T) { t.Log(helper2()) }

func helper2() int { return 2 }

type fixture struct{}

var _ = fixture{}
`, 1) + "\nfunc TestA(t *testing.T) { _ = store.X }\n"
	a, _ := Parse("a", []byte(before))
	b, err := Parse("b", []byte(after))
	if err != nil {
		t.Fatal(err)
	}
	d, added := CompareFiles(a, b)
	if d != nil {
		t.Errorf("changes = %v", d)
	}
	if want := []string{"func TestNew", "func helper2", "type fixture", "var _"}; !reflect.DeepEqual(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
}

func TestParseEdgeFiles(t *testing.T) {
	for name, src := range map[string]string{
		"package only": "package p\n",
		"imports only": "package p\n\nimport (\n\t\"testing\"\n)\n\nimport _ \"embed\"\n",
		"no newline":   "package p\nfunc TestX(t *testing.T) {}",
	} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(name, []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if f.Package != "p" || len(f.Outside) != 0 {
				t.Errorf("package = %q, outside = %v", f.Package, f.Outside)
			}
			if name == "no newline" && !reflect.DeepEqual(f.Decls, []Decl{{"func TestX", []Line{{2, "func TestX(t *testing.T) {}"}}}}) {
				t.Errorf("decls = %v", f.Decls)
			}
		})
	}
	if _, err := Parse("bad.go", []byte("package\n")); err == nil {
		t.Error("bad file parsed")
	}
}

func TestIsTestName(t *testing.T) {
	for name, want := range map[string]bool{
		"Test": true, "TestX": true, "Test_x": true, "Test1": true, "TestÄ": true,
		"Testing": false, "Testé": false, "Benchmark": true, "BenchmarkX": true, "Benchmarks": false,
		"Fuzz": true, "FuzzParse": true, "Fuzzy": false, "Example": true, "ExampleF_m": true,
		"Examples": false, "helper": false, "test": false,
	} {
		if got := IsTestName(name); got != want {
			t.Errorf("IsTestName(%q) = %v", name, got)
		}
	}
}

func lines(s string) []Line {
	var out []Line
	for i, f := range strings.Fields(s) {
		out = append(out, Line{N: i + 1, Text: f})
	}
	return out
}

func render(cs []Change) string {
	var parts []string
	for _, c := range cs {
		parts = append(parts, fmt.Sprintf("%c%d%s", c.Op, c.Line.N, c.Line.Text))
	}
	return strings.Join(parts, " ")
}

func TestDiff(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"a b c", "a b c", ""},
		{"", "", ""},
		{"a b c", "a x c", "-2b +2x"},
		{"a b c", "a b c d", "+4d"},
		{"a b c", "b c", "-1a"},
		{"a b c d e", "a c e f", "-2b -4d +4f"},
		{"x y", "", "-1x -2y"},
		{"", "x", "+1x"},
		{"a a a", "a a", "-3a"},
	} {
		if got := render(Diff(lines(tc.a), lines(tc.b))); got != tc.want {
			t.Errorf("Diff(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
	if (Change{Insert, Line{7, "x := 1"}}).String() != "+7: x := 1" {
		t.Error("Change.String")
	}
}

// TestPropertyDiffMinimal checks that the diff rebuilds b from a and is no
// longer than the edit distance of a random sequence of edits that made b.
func TestPropertyDiffMinimal(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for iter := 0; iter < 500; iter++ {
		var a []Line
		for i := 0; i < r.Intn(30); i++ {
			a = append(a, Line{N: i + 1, Text: string(rune('a' + r.Intn(4)))})
		}
		b := append([]Line(nil), a...)
		edits := r.Intn(6)
		for e := 0; e < edits; e++ {
			if len(b) > 0 && r.Intn(2) == 0 {
				i := r.Intn(len(b))
				b = append(b[:i], b[i+1:]...)
			} else {
				i := r.Intn(len(b) + 1)
				b = append(b[:i], append([]Line{{Text: string(rune('a' + r.Intn(5)))}}, b[i:]...)...)
			}
		}
		for i := range b {
			b[i].N = i + 1
		}
		d := Diff(a, b)
		if len(d) > edits {
			t.Fatalf("diff of %d edits has %d changes", edits, len(d))
		}
		// Apply: walk a, dropping deletions and splicing insertions.
		del := map[int]bool{}
		ins := map[int]bool{}
		for _, c := range d {
			if c.Op == Delete {
				del[c.Line.N] = true
			} else {
				ins[c.Line.N] = true
			}
		}
		var keptA, keptB []string
		for _, l := range a {
			if !del[l.N] {
				keptA = append(keptA, l.Text)
			}
		}
		for _, l := range b {
			if !ins[l.N] {
				keptB = append(keptB, l.Text)
			}
		}
		if !reflect.DeepEqual(keptA, keptB) {
			t.Fatalf("a %v b %v diff %s: common parts differ", a, b, render(d))
		}
	}
}

func TestDiffTooLarge(t *testing.T) {
	n := 5000
	a := make([]Line, n)
	b := make([]Line, n)
	for i := range a {
		a[i] = Line{i + 1, fmt.Sprint("a", i)}
		b[i] = Line{i + 1, fmt.Sprint("b", i)}
	}
	b[0], b[n-1] = a[0], a[n-1]
	d := Diff(a, b)
	if len(d) != 2*(n-2) {
		t.Fatalf("got %d changes, want the whole middle (%d)", len(d), 2*(n-2))
	}
	if d[0].Op != Delete || d[0].Line.N != 2 || d[len(d)-1].Op != Insert || d[len(d)-1].Line.N != n-1 {
		t.Errorf("bounds: %v ... %v", d[0], d[len(d)-1])
	}
}

func TestParseRenames(t *testing.T) {
	out := []byte("R097\x00old/a_test.go\x00new/a_test.go\x00M\x00m_test.go\x00D\x00gone_test.go\x00A\x00add_test.go\x00C075\x00c_test.go\x00c2_test.go\x00")
	got, err := ParseRenames(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"old/a_test.go": "new/a_test.go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("renames = %v", got)
	}
	if got, err := ParseRenames(nil); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"R100\x00only\x00", "M\x00", "\x00\x00x"} {
		if _, err := ParseRenames([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestPairs(t *testing.T) {
	old := []string{"a/x_test.go", "a/x.go", "b/y_test.go", "c/z_test.go", "d/w_test.go"}
	new := []string{"n/x_test.go", "b/y_test.go", "n/x.go", "e/new_test.go", "e/w_test.go"}
	renames := map[string]string{"a/x_test.go": "n/x_test.go", "d/w_test.go": "gone/w_test.go"}
	got := Pairs(old, new, renames)
	want := []Pair{
		{"a/x_test.go", "n/x_test.go"},
		{"b/y_test.go", "b/y_test.go"},
		{"c/z_test.go", ""},
		{"d/w_test.go", ""},
		{"", "e/new_test.go"},
		{"", "e/w_test.go"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pairs = %v\nwant    %v", got, want)
	}
}

const allowText = `# comment

new/x_test.go + path := filepath.Join("..", "..", "..", "fixtures")
old/x_test.go   -   path := filepath.Join("..", "..", "fixtures")
`

func TestParseAllow(t *testing.T) {
	got, err := ParseAllow(strings.NewReader(allowText))
	if err != nil {
		t.Fatal(err)
	}
	want := []Allowed{
		{File: "new/x_test.go", Op: Insert, Text: `path := filepath.Join("..", "..", "..", "fixtures")`, Line: 3},
		{File: "old/x_test.go", Op: Delete, Text: `path := filepath.Join("..", "..", "fixtures")`, Line: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allow = %+v", got)
	}
	if got[0].String() != `new/x_test.go + path := filepath.Join("..", "..", "..", "fixtures")` {
		t.Errorf("String = %q", got[0])
	}
	for _, bad := range []string{"file", "file +", "file * text", "file + ", "file ++ text"} {
		if _, err := ParseAllow(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if _, err := ParseAllow(strings.NewReader(strings.Repeat("x", 2<<20))); err == nil {
		t.Error("overlong line accepted")
	}
}

const (
	oldFixture = "package x\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tpath := filepath.Join(\"..\", \"..\", \"fixtures\")\n\t_ = path\n}\n\nfunc TestG(t *testing.T) {}\n"
	newFixture = "package x\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tpath := filepath.Join(\"..\", \"..\", \"..\", \"fixtures\")\n\t_ = path\n}\n\nfunc TestG(t *testing.T) {}\n"
)

func tree(files map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		s, ok := files[p]
		if !ok {
			return nil, errors.New("not found")
		}
		return []byte(s), nil
	}
}

func TestCompareAllow(t *testing.T) {
	pairs := []Pair{{"old/x_test.go", "new/x_test.go"}}
	read := func() (*Report, error) {
		return Compare(pairs, tree(map[string]string{"old/x_test.go": oldFixture}), tree(map[string]string{"new/x_test.go": newFixture}))
	}
	rep, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || len(rep.Files[0].Changes) != 2 {
		t.Fatalf("fixture change not reported: %+v", rep.Files[0])
	}
	list, _ := ParseAllow(strings.NewReader(allowText))
	if stale := rep.Allow(list); len(stale) != 0 {
		t.Errorf("stale = %v", stale)
	}
	if !rep.OK() || len(rep.Files[0].Allowed) != 2 {
		t.Fatalf("allowed change still fails: %+v", rep.Files[0])
	}
	var buf bytes.Buffer
	rep.Write(&buf, true)
	for _, want := range []string{"clean   old/x_test.go -> new/x_test.go (2 allowed line(s))", "- old/x_test.go:6:", "+ new/x_test.go:6:", "2 allowed line(s), 0 stale"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, buf.String())
		}
	}

	// An entry that matches nothing is stale and fails the report, and one
	// entry accepts only one line.
	rep, _ = read()
	extra := append(list, Allowed{File: "new/x_test.go", Op: Insert, Text: "unused", Line: 9}, list[0])
	if stale := rep.Allow(extra); len(stale) != 2 {
		t.Errorf("stale = %v", stale)
	}
	if rep.OK() {
		t.Error("stale entry passed")
	}
	buf.Reset()
	rep.Write(&buf, false)
	if !strings.Contains(buf.String(), "STALE   allow entry on line 9 matches no change: new/x_test.go + unused") {
		t.Errorf("output:\n%s", buf.String())
	}
}

func TestCompareCounts(t *testing.T) {
	oldTree := map[string]string{
		"p/a_test.go":    oldFixture,
		"p/b_test.go":    "package x\nfunc TestB(t *testing.T) {}\nfunc BenchmarkB(b *testing.B) {}\n",
		"q/gone_test.go": "package q\nfunc TestQ(t *testing.T) {}\n",
		"r/r_test.go":    "package main\nfunc TestR(t *testing.T) {}\nfunc TestS(t *testing.T) {}\n",
	}
	newTree := map[string]string{
		"n/a_test.go":   oldFixture,
		"m/b_test.go":   "package x\nfunc TestB(t *testing.T) {}\nfunc BenchmarkB(b *testing.B) {}\n",
		"n/new_test.go": "package x\nfunc TestNew(t *testing.T) {}\nfunc TestNew2(t *testing.T) {}\n",
		"r/r_test.go":   "package r\nfunc TestR(t *testing.T) {}\nfunc TestRenamed(t *testing.T) {}\n",
	}
	pairs := []Pair{
		{"p/a_test.go", "n/a_test.go"},
		{"p/b_test.go", "m/b_test.go"},
		{"q/gone_test.go", ""},
		{"r/r_test.go", "r/r_test.go"},
		{"", "n/new_test.go"},
	}
	rep, err := Compare(pairs, tree(oldTree), tree(newTree))
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("report with a gone file and a renamed test passed")
	}
	want := []PackageCount{
		{OldDir: "p", NewDirs: []string{"m", "n"}, Before: 4, Moved: 4, Added: 2},
		{OldDir: "q", Before: 1, Moved: 0, Missing: []string{"q/gone_test.go: TestQ"}},
		{OldDir: "r", NewDirs: []string{"r"}, Before: 2, Moved: 1, Added: 1, Missing: []string{"r/r_test.go: TestS"}},
	}
	if !reflect.DeepEqual(rep.Packages, want) {
		t.Errorf("packages = %+v\nwant       %+v", rep.Packages, want)
	}
	if !rep.Packages[0].OK() || rep.Packages[1].OK() || rep.Packages[2].OK() {
		t.Error("PackageCount.OK")
	}
	var buf bytes.Buffer
	rep.Write(&buf, false)
	out := buf.String()
	for _, want := range []string{
		"GONE    q/gone_test.go (1 tests)",
		"CHANGED r/r_test.go -> r/r_test.go [package main -> r]: 1 line(s)",
		"        - r/r_test.go:3: func TestS(t *testing.T) {}",
		"        tests gone: TestS",
		"ok   p    4 ->    4  m, n (+2 added since)",
		"FAIL q    1 ->    0  (gone)",
		"     missing r/r_test.go: TestS",
		"2 file(s) clean, 1 changed (1 line(s)), 1 gone, 1 added",
		"3 package(s): 7 test(s) before, 5 still there, 3 added since",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "added   n/new_test.go") {
		t.Error("added file listed without -v")
	}
}

func TestCompareErrors(t *testing.T) {
	ok := tree(map[string]string{"a_test.go": "package a\n"})
	bad := tree(map[string]string{"a_test.go": "package\n"})
	none := tree(nil)
	for name, tc := range map[string]struct {
		old, new func(string) ([]byte, error)
		want     string
	}{
		"old missing":  {none, ok, "old a_test.go: not found"},
		"new missing":  {ok, none, "new a_test.go: not found"},
		"old unparsed": {bad, ok, "old a_test.go:"},
		"new unparsed": {ok, bad, "new a_test.go:"},
	} {
		_, err := Compare([]Pair{{"a_test.go", "a_test.go"}}, tc.old, tc.new)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestWriteTruncates(t *testing.T) {
	var a, b []Line
	for i := 0; i < maxShown+5; i++ {
		a = append(a, Line{i + 1, fmt.Sprint("old", i)})
	}
	rep := &Report{Files: []FileResult{{Pair: Pair{"o_test.go", "n_test.go"}, Changes: Diff(a, b)}}}
	var buf bytes.Buffer
	rep.Write(&buf, false)
	if !strings.Contains(buf.String(), "        ... 5 more\n") {
		t.Errorf("output:\n%s", buf.String())
	}
}
