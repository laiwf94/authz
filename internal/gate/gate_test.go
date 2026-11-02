package gate

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseFindings(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "pkg", "a_test.go")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("package pkg\n\n\tx := y == y // flagged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := `{"code":"SA4000","severity":"error","location":{"file":"` + src + `","line":3,"column":7},"end":{"file":"` + src + `","line":3,"column":13},"message":"identical expressions"}

{"code":"SA4000","severity":"error","location":{"file":"` + src + `","line":1,"column":1},"message":"again"}
{"code":"SA9999","severity":"error","location":{"file":"` + src + `","line":99,"column":1},"message":"past the end"}
{"code":"ST1000","severity":"warning","location":{"file":"/elsewhere/b.go","line":0,"column":0},"message":"no line"}
`
	got, err := ParseFindings(strings.NewReader(out), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4", len(got))
	}
	if f := got[0]; f.File != "pkg/a_test.go" || f.Code != "SA4000" || f.Text != "x := y == y // flagged" || f.Location.Line != 3 || f.Location.Column != 7 {
		t.Fatalf("first finding = %+v", f)
	}
	if got[1].Text != "package pkg" {
		t.Fatalf("second finding text = %q (file cache)", got[1].Text)
	}
	if got[2].Text != "" {
		t.Fatalf("line past the end of the file gave text %q", got[2].Text)
	}
	if f := got[3]; f.File != "/elsewhere/b.go" || f.Text != "" {
		t.Fatalf("finding outside root = %+v", f)
	}
	if s := got[0].String(); s != "pkg/a_test.go:3:7: identical expressions (SA4000)" {
		t.Fatalf("String() = %q", s)
	}

	for name, bad := range map[string]string{
		"not json": "SA4000 oops\n",
		"no code":  `{"location":{"file":"a.go","line":1}}` + "\n",
		"no file":  `{"code":"SA1000","location":{"line":1}}` + "\n",
	} {
		if _, err := ParseFindings(strings.NewReader(bad), root); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ParseFindings(errReader{}, root); err == nil {
		t.Error("read error not returned")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

func TestRelPath(t *testing.T) {
	for _, c := range []struct{ root, file, want string }{
		{"/m", "/m/a/b.go", "a/b.go"},
		{"/m", "/other/b.go", "/other/b.go"},
		{"/m", "a/b.go", "a/b.go"},
		{"", "/m/a.go", "/m/a.go"},
	} {
		if got := relPath(c.root, c.file); got != c.want {
			t.Errorf("relPath(%q, %q) = %q, want %q", c.root, c.file, got, c.want)
		}
	}
}

func TestParseLintAllow(t *testing.T) {
	in := `# comment

a/x_test.go SA4006   resp, body = get(u)
  b/y_test.go   SA1018 strings.Replace(s, "", "", 0)
`
	got, err := ParseLintAllow(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []LintAllowed{
		{File: "a/x_test.go", Code: "SA4006", Text: "resp, body = get(u)", Line: 3},
		{File: "b/y_test.go", Code: "SA1018", Text: `strings.Replace(s, "", "", 0)`, Line: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if s := got[0].String(); s != "a/x_test.go SA4006 resp, body = get(u)" {
		t.Fatalf("String() = %q", s)
	}
	for name, bad := range map[string]string{
		"no text":   "a_test.go SA4006\n",
		"only file": "a_test.go\n",
		"not test":  "a.go SA4006 x := 1\n",
		"compile":   "a_test.go compile x := 1\n",
	} {
		if _, err := ParseLintAllow(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: no error", name)
		} else if !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: error %q does not name the line", name, err)
		}
	}
	if _, err := ParseLintAllow(errReader{}); err == nil {
		t.Error("read error not returned")
	}
}

func finding(file string, line, col int, code, text string) Finding {
	f := Finding{Code: code, File: file, Text: text}
	f.Location.Line, f.Location.Column = line, col
	return f
}

func TestFilterLint(t *testing.T) {
	findings := []Finding{
		finding("b_test.go", 9, 1, "SA4006", "resp, _ = get()"),
		finding("a_test.go", 5, 2, "SA4006", "resp, _ = get()"),
		finding("a_test.go", 7, 2, "SA4006", "resp, _ = get()"),
		finding("a_test.go", 7, 1, "SA4010", "s = append(s, x)"),
		finding("a.go", 3, 1, "ST1005", `errors.New("Bad")`),
	}
	allow := []LintAllowed{
		// One entry accepts one finding, even when two share the text.
		{File: "a_test.go", Code: "SA4006", Text: "resp, _ = get()"},
		// The code has to match.
		{File: "a_test.go", Code: "SA4000", Text: "s = append(s, x)"},
		{File: "b_test.go", Code: "SA4006", Text: "resp, _ = get()"},
	}
	rejected, accepted, stale := FilterLint(findings, allow)
	if len(accepted) != 2 || accepted[0].File != "b_test.go" || accepted[1].Location.Line != 5 {
		t.Fatalf("accepted = %v", accepted)
	}
	var got []string
	for _, f := range rejected {
		got = append(got, f.String())
	}
	want := []string{
		"a.go:3:1:  (ST1005)",
		"a_test.go:7:1:  (SA4010)",
		"a_test.go:7:2:  (SA4006)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected = %q, want %q (sorted by file, line, column)", got, want)
	}
	if len(stale) != 1 || stale[0].Code != "SA4000" {
		t.Fatalf("stale = %v", stale)
	}

	// A changed line no longer matches its entry: the finding fails and the
	// entry is stale.
	rejected, accepted, stale = FilterLint(
		[]Finding{finding("a_test.go", 5, 2, "SA4006", "resp, _ = get2()")},
		allow[:1])
	if len(rejected) != 1 || len(accepted) != 0 || len(stale) != 1 {
		t.Fatalf("changed line: rejected %v accepted %v stale %v", rejected, accepted, stale)
	}
	if r, a, s := FilterLint(nil, nil); r != nil || a != nil || s != nil {
		t.Fatal("empty input gave output")
	}
}

const profile = `mode: atomic
example.com/m/a/a.go:3.10,5.2 2 4
example.com/m/a/a.go:5.2,7.3 3 0
example.com/m/a/b.go:1.1,2.2 5 0
example.com/m/ab/c.go:1.1,2.2 10 1
example.com/m/z.go:1.1,1.9 1 0
mode: atomic
example.com/m/a/b.go:1.1,2.2 5 2
`

func TestParseCoverProfile(t *testing.T) {
	c, err := ParseCoverProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "atomic" {
		t.Fatalf("mode = %q", c.Mode)
	}
	// a.go 2 of 5, b.go 5 of 5 (covered in the second profile), c.go 10 of
	// 10, z.go 0 of 1.
	if got := c.Total(); got != (Stat{Statements: 21, Covered: 17}) {
		t.Fatalf("total = %+v", got)
	}
	if s := c.Total().String(); s != "81.0% of 21 statements" {
		t.Fatalf("String() = %q", s)
	}

	for name, bad := range map[string]string{
		"empty":         "",
		"no mode":       "a.go:1.1,2.2 1 1\n",
		"mixed modes":   "mode: set\nmode: count\n",
		"no file":       "mode: set\n1.1,2.2 1 1\n",
		"few fields":    "mode: set\na.go:1.1,2.2 1\n",
		"bad range":     "mode: set\na.go:1.1-2.2 1 1\n",
		"bad position":  "mode: set\na.go:1,2.2 1 1\n",
		"bad line":      "mode: set\na.go:x.1,2.2 1 1\n",
		"bad stmts":     "mode: set\na.go:1.1,2.2 x 1\n",
		"bad count":     "mode: set\na.go:1.1,2.2 1 -1\n",
		"changed block": "mode: set\na.go:1.1,2.2 1 1\na.go:1.1,2.2 2 1\n",
	} {
		if _, err := ParseCoverProfile(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ParseCoverProfile(errReader{}); err == nil {
		t.Error("read error not returned")
	}
}

func TestStatPercent(t *testing.T) {
	if p := (Stat{}).Percent(); p != 100 {
		t.Fatalf("no statements = %v%%, want 100", p)
	}
	if p := (Stat{Statements: 3, Covered: 1}).Percent(); math.Abs(p-33.333) > 0.001 {
		t.Fatalf("1 of 3 = %v%%", p)
	}
}

func TestParseGroup(t *testing.T) {
	g, err := ParseGroup("authn=example.com/m/a, example.com/m/z.go")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Group{Name: "authn", Prefixes: []string{"example.com/m/a", "example.com/m/z.go"}}); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %+v", g)
	}
	for _, bad := range []string{"", "authn", "=x", "authn=", "authn=a,,b"} {
		if _, err := ParseGroup(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestByGroup(t *testing.T) {
	c, err := ParseCoverProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	got := c.ByGroup([]Group{
		// "a" must not swallow "ab": prefixes match whole path elements.
		{Name: "a", Prefixes: []string{"example.com/m/a/"}},
		{Name: "ab", Prefixes: []string{"example.com/m/ab", "example.com/none"}},
		// The longest matching prefix wins over an earlier, shorter one.
		{Name: "m", Prefixes: []string{"example.com/m"}},
		{Name: "a-b", Prefixes: []string{"example.com/m/a/b.go/x", "example.com/m/a"}},
	}, "rest")
	// "a" and "a-b" tie on example.com/m/a; the earlier group keeps a.go
	// and b.go.
	want := []NamedStat{
		{"a", Stat{10, 7}},
		{"ab", Stat{10, 10}},
		{"m", Stat{1, 0}},
		{"a-b", Stat{0, 0}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	got = c.ByGroup([]Group{{Name: "ab", Prefixes: []string{"example.com/m/ab"}}}, "rest")
	want = []NamedStat{{"ab", Stat{10, 10}}, {"rest", Stat{11, 7}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with rest: got %+v\nwant %+v", got, want)
	}
}
