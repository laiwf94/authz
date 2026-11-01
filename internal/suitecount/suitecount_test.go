package suitecount

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

const stream = `{"Action":"start","Package":"ex/a"}
{"Action":"run","Package":"ex/a","Test":"TestOne"}
{"Action":"output","Package":"ex/a","Test":"TestOne","Output":"=== RUN   TestOne\n"}
{"Action":"pass","Package":"ex/a","Test":"TestOne","Elapsed":0}
{"Action":"pass","Package":"ex/a","Test":"TestAttacks/forged_cookie","Elapsed":0}
{"Action":"pass","Package":"ex/a","Test":"TestAttacks","Elapsed":0}
{"Action":"skip","Package":"ex/a","Test":"TestNeedsNetwork","Elapsed":0}
{"Action":"pass","Package":"ex/a","Test":"FuzzParse/seed#0","Elapsed":0}
{"Action":"pass","Package":"ex/a","Test":"FuzzParse","Elapsed":0}
{"Action":"pass","Package":"ex/a","Elapsed":0.1}
not json: a build error from an old toolchain
{"Action":"fail","Package":"ex/b","Test":"TestPropertyRoundTrip","Elapsed":0}
{"Action":"fail","Package":"ex/b","Elapsed":0.1}
{"broken json
{"ImportPath":"ex/c","Action":"build-output","Output":"syntax error\n"}
{"ImportPath":"ex/c","Action":"build-fail"}
{"Action":"skip","Package":"ex/d","Elapsed":0}
`

func TestRead(t *testing.T) {
	run, err := Read(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	want := map[Case]Status{
		{"ex/a", "TestOne"}:                   Pass,
		{"ex/a", "TestAttacks/forged_cookie"}: Pass,
		{"ex/a", "TestAttacks"}:               Pass,
		{"ex/a", "TestNeedsNetwork"}:          Skip,
		{"ex/a", "FuzzParse/seed#0"}:          Pass,
		{"ex/a", "FuzzParse"}:                 Pass,
		{"ex/b", "TestPropertyRoundTrip"}:     Fail,
	}
	if !reflect.DeepEqual(run.Cases, want) {
		t.Errorf("cases = %v, want %v", run.Cases, want)
	}
	if !reflect.DeepEqual(run.Failed, []string{"ex/b", "ex/c"}) {
		t.Errorf("failed = %v", run.Failed)
	}
	passed := run.Passed()
	if len(passed) != 5 || passed[0] != (Case{"ex/a", "FuzzParse"}) || passed[4] != (Case{"ex/a", "TestOne"}) {
		t.Errorf("passed = %v", passed)
	}
}

func TestReadLastResultWins(t *testing.T) {
	// -count=2 reports a case twice; the later result is the one that counts.
	run, err := Read(strings.NewReader(`{"Action":"pass","Package":"p","Test":"TestFlaky"}
{"Action":"fail","Package":"p","Test":"TestFlaky"}
`))
	if err != nil {
		t.Fatal(err)
	}
	if run.Cases[Case{"p", "TestFlaky"}] != Fail {
		t.Errorf("status = %q", run.Cases[Case{"p", "TestFlaky"}])
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadError(t *testing.T) {
	if _, err := Read(errReader{}); err == nil {
		t.Fatal("want error")
	}
}

func TestSuite(t *testing.T) {
	for name, want := range map[string]string{
		"FuzzParse":                       "fuzz",
		"FuzzParse/seed#3":                "fuzz",
		"TestPropertyTamper":              "property",
		"TestPropertyTamper/x":            "property",
		"TestAttacks/XSW1":                "attack",
		"TestIDTokenAttacks/wrong_aud":    "attack",
		"TestSessionCookieAttacks":        "attack",
		"TestRun":                         "unit",
		"TestRun/Attack_in_a_subtest":     "unit",
		"TestProperties":                  "unit",
		"TestHelperProperty/FuzzLikeName": "unit",
	} {
		if got := (Case{"p", name}).Suite(); got != want {
			t.Errorf("Suite(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	cases := []Case{{"b", "TestZ"}, {"a", "TestB/sub_case"}, {"a", "TestA"}, {"b", "FuzzX/seed#0"}}
	var buf bytes.Buffer
	if err := Format(&buf, "first line\nsecond line", cases); err != nil {
		t.Fatal(err)
	}
	want := "# first line\n# second line\na\tTestA\na\tTestB/sub_case\nb\tFuzzX/seed#0\nb\tTestZ\n"
	if buf.String() != want {
		t.Fatalf("format:\n%s\nwant:\n%s", buf.String(), want)
	}
	got, err := Parse(strings.NewReader(buf.String() + "\n# trailing comment\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []Case{{"a", "TestA"}, {"a", "TestB/sub_case"}, {"b", "FuzzX/seed#0"}, {"b", "TestZ"}}) {
		t.Errorf("parse = %v", got)
	}
	if cases[0] != (Case{"b", "TestZ"}) {
		t.Error("Format reordered its input")
	}

	buf.Reset()
	if err := Format(&buf, "", cases[:1]); err != nil || buf.String() != "b\tTestZ\n" {
		t.Errorf("no header: %q %v", buf.String(), err)
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":       "# only a comment\n",
		"no tab":      "pkg TestA\n",
		"no name":     "pkg\t\n",
		"no package":  "\tTestA\n",
		"space pkg":   "a b\tTestA\n",
		"two tabs":    "pkg\tTestA\textra\n",
		"duplicate":   "pkg\tTestA\npkg\tTestA\n",
		"read failed": "",
	} {
		var err error
		if name == "read failed" {
			_, err = Parse(errReader{})
		} else {
			_, err = Parse(strings.NewReader(in))
		}
		if err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestCompare(t *testing.T) {
	base := []Case{
		{"p", "TestA"},
		{"p", "TestAttacks/one"},
		{"p", "TestAttacks/two"},
		{"p", "FuzzX/seed#0"},
		{"p", "TestPropertyY"},
		{"q", "TestGone"},
	}
	run := &Run{Cases: map[Case]Status{
		{"p", "TestA"}:           Pass,
		{"p", "TestAttacks/one"}: Pass,
		{"p", "TestAttacks/two"}: Skip,
		{"p", "FuzzX/seed#0"}:    Pass,
		{"p", "FuzzX/seed#1"}:    Pass,
		{"p", "TestPropertyY"}:   Fail,
		{"p", "TestNew"}:         Pass,
		{"other", "TestA"}:       Pass, // not a baseline package: not counted
	}, Failed: []string{"p"}}
	rep := Compare(base, run)
	if rep.OK() {
		t.Fatal("report is OK with missing cases")
	}
	wantMissing := []Missing{
		{Case{"p", "TestAttacks/two"}, Skip},
		{Case{"p", "TestPropertyY"}, Fail},
		{Case{"q", "TestGone"}, ""},
	}
	if !reflect.DeepEqual(rep.Missing, wantMissing) {
		t.Errorf("missing = %v", rep.Missing)
	}
	if !reflect.DeepEqual(rep.Added, []Case{{"p", "FuzzX/seed#1"}, {"p", "TestNew"}}) {
		t.Errorf("added = %v", rep.Added)
	}
	wantSuites := map[string]Counts{
		"attack":   {2, 1},
		"property": {1, 0},
		"fuzz":     {1, 2},
		"unit":     {2, 2},
	}
	if !reflect.DeepEqual(rep.Suites, wantSuites) {
		t.Errorf("suites = %v", rep.Suites)
	}

	var out bytes.Buffer
	rep.Write(&out, true)
	want := `suite     baseline      now
attack           2        1
property         1        0
fuzz             1        2
unit             2        2
total            6        5
FAIL package p
MISSING p TestAttacks/two (skip)
MISSING p TestPropertyY (fail)
MISSING q TestGone (did not run)
2 case(s) added since the baseline
added p FuzzX/seed#1
added p TestNew
`
	if out.String() != want {
		t.Errorf("report:\n%s\nwant:\n%s", out.String(), want)
	}
	out.Reset()
	rep.Write(&out, false)
	if strings.Contains(out.String(), "added p") {
		t.Error("non-verbose report lists added cases")
	}
}

func TestCompareOK(t *testing.T) {
	base := []Case{{"p", "TestA"}}
	rep := Compare(base, &Run{Cases: map[Case]Status{{"p", "TestA"}: Pass}})
	if !rep.OK() || len(rep.Added) != 0 || rep.Suites["unit"] != (Counts{1, 1}) {
		t.Errorf("report = %+v", rep)
	}
	rep = Compare(base, &Run{Cases: map[Case]Status{{"p", "TestA"}: Pass}, Failed: []string{"elsewhere"}})
	if rep.OK() {
		t.Error("a failed package must fail the comparison")
	}
}

// TestWicketBaseline pins the checked-in baseline of the wicket suite, so
// that the file cannot lose cases without this test changing too.
func TestWicketBaseline(t *testing.T) {
	f, err := os.Open("../authn/testdata/wicket-suite.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	base, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, c := range base {
		counts[c.Suite()]++
		if !strings.HasPrefix(c.Package, "github.com/laiwf94/authz/") {
			t.Errorf("unmapped package %s", c.Package)
		}
	}
	want := map[string]int{"attack": 73, "property": 6, "fuzz": 25, "unit": 234}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("baseline suites = %v, want %v", counts, want)
	}
}
