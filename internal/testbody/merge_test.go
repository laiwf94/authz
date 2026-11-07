package testbody

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseMerges(t *testing.T) {
	got, err := ParseMerges(strings.NewReader("# three into one\n\n a/m_test.go  p/m_test.go \nb/m_test.go p/m_test.go\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Merge{{"a/m_test.go", "p/m_test.go", 3}, {"b/m_test.go", "p/m_test.go", 4}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merges = %+v", got)
	}
	for in, msg := range map[string]string{
		"a/m_test.go\n":                                        "line 1: want OLD_test.go NEW_test.go",
		"a/m_test.go p/m_test.go extra\n":                      "line 1: want",
		"a/m.go p/m_test.go\n":                                 "line 1: want",
		"a/m_test.go p/m.go\n":                                 "line 1: want",
		"a/m_test.go p/x_test.go\n\na/m_test.go p/y_test.go\n": "line 3: a/m_test.go is already merged on line 1",
	} {
		if _, err := ParseMerges(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: err = %v, want %q", in, err, msg)
		}
	}
	if _, err := ParseMerges(strings.NewReader(strings.Repeat("x", 70<<10))); err == nil {
		t.Error("overlong line accepted")
	}
}

func TestApplyMerges(t *testing.T) {
	old := []string{"a/m_test.go", "b/m_test.go", "c/m_test.go"}
	new := []string{"p/m_test.go"}
	renames := map[string]string{"a/m_test.go": "p/m_test.go", "c/m_test.go": "elsewhere_test.go"}
	merges := []Merge{{"b/m_test.go", "p/m_test.go", 1}, {"c/m_test.go", "p/m_test.go", 2}}
	if err := ApplyMerges(renames, merges, old, new); err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"a/m_test.go": "p/m_test.go", "b/m_test.go": "p/m_test.go", "c/m_test.go": "p/m_test.go"}; !reflect.DeepEqual(renames, want) {
		t.Errorf("renames = %v", renames)
	}
	if got := Pairs(old, new, renames); !reflect.DeepEqual(got, []Pair{{"a/m_test.go", "p/m_test.go"}, {"b/m_test.go", "p/m_test.go"}, {"c/m_test.go", "p/m_test.go"}}) {
		t.Errorf("pairs = %v", got)
	}
	if err := ApplyMerges(map[string]string{}, []Merge{{"z/m_test.go", "p/m_test.go", 7}}, old, new); err == nil || !strings.Contains(err.Error(), "line 7: z/m_test.go is not in the old tree") {
		t.Errorf("stale old: %v", err)
	}
	if err := ApplyMerges(map[string]string{}, []Merge{{"a/m_test.go", "q/m_test.go", 8}}, old, new); err == nil || !strings.Contains(err.Error(), "line 8: q/m_test.go is not in the new tree") {
		t.Errorf("stale new: %v", err)
	}
}

// TestCompareMerged: identical old files merged into one new file are each
// clean, and a merge whose new file lost a test still fails for every old
// package that had it.
func TestCompareMerged(t *testing.T) {
	body := "package metrics\n\nimport \"testing\"\n\nfunc TestExposition(t *testing.T) { t.Log(1) }\n\nfunc TestFormatFloat(t *testing.T) {}\n"
	oldTree := map[string]string{"a/m_test.go": body, "b/m_test.go": body, "c/m_test.go": body}
	pairs := []Pair{{"a/m_test.go", "p/m_test.go"}, {"b/m_test.go", "p/m_test.go"}, {"c/m_test.go", "p/m_test.go"}}

	rep, err := Compare(pairs, tree(oldTree), tree(map[string]string{"p/m_test.go": body}))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("clean merge failed: %+v", rep)
	}
	// A test added to the new file counts once in the total, not once per
	// old package merged into it.
	grown := body + "\nfunc TestCap(t *testing.T) {}\n"
	if rep, err := Compare(pairs, tree(oldTree), tree(map[string]string{"p/m_test.go": grown})); err != nil || !rep.OK() || rep.Added != 1 {
		t.Errorf("grown merge: ok %v added %d err %v", rep.OK(), rep.Added, err)
	}
	for _, p := range rep.Packages {
		if p.Before != 2 || p.Moved != 2 || p.Added != 0 || !reflect.DeepEqual(p.NewDirs, []string{"p"}) {
			t.Errorf("package %+v", p)
		}
	}

	lost := "package metrics\n\nimport \"testing\"\n\nfunc TestExposition(t *testing.T) { t.Log(1) }\n"
	rep, err = Compare(pairs, tree(oldTree), tree(map[string]string{"p/m_test.go": lost}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("merge that lost a test passed")
	}
	for _, p := range rep.Packages {
		if p.OK() || len(p.Missing) != 1 || !strings.HasSuffix(p.Missing[0], ": TestFormatFloat") {
			t.Errorf("package %+v", p)
		}
	}
}
