package datasets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

func mustSize(t testing.TB, n int64, seed uint64) Graph {
	t.Helper()
	g, err := Size(n, seed)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestPresetsFitTheirSize(t *testing.T) {
	for name, n := range Presets {
		g := mustSize(t, n, 1)
		c := g.Count()
		// The largest graph that fits: one more document would not.
		if c > n || shape(g.Docs+1, 1).Count() <= n {
			t.Errorf("%s: %d relationships, docs %d is not the largest fit for %d", name, c, g.Docs, n)
		}
		if float64(c) < 0.9999*float64(n) {
			t.Errorf("%s: %d relationships, under 99.99%% of %d", name, c, n)
		}
		t.Logf("%s: %d relationships: %d users, %d groups, %d folders, %d docs", name, c, g.Users, g.Groups, g.Folders, g.Docs)
	}
}

func TestCountIsWhatEachEmits(t *testing.T) {
	for _, n := range []int64{MinRelationships, 101, 999, 12_345, 1_000_000} {
		g := mustSize(t, n, 7)
		var got int64
		if err := g.Each(func(*Relationship) error { got++; return nil }); err != nil {
			t.Fatal(err)
		}
		if got != g.Count() {
			t.Errorf("size %d: Each emitted %d, Count says %d", n, got, g.Count())
		}
	}
}

func tuples(t testing.TB, g Graph, from, to int64) []byte {
	t.Helper()
	var b bytes.Buffer
	n, err := WriteGraph(&b, g, FormatTuples, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if n != to-from {
		t.Fatalf("wrote %d of %d..%d", n, from, to)
	}
	return b.Bytes()
}

// The dataset is part of the published results: any change to the
// generator that changes a dataset must change this digest on purpose.
func TestDatasetIsPinned(t *testing.T) {
	g := mustSize(t, 100_000, 1)
	sum := sha256.Sum256(tuples(t, g, 0, g.Count()))
	const want = "f17ac4215bf4500b8b2dca0003fde48cf4cd4f31447b883b4472575d111337f6"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("the 100k seed 1 dataset hashes to %s, pinned %s", got, want)
	}
}

func TestSameSeedSameDataset(t *testing.T) {
	a, b, c := mustSize(t, 50_000, 3), mustSize(t, 50_000, 3), mustSize(t, 50_000, 4)
	ta, tb, tc := tuples(t, a, 0, a.Count()), tuples(t, b, 0, b.Count()), tuples(t, c, 0, c.Count())
	if !bytes.Equal(ta, tb) {
		t.Error("two runs with one seed differ")
	}
	if bytes.Equal(ta, tc) {
		t.Error("seeds 3 and 4 give the same dataset")
	}
}

func TestRangesConcatenateToTheWhole(t *testing.T) {
	g := mustSize(t, 30_011, 5)
	whole := tuples(t, g, 0, g.Count())
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		// Cut the dataset at random points, some on section boundaries.
		cuts := []int64{0, g.Count()}
		for range 1 + r.IntN(6) {
			cuts = append(cuts, r.Int64N(g.Count()+1))
		}
		cuts = append(cuts, int64(g.Users*groupsPerUser), g.Count()-int64(g.Docs*4+g.Docs/bannedEvery))
		sortInt64(cuts)
		var got []byte
		for i := 1; i < len(cuts); i++ {
			got = append(got, tuples(t, g, cuts[i-1], cuts[i])...)
		}
		if !bytes.Equal(got, whole) {
			t.Fatalf("ranges cut at %v do not add up to the dataset", cuts)
		}
	}
	for _, bad := range [][2]int64{{-1, 5}, {5, 4}, {0, g.Count() + 1}} {
		if err := g.EachRange(bad[0], bad[1], func(*Relationship) error { return nil }); err == nil {
			t.Errorf("range %v accepted", bad)
		}
	}
}

func sortInt64(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func TestEveryRelationshipIsValidAndDistinct(t *testing.T) {
	// The schema check of every type and relation is the engine's, in
	// TestLoadMatchesOracle; here every tuple parses and none repeats.
	if _, err := schema.Parse(Schema); err != nil {
		t.Fatal(err)
	}
	g := mustSize(t, 100_000, 9)
	seen := make(map[string]bool, g.Count())
	err := g.Each(func(r *Relationship) error {
		s := r.String()
		rel, err := store.ParseRelationship(s)
		if err != nil {
			return err
		}
		if rel.String() != s {
			return errors.New(s + " reads back as " + rel.String())
		}
		if seen[s] {
			return errors.New("duplicate " + s)
		}
		seen[s] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEachStopsAtFirstError(t *testing.T) {
	g := mustSize(t, 10_000, 1)
	stop := errors.New("stop")
	for _, at := range []int64{0, 5, int64(g.Users * groupsPerUser), g.Count() - 1} {
		var n int64
		err := g.EachRange(0, g.Count(), func(*Relationship) error {
			if n == at {
				return stop
			}
			n++
			return nil
		})
		if err != stop || n != at {
			t.Errorf("stop at %d: err %v after %d", at, err, n)
		}
	}
	if _, err := WriteGraph(failWriter{}, g, FormatTuples, 0, g.Count()); err == nil {
		t.Error("WriteGraph hid a write error")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOpenFGAFormat(t *testing.T) {
	g := mustSize(t, 5_000, 2)
	var b bytes.Buffer
	if _, err := WriteGraph(&b, g, FormatOpenFGA, 0, g.Count()); err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSpace(string(tuples(t, g, 0, g.Count()))), "\n")
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("%d lines, want %d", len(lines), len(want))
	}
	wildcards := 0
	for i, line := range lines {
		var k struct{ User, Relation, Object string }
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&k); err != nil {
			t.Fatalf("line %d %q: %v", i, line, err)
		}
		if got := k.Object + "#" + k.Relation + "@" + k.User; got != want[i] {
			t.Fatalf("line %d is %s, want %s", i, got, want[i])
		}
		if k.User == "user:*" {
			wildcards++
		}
	}
	if wildcards != g.Folders/publicFolderEvery {
		t.Errorf("%d public folders, want %d", wildcards, g.Folders/publicFolderEvery)
	}
	if _, err := WriteGraph(&b, g, "csv", 0, 1); err == nil {
		t.Error("unknown format accepted")
	}
	for _, def := range []string{"type user", "type group", "type folder", "type doc",
		"define view: (edit or view from parent) but not banned", "define viewer: [user, user:*, group#member]"} {
		if !strings.Contains(OpenFGAModel, def) {
			t.Errorf("OpenFGA model has no %q", def)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1m": 1e6, "10M": 1e7, " 100m ": 1e8, "250k": 250_000, "2500000": 2_500_000, "100": 100} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "m", "-5", "99", "0k", "1.5m", "20000000m", "lots"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) accepted", in)
		}
	}
	if _, err := Size(MinRelationships-1, 1); err == nil {
		t.Error("Size below the minimum accepted")
	}
	if _, err := Size(MaxRelationships+1, 1); err == nil {
		t.Error("Size above the maximum accepted")
	}
	if err := (Graph{Users: 1, Docs: 1, Folders: 1, Groups: 1}).Each(func(*Relationship) error { return nil }); err == nil {
		t.Error("a graph with one group accepted")
	}
	if err := (Graph{Groups: 2}).Validate(); err == nil {
		t.Error("an empty graph accepted")
	}
}

// The shape is what the package comment promises: a few big groups, a
// shallow nesting, folder trees a few levels deep.
func TestShape(t *testing.T) {
	g := mustSize(t, 1_000_000, 1)
	members := make([]int, g.Groups)
	parent := make([]int, g.Groups)
	for i := range parent {
		parent[i] = -1
	}
	fparent := make([]int, g.Folders)
	for i := range fparent {
		fparent[i] = -1
	}
	err := g.Each(func(r *Relationship) error {
		switch {
		case r.ResourceType == TypeGroup && r.SubjectType == TypeUser:
			members[r.Resource]++
		case r.ResourceType == TypeGroup:
			if r.Resource >= r.Subject {
				t.Fatalf("group %d nests in group %d, not a lower one", r.Subject, r.Resource)
			}
			parent[r.Subject] = r.Resource
		case r.ResourceType == TypeFolder && r.Relation == "parent":
			fparent[r.Resource] = r.Subject
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	depth := func(p []int, i int) int {
		d := 0
		for ; p[i] >= 0; i = p[i] {
			d++
		}
		return d
	}
	gdepth, fdepth := 0, 0
	for i := range parent {
		gdepth = max(gdepth, depth(parent, i))
	}
	for i := range fparent {
		fdepth = max(fdepth, depth(fparent, i))
	}
	share := float64(members[0]) / float64(g.Users)
	t.Logf("1m: largest group has %.1f%% of users; group nesting %d deep; folders %d deep", 100*share, gdepth, fdepth)
	if share < 0.01 || share > 0.1 || members[g.Groups-1] > members[0]/10 {
		t.Errorf("group sizes are not skewed as described: first %d, last %d of %d users", members[0], members[g.Groups-1], g.Users)
	}
	if gdepth < 1 || gdepth > 3 || fdepth < 3 || fdepth > 5 {
		t.Errorf("group nesting %d deep and folders %d deep, want 1-3 and 3-5", gdepth, fdepth)
	}
}

func BenchmarkGenerate(b *testing.B) {
	g := mustSize(b, 1_000_000, 1)
	b.ReportAllocs()
	var n int64
	for b.Loop() {
		w, err := WriteGraph(io.Discard, g, FormatTuples, 0, g.Count())
		if err != nil {
			b.Fatal(err)
		}
		n += w
	}
	b.ReportMetric(float64(n)/b.Elapsed().Seconds(), "rels/s")
}
