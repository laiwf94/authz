package hdr

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"
)

// Every quantile is within the histogram's precision of the exact value
// from the sorted samples, over values spanning nine decades.
func TestQuantilesMatchSortedSamples(t *testing.T) {
	for _, digits := range []int{2, 3, 4} {
		h := MustNew(time.Hour, digits)
		rng := rand.New(rand.NewPCG(1, uint64(digits)))
		vals := make([]int64, 200000)
		for i := range vals {
			// Log-uniform from 1 ns to about 10 s.
			vals[i] = int64(math.Exp(rng.Float64() * math.Log(1e10)))
			h.Record(time.Duration(vals[i]))
		}
		sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
		tol := math.Pow10(-digits)
		for _, q := range []float64{0, 0.001, 0.1, 0.5, 0.9, 0.99, 0.999, 0.9999, 1} {
			idx := int(math.Ceil(q*float64(len(vals)))) - 1
			if idx < 0 {
				idx = 0
			}
			want := float64(vals[idx])
			got := float64(h.Quantile(q))
			if got < want || (got-want) > tol*want+1 {
				t.Errorf("digits %d q %v: %v, want %v within %.4f%%", digits, q, got, want, tol*100)
			}
		}
		if h.Count() != int64(len(vals)) || h.Min() != time.Duration(vals[0]) || h.Max() != time.Duration(vals[len(vals)-1]) {
			t.Errorf("digits %d: count %d min %v max %v", digits, h.Count(), h.Min(), h.Max())
		}
	}
}

// Values below the first bucket boundary are kept exactly, and each bucket
// covers exactly the values that map to it.
func TestBucketsAreExactAndContiguous(t *testing.T) {
	h := MustNew(10*time.Second, 3)
	prevHigh := int64(0)
	// Index 0 would hold the value 0, which Record never stores.
	for i := 1; i < len(h.counts); i++ {
		lo, hi := h.lowestAt(i), h.highestAt(i)
		if lo != prevHigh+1 {
			t.Fatalf("index %d starts at %d, previous ended at %d", i, lo, prevHigh)
		}
		if h.index(lo) != i || h.index(hi) != i {
			t.Fatalf("index %d covers [%d, %d] but they map to %d and %d", i, lo, hi, h.index(lo), h.index(hi))
		}
		if lo < 2048 && lo != hi {
			t.Fatalf("value %d below the sub-bucket count is not exact", lo)
		}
		prevHigh = hi
		if hi >= h.highest {
			break
		}
	}
	if prevHigh < h.highest {
		t.Fatalf("buckets end at %d, below the highest trackable %d", prevHigh, h.highest)
	}
}

func TestClampAndEdges(t *testing.T) {
	h := MustNew(time.Second, 3)
	if h.Quantile(0.5) != 0 || h.Mean() != 0 || h.Min() != 0 || h.Max() != 0 {
		t.Fatal("empty histogram should answer zeros")
	}
	h.Record(-5)
	h.Record(0)
	h.RecordN(time.Millisecond, 0)
	h.RecordN(3*time.Second, 2)
	if h.Count() != 4 || h.Clamped() != 2 || h.Min() != 1 || h.Max() != time.Second {
		t.Fatalf("count %d clamped %d min %v max %v", h.Count(), h.Clamped(), h.Min(), h.Max())
	}
	if h.Quantile(-1) != 1 || h.Quantile(2) != time.Second {
		t.Fatalf("quantile out of range: %v %v", h.Quantile(-1), h.Quantile(2))
	}
	if m := h.Mean(); m != time.Duration((1+1+2*int64(time.Second))/4) {
		t.Fatalf("mean %v", m)
	}
	h.Reset()
	if h.Count() != 0 || h.Clamped() != 0 || h.Quantile(0.99) != 0 {
		t.Fatal("reset did not empty the histogram")
	}
	for _, bad := range []struct {
		hi time.Duration
		d  int
	}{{time.Second, 0}, {time.Second, 6}, {1, 3}} {
		if _, err := New(bad.hi, bad.d); err == nil {
			t.Errorf("New(%v, %d) accepted", bad.hi, bad.d)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNew with bad settings did not panic")
		}
	}()
	MustNew(time.Second, 9)
}

// Merging per-worker histograms gives what one histogram of every value
// would; histograms of different settings refuse to merge.
func TestMerge(t *testing.T) {
	all := MustNew(time.Minute, 3)
	parts := []*Histogram{MustNew(time.Minute, 3), MustNew(time.Minute, 3), MustNew(time.Minute, 3)}
	rng := rand.New(rand.NewPCG(2, 2))
	for i := range 30000 {
		d := time.Duration(rng.Int64N(int64(50 * time.Millisecond)))
		all.Record(d)
		parts[i%3].Record(d)
	}
	m := MustNew(time.Minute, 3)
	m.Merge(MustNew(time.Minute, 3)) // empty: no change
	for _, p := range parts {
		if err := m.Merge(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []float64{0.5, 0.99, 0.999} {
		if m.Quantile(q) != all.Quantile(q) {
			t.Fatalf("q %v: merged %v, single %v", q, m.Quantile(q), all.Quantile(q))
		}
	}
	if m.Count() != all.Count() || m.Min() != all.Min() || m.Max() != all.Max() || m.Mean() != all.Mean() {
		t.Fatal("merged summary differs")
	}
	if err := m.Merge(MustNew(time.Hour, 3)); err == nil {
		t.Fatal("merged histograms of different ranges")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	h := MustNew(time.Minute, 3)
	for _, d := range []time.Duration{1, 900, 5 * time.Microsecond, 3 * time.Millisecond, 3 * time.Millisecond, 2 * time.Minute} {
		h.Record(d)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var back Histogram
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for _, q := range []float64{0, 0.3, 0.5, 0.8, 1} {
		if back.Quantile(q) != h.Quantile(q) {
			t.Fatalf("q %v: %v after a round trip, was %v", q, back.Quantile(q), h.Quantile(q))
		}
	}
	if back.Count() != h.Count() || back.Clamped() != 1 || back.Mean() != h.Mean() || back.Min() != 1 {
		t.Fatalf("summary changed: %s", b)
	}
	var empty Histogram
	b, _ = json.Marshal(MustNew(time.Second, 2))
	if err := json.Unmarshal(b, &empty); err != nil || empty.Count() != 0 {
		t.Fatalf("empty round trip: %v %s", err, b)
	}
	for _, bad := range []string{
		`{`,
		`{"highest_ns":1000,"digits":9,"buckets":[]}`,
		`{"highest_ns":1000000,"digits":3,"min_ns":5,"max_ns":5,"buckets":[[5,1],[3,1]]}`,
		`{"highest_ns":1000000,"digits":3,"min_ns":5,"max_ns":5,"buckets":[[5,0]]}`,
		`{"highest_ns":1000000,"digits":3,"min_ns":5,"max_ns":5,"buckets":[[5000000,1]]}`,
		`{"highest_ns":1000000,"digits":3,"min_ns":5000,"max_ns":5000,"buckets":[[4097,1]]}`,
		`{"highest_ns":1000000,"digits":3,"min_ns":9,"max_ns":5,"buckets":[[5,1]]}`,
	} {
		var x Histogram
		if err := json.Unmarshal([]byte(bad), &x); err == nil {
			t.Errorf("accepted %s", bad)
		} else if strings.Contains(bad, "4097") && !strings.Contains(err.Error(), "start of a bucket") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// Recording allocates nothing, so per-request cost is an increment.
func TestRecordDoesNotAllocate(t *testing.T) {
	h := MustNew(time.Minute, 3)
	if n := testing.AllocsPerRun(1000, func() { h.Record(1234567) }); n != 0 {
		t.Fatalf("%v allocations per record", n)
	}
}

func BenchmarkRecord(b *testing.B) {
	h := MustNew(time.Minute, 3)
	for i := 0; b.Loop(); i++ {
		h.Record(time.Duration(i&0xfffff) * 1000)
	}
}
