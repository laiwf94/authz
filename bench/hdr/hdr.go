// Package hdr is a high dynamic range histogram of durations, in the layout
// of Gil Tene's HdrHistogram: values are kept to a fixed number of
// significant decimal digits over the whole trackable range, recording is
// one array increment with no allocation, and two histograms with the same
// settings merge by adding their counts. The benchmark runner keeps one per
// worker and operation and merges them when the run ends, so recording takes
// no lock.
//
// Values are nanoseconds. A histogram tracks 1 ns up to its highest
// trackable value; larger values are clamped to it and counted in Clamped,
// so a stalled request is never silently lost.
package hdr

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"time"
)

// Histogram counts durations to a fixed relative precision. It is not safe
// for concurrent use.
type Histogram struct {
	highest     int64
	digits      int
	subMag      uint // log2 of the sub-bucket count
	subHalfMag  uint
	subCount    int64
	subHalf     int64
	subMask     int64
	bucketCount int
	counts      []int64

	total   int64
	clamped int64
	min     int64
	max     int64
	sum     float64 // of recorded values, for the mean
}

// New returns a histogram tracking 1 ns to highest at digits significant
// decimal digits (1 to 5). Three digits keep every value within 0.1%.
func New(highest time.Duration, digits int) (*Histogram, error) {
	if digits < 1 || digits > 5 {
		return nil, fmt.Errorf("hdr: %d significant digits, want 1 to 5", digits)
	}
	if highest < 2 {
		return nil, fmt.Errorf("hdr: highest trackable value %v, want at least 2ns", highest)
	}
	largestSingle := 2 * int64(math.Pow10(digits))
	subMag := uint(bits.Len64(uint64(largestSingle - 1)))
	h := &Histogram{
		highest:    int64(highest),
		digits:     digits,
		subMag:     subMag,
		subHalfMag: subMag - 1,
		subCount:   1 << subMag,
		subHalf:    1 << (subMag - 1),
		min:        math.MaxInt64,
	}
	h.subMask = h.subCount - 1
	// The smallest bucket count whose top value reaches highest.
	h.bucketCount = 1
	for v := h.subCount; v <= h.highest; v <<= 1 {
		h.bucketCount++
		if v > math.MaxInt64/2 {
			break
		}
	}
	h.counts = make([]int64, (h.bucketCount+1)*int(h.subHalf))
	return h, nil
}

// MustNew is New for settings known to be valid.
func MustNew(highest time.Duration, digits int) *Histogram {
	h, err := New(highest, digits)
	if err != nil {
		panic(err)
	}
	return h
}

func (h *Histogram) index(v int64) int {
	pow2 := 64 - bits.LeadingZeros64(uint64(v|h.subMask))
	bucket := pow2 - int(h.subHalfMag) - 1
	sub := v >> uint(bucket)
	return (bucket+1)<<h.subHalfMag + int(sub-h.subHalf)
}

// lowestAt is the smallest value counted at index i.
func (h *Histogram) lowestAt(i int) int64 {
	bucket := (i >> h.subHalfMag) - 1
	sub := int64(i&int(h.subHalf-1)) + h.subHalf
	if bucket < 0 {
		sub -= h.subHalf
		bucket = 0
	}
	return sub << uint(bucket)
}

// highestAt is the largest value counted at index i.
func (h *Histogram) highestAt(i int) int64 {
	lo := h.lowestAt(i)
	bucket := (i >> h.subHalfMag) - 1
	if bucket < 0 {
		bucket = 0
	}
	return lo + int64(1)<<uint(bucket) - 1
}

// Record counts one duration. Durations below 1 ns count as 1 ns.
func (h *Histogram) Record(d time.Duration) {
	h.RecordN(d, 1)
}

// RecordN counts n equal durations.
func (h *Histogram) RecordN(d time.Duration, n int64) {
	if n <= 0 {
		return
	}
	v := int64(d)
	if v < 1 {
		v = 1
	}
	if v > h.highest {
		v = h.highest
		h.clamped += n
	}
	h.counts[h.index(v)] += n
	h.total += n
	h.sum += float64(v) * float64(n)
	if v < h.min {
		h.min = v
	}
	if v > h.max {
		h.max = v
	}
}

// Count is the number of recorded values.
func (h *Histogram) Count() int64 { return h.total }

// Clamped is how many recorded values exceeded the highest trackable value.
func (h *Histogram) Clamped() int64 { return h.clamped }

// Min is the smallest recorded value, or 0 when empty.
func (h *Histogram) Min() time.Duration {
	if h.total == 0 {
		return 0
	}
	return time.Duration(h.min)
}

// Max is the largest recorded value, or 0 when empty.
func (h *Histogram) Max() time.Duration { return time.Duration(h.max) }

// Mean is the arithmetic mean of the recorded values, or 0 when empty.
func (h *Histogram) Mean() time.Duration {
	if h.total == 0 {
		return 0
	}
	return time.Duration(h.sum / float64(h.total))
}

// Quantile returns the value at quantile q in [0, 1]: the highest value
// equivalent to the smallest recorded value with at least q of the count at
// or below it, capped at Max. Quantile(1) is Max; an empty histogram
// answers 0.
func (h *Histogram) Quantile(q float64) time.Duration {
	if h.total == 0 {
		return 0
	}
	if q >= 1 {
		return time.Duration(h.max)
	}
	if q < 0 {
		q = 0
	}
	want := int64(math.Ceil(q * float64(h.total)))
	if want < 1 {
		want = 1
	}
	var seen int64
	for i, c := range h.counts {
		seen += c
		if seen >= want {
			v := h.highestAt(i)
			if v > h.max {
				v = h.max
			}
			if v < h.min {
				v = h.min
			}
			return time.Duration(v)
		}
	}
	return time.Duration(h.max)
}

// Merge adds o's counts to h. Both must have been made with the same
// highest value and digits.
func (h *Histogram) Merge(o *Histogram) error {
	if o.highest != h.highest || o.digits != h.digits {
		return errors.New("hdr: merging histograms with different settings")
	}
	if o.total == 0 {
		return nil
	}
	for i, c := range o.counts {
		h.counts[i] += c
	}
	h.total += o.total
	h.clamped += o.clamped
	h.sum += o.sum
	if o.min < h.min {
		h.min = o.min
	}
	if o.max > h.max {
		h.max = o.max
	}
	return nil
}

// Reset empties h, keeping its settings.
func (h *Histogram) Reset() {
	clear(h.counts)
	h.total, h.clamped, h.sum, h.max = 0, 0, 0, 0
	h.min = math.MaxInt64
}

// wire is the JSON form: the settings and the non-zero buckets as pairs of
// the bucket's lowest value in nanoseconds and its count, ascending. It is
// what results files keep, so runs can be merged and re-read later.
type wire struct {
	Highest int64      `json:"highest_ns"`
	Digits  int        `json:"digits"`
	Clamped int64      `json:"clamped,omitempty"`
	Min     int64      `json:"min_ns"`
	Max     int64      `json:"max_ns"`
	Sum     float64    `json:"sum_ns"`
	Buckets [][2]int64 `json:"buckets"`
}

// MarshalJSON writes the settings, min, max, sum and non-zero buckets.
func (h *Histogram) MarshalJSON() ([]byte, error) {
	w := wire{Highest: h.highest, Digits: h.digits, Clamped: h.clamped, Max: h.max, Sum: h.sum, Buckets: [][2]int64{}}
	if h.total > 0 {
		w.Min = h.min
	}
	for i, c := range h.counts {
		if c != 0 {
			w.Buckets = append(w.Buckets, [2]int64{h.lowestAt(i), c})
		}
	}
	return json.Marshal(w)
}

// UnmarshalJSON reads what MarshalJSON wrote.
func (h *Histogram) UnmarshalJSON(b []byte) error {
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	n, err := New(time.Duration(w.Highest), w.Digits)
	if err != nil {
		return err
	}
	if !sort.SliceIsSorted(w.Buckets, func(i, j int) bool { return w.Buckets[i][0] < w.Buckets[j][0] }) {
		return errors.New("hdr: buckets out of order")
	}
	for _, b := range w.Buckets {
		v, c := b[0], b[1]
		if v < 1 || v > n.highest || c <= 0 {
			return fmt.Errorf("hdr: bad bucket [%d, %d]", v, c)
		}
		i := n.index(v)
		if n.lowestAt(i) != v {
			return fmt.Errorf("hdr: %d is not the start of a bucket", v)
		}
		n.counts[i] += c
		n.total += c
	}
	if n.total > 0 {
		if w.Min < 1 || w.Max < w.Min || w.Max > n.highest {
			return fmt.Errorf("hdr: min %d and max %d do not fit the buckets", w.Min, w.Max)
		}
		n.min, n.max = w.Min, w.Max
	}
	n.clamped, n.sum = w.Clamped, w.Sum
	*h = *n
	return nil
}
