// Package metrics is the platform's one metrics registry: counters, gauges
// and histograms rendered in the Prometheus text exposition format (version
// 0.0.4), without third-party dependencies. It replaced the three identical
// copies grantd, wicket and toolgate carried (internal/metrics,
// internal/authn/metrics and internal/agents/metrics) in week 2 (#77); the
// exposition of every metric they registered is unchanged byte for byte.
//
// A metric family is a name with one type and one help text. Each distinct
// label set of a family is a series. Series are created on first use and live
// for the life of the registry, so a family's series count is capped (see
// Registry.Limit): a label set past the cap is folded into the family's
// overflow series, the one labelled overflow="true", and
// authz_metrics_overflow_total{metric="NAME"} counts the lookups that were
// folded. Nothing is dropped, and a label value an agent or upstream chose
// cannot grow memory without bound.
//
// Names, label sets, bucket bounds and types are checked when a series is
// created. A mistake there is a programming error and panics: a family
// registered under two types, an invalid metric or label name, a malformed
// label set or a histogram registered with two different bucket layouts.
// Build label sets from values that are not constants with Labels, which
// escapes them as the exposition format requires.
package metrics

import (
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ContentType is the media type of Write's output.
const ContentType = "text/plain; version=0.0.4"

// DefaultLimit is the series cap per family of a new registry.
const DefaultLimit = 2000

// OverflowLabels is the label set a series past its family's cap folds into.
const OverflowLabels = `overflow="true"`

// OverflowMetric counts, per family, the lookups folded into the overflow
// series. It appears in the exposition only once something has overflowed.
const OverflowMetric = "authz_metrics_overflow_total"

type kind uint8

const (
	kindCounter kind = iota + 1
	kindGauge
	kindHistogram
)

func (k kind) String() string {
	switch k {
	case kindCounter:
		return "counter"
	case kindGauge:
		return "gauge"
	default:
		return "histogram"
	}
}

// family is the shared state of one metric name.
type family struct {
	kind   kind
	help   string
	bounds []float64 // histograms only
	series int       // series created, not counting the overflow series
	limit  int       // 0: the registry's limit
	folded atomic.Uint64
}

// Registry holds every metric. The zero value is not usable; call New. All
// methods are safe for concurrent use.
type Registry struct {
	mu         sync.RWMutex
	families   map[string]*family
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	gaugeFns   map[string]func() float64
	histograms map[string]*Histogram
	limit      int
}

// New returns an empty registry with a series cap of DefaultLimit per family.
func New() *Registry {
	return &Registry{
		families:   map[string]*family{},
		counters:   map[string]*Counter{},
		gauges:     map[string]*Gauge{},
		gaugeFns:   map[string]func() float64{},
		histograms: map[string]*Histogram{},
		limit:      DefaultLimit,
	}
}

// Limit sets the series cap of every family that has no cap of its own.
// Series already created stay; only new label sets are folded. n must be at
// least 1.
func (r *Registry) Limit(n int) {
	if n < 1 {
		panic(fmt.Sprintf("metrics: series limit %d is below 1", n))
	}
	r.mu.Lock()
	r.limit = n
	r.mu.Unlock()
}

// LimitFamily sets the series cap of one family, which need not be
// registered yet. n must be at least 1.
func (r *Registry) LimitFamily(name string, n int) {
	if n < 1 {
		panic(fmt.Sprintf("metrics: series limit %d for %s is below 1", n, name))
	}
	if !validName(name) {
		panic(fmt.Sprintf("metrics: invalid metric name %q", name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.families[name]
	if !ok {
		f = &family{}
		r.families[name] = f
	}
	f.limit = n
}

// Counter is a monotonically increasing count.
type Counter struct{ v atomic.Uint64 }

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n.
func (c *Counter) Add(n uint64) { c.v.Add(n) }

// Value returns the current count.
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a value that goes up and down.
type Gauge struct{ bits atomic.Uint64 }

// Set replaces the value.
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Add adds d, which may be negative.
func (g *Gauge) Add(d float64) {
	for {
		old := g.bits.Load()
		if g.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

// Inc adds one.
func (g *Gauge) Inc() { g.Add(1) }

// Dec subtracts one.
func (g *Gauge) Dec() { g.Add(-1) }

// Value returns the current value.
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

// Histogram counts observations into fixed buckets (seconds).
type Histogram struct {
	bounds []float64
	counts []atomic.Uint64 // len(bounds)+1, last is +Inf
	sumNs  atomic.Uint64
	total  atomic.Uint64
}

// DefaultLatencyBuckets covers 50µs to 2.5s.
var DefaultLatencyBuckets = []float64{0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1, 2.5}

// Observe records one duration. A negative duration counts as zero.
func (h *Histogram) Observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s := d.Seconds()
	i := sort.SearchFloat64s(h.bounds, s)
	h.counts[i].Add(1)
	h.sumNs.Add(uint64(d.Nanoseconds()))
	h.total.Add(1)
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 { return h.total.Load() }

// Counter returns the counter with this name and labels, creating it.
// name must be a valid Prometheus metric name; labels are rendered as given,
// e.g. `route="/v1/check",code="200"`.
func (r *Registry) Counter(name, labels, help string) *Counter {
	k := series(name, labels)
	r.mu.RLock()
	c, ok := r.counters[k]
	r.mu.RUnlock()
	if ok {
		return c
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[k]; ok {
		return c
	}
	f, k := r.admit(name, labels, help, kindCounter, nil)
	if c, ok := r.counters[k]; ok {
		return c // the overflow series
	}
	c = &Counter{}
	r.counters[k] = c
	f.created(labels)
	return c
}

// GaugeSeries returns the settable gauge with this name and labels, creating
// it at zero.
func (r *Registry) GaugeSeries(name, labels, help string) *Gauge {
	k := series(name, labels)
	r.mu.RLock()
	g, ok := r.gauges[k]
	r.mu.RUnlock()
	if ok {
		return g
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[k]; ok {
		return g
	}
	if _, ok := r.gaugeFns[k]; ok {
		panic(fmt.Sprintf("metrics: %s is already a gauge read from a function", k))
	}
	f, k := r.admit(name, labels, help, kindGauge, nil)
	if g, ok := r.gauges[k]; ok {
		return g
	}
	g = &Gauge{}
	r.gauges[k] = g
	f.created(labels)
	return g
}

// Gauge registers a function read at scrape time, without labels.
// Registering the same name again replaces the function. fn is called
// without the registry's lock held, so it may use the registry.
func (r *Registry) Gauge(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.gauges[name]; ok {
		panic(fmt.Sprintf("metrics: %s is already a settable gauge", name))
	}
	f := r.family(name, help, kindGauge, nil)
	if _, ok := r.gaugeFns[name]; !ok {
		f.series++
	}
	r.gaugeFns[name] = fn
}

// Histogram returns the histogram with this name and labels, creating it
// with DefaultLatencyBuckets.
func (r *Registry) Histogram(name, labels, help string) *Histogram {
	return r.HistogramBuckets(name, labels, help, DefaultLatencyBuckets)
}

// HistogramBuckets returns the histogram with this name and labels, creating
// it with these upper bounds in seconds, which must be finite and strictly
// increasing. Every series of a family has the same bounds.
func (r *Registry) HistogramBuckets(name, labels, help string, bounds []float64) *Histogram {
	k := series(name, labels)
	r.mu.RLock()
	h, ok := r.histograms[k]
	r.mu.RUnlock()
	if ok {
		return h
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[k]; ok {
		return h
	}
	f, k := r.admit(name, labels, help, kindHistogram, bounds)
	if h, ok := r.histograms[k]; ok {
		return h
	}
	h = &Histogram{bounds: f.bounds, counts: make([]atomic.Uint64, len(f.bounds)+1)}
	r.histograms[k] = h
	f.created(labels)
	return h
}

// created counts a new series against the cap. The overflow series is free.
func (f *family) created(labels string) {
	if labels != OverflowLabels {
		f.series++
	}
}

// admit checks a new series and returns its family and the key it is stored
// under: its own, or the family's overflow series when the family is full.
// r.mu is held.
func (r *Registry) admit(name, labels, help string, k kind, bounds []float64) (*family, string) {
	f := r.family(name, help, k, bounds)
	if err := checkLabels(labels, k == kindHistogram); err != nil {
		panic(fmt.Sprintf("metrics: %s: %v", series(name, labels), err))
	}
	limit := f.limit
	if limit == 0 {
		limit = r.limit
	}
	if labels != OverflowLabels && f.series >= limit {
		f.folded.Add(1)
		return f, series(name, OverflowLabels)
	}
	return f, series(name, labels)
}

// family returns the family of name, creating it, and checks that it has
// this type and these bounds. r.mu is held.
func (r *Registry) family(name, help string, k kind, bounds []float64) *family {
	if !validName(name) {
		panic(fmt.Sprintf("metrics: invalid metric name %q", name))
	}
	f, ok := r.families[name]
	if !ok || f.kind == 0 {
		if !ok {
			f = &family{}
			r.families[name] = f
		}
		if k == kindHistogram {
			if err := checkBounds(bounds); err != nil {
				panic(fmt.Sprintf("metrics: %s: %v", name, err))
			}
			f.bounds = append([]float64(nil), bounds...)
		}
		f.kind = k
		f.help = help
		return f
	}
	if f.kind != k {
		panic(fmt.Sprintf("metrics: %s is a %s, not a %s", name, f.kind, k))
	}
	if k == kindHistogram && !equalBounds(f.bounds, bounds) {
		panic(fmt.Sprintf("metrics: %s already has buckets %v, not %v", name, f.bounds, bounds))
	}
	f.help = help
	return f
}

func checkBounds(b []float64) error {
	if len(b) == 0 {
		return fmt.Errorf("no buckets")
	}
	for i, v := range b {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("bucket bound %v is not finite", v)
		}
		if i > 0 && v <= b[i-1] {
			return fmt.Errorf("bucket bounds are not strictly increasing at %v", v)
		}
	}
	return nil
}

func equalBounds(a, b []float64) bool {
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

func series(name, labels string) string {
	if labels == "" {
		return name
	}
	return name + "{" + labels + "}"
}

func splitSeries(k string) (name, labels string) {
	if i := strings.IndexByte(k, '{'); i >= 0 {
		return k[:i], k[i+1 : len(k)-1]
	}
	return k, ""
}

// Write renders every metric in the Prometheus text exposition format:
// counters, then gauges, then histograms, each in series order. Gauge
// functions are called after the registry's lock is released.
func (r *Registry) Write(w io.Writer) error {
	type sample struct {
		key string
		c   *Counter
		g   *Gauge
		fn  func() float64
		h   *Histogram
	}
	r.mu.RLock()
	counters := make([]sample, 0, len(r.counters)+1)
	gauges := make([]sample, 0, len(r.gauges)+len(r.gaugeFns))
	hists := make([]sample, 0, len(r.histograms))
	help := make(map[string]string, len(r.families)+1)
	for k, c := range r.counters {
		counters = append(counters, sample{key: k, c: c})
	}
	for k, g := range r.gauges {
		gauges = append(gauges, sample{key: k, g: g})
	}
	for k, fn := range r.gaugeFns {
		gauges = append(gauges, sample{key: k, fn: fn})
	}
	for k, h := range r.histograms {
		hists = append(hists, sample{key: k, h: h})
	}
	var overflow []sample
	for name, f := range r.families {
		help[name] = f.help
		if n := f.folded.Load(); n > 0 {
			c := &Counter{}
			c.Add(n)
			overflow = append(overflow, sample{key: series(OverflowMetric, Labels("metric", name)), c: c})
		}
	}
	r.mu.RUnlock()
	if len(overflow) > 0 {
		help[OverflowMetric] = "Series lookups folded into a family's overflow series by its cap."
		counters = append(counters, overflow...)
	}
	byKey := func(s []sample) {
		slices.SortFunc(s, func(a, b sample) int { return strings.Compare(a.key, b.key) })
	}
	byKey(counters)
	byKey(gauges)
	byKey(hists)

	var b strings.Builder
	typed := map[string]bool{}
	header := func(name, typ string) {
		if typed[name] {
			return
		}
		typed[name] = true
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, escapeHelp(help[name]), name, typ)
	}
	for _, s := range counters {
		name, _ := splitSeries(s.key)
		header(name, "counter")
		fmt.Fprintf(&b, "%s %d\n", s.key, s.c.Value())
	}
	for _, s := range gauges {
		name, _ := splitSeries(s.key)
		header(name, "gauge")
		v := 0.0
		if s.fn != nil {
			v = s.fn()
		} else {
			v = s.g.Value()
		}
		fmt.Fprintf(&b, "%s %s\n", s.key, formatFloat(v))
	}
	for _, s := range hists {
		name, labels := splitSeries(s.key)
		header(name, "histogram")
		h := s.h
		sep := ""
		if labels != "" {
			sep = ","
		}
		var cum uint64
		for i, bound := range h.bounds {
			cum += h.counts[i].Load()
			fmt.Fprintf(&b, "%s_bucket{%s%sle=\"%s\"} %d\n", name, labels, sep, formatFloat(bound), cum)
		}
		cum += h.counts[len(h.bounds)].Load()
		fmt.Fprintf(&b, "%s_bucket{%s%sle=\"+Inf\"} %d\n", name, labels, sep, cum)
		fmt.Fprintf(&b, "%s_sum%s %s\n", name, braces(labels), formatFloat(float64(h.sumNs.Load())/1e9))
		fmt.Fprintf(&b, "%s_count%s %d\n", name, braces(labels), h.total.Load())
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func braces(labels string) string {
	if labels == "" {
		return ""
	}
	return "{" + labels + "}"
}

// formatFloat prints f with at most six decimals and no trailing zeros, the
// form every old exposition used.
func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", f), "0"), ".")
}

// Labels renders name/value pairs as a label set, escaping each value as the
// exposition format requires: backslash, double quote and line feed. Invalid
// UTF-8 is replaced with U+FFFD. It panics on an odd number of arguments.
func Labels(kv ...string) string {
	if len(kv)%2 != 0 {
		panic("metrics: Labels needs name/value pairs")
	}
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[i])
		b.WriteString(`="`)
		for _, r := range strings.ToValidUTF8(kv[i+1], "\uFFFD") {
			switch r {
			case '\\':
				b.WriteString(`\\`)
			case '"':
				b.WriteString(`\"`)
			case '\n':
				b.WriteString(`\n`)
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
	}
	return b.String()
}

func escapeHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

// validName reports whether s is a Prometheus metric name.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == ':' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || i > 0 && '0' <= c && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func validLabelName(s string) bool {
	if s == "" || strings.HasPrefix(s, "__") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || i > 0 && '0' <= c && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// checkLabels parses a label set: name="value" pairs separated by commas,
// with \\, \" and \n the only escapes, valid UTF-8 and no repeated name.
// A histogram's labels may not use le, which its buckets add.
func checkLabels(s string, histogram bool) error {
	seen := map[string]bool{}
	for rest := s; rest != ""; {
		eq := strings.Index(rest, `="`)
		if eq < 0 {
			return fmt.Errorf("label set %q: expected name=\"value\"", s)
		}
		name := rest[:eq]
		if !validLabelName(name) {
			return fmt.Errorf("invalid label name %q", name)
		}
		if seen[name] {
			return fmt.Errorf("label %s repeated", name)
		}
		if histogram && name == "le" {
			return fmt.Errorf("label le is reserved for histogram buckets")
		}
		seen[name] = true
		rest = rest[eq+2:]
		end := -1
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case '\\':
				if i+1 >= len(rest) || !strings.ContainsRune(`\"n`, rune(rest[i+1])) {
					return fmt.Errorf("label %s: invalid escape", name)
				}
				i++
			case '\n':
				return fmt.Errorf("label %s: raw line feed", name)
			case '"':
				end = i
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return fmt.Errorf("label %s: unterminated value", name)
		}
		if !utf8.ValidString(rest[:end]) {
			return fmt.Errorf("label %s: value is not UTF-8", name)
		}
		rest = rest[end+1:]
		if rest == "" {
			break
		}
		if rest[0] != ',' || len(rest) == 1 {
			return fmt.Errorf("label set %q: expected a comma between labels", s)
		}
		rest = rest[1:]
	}
	return nil
}
