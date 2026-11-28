package metrics

import (
	"fmt"
	"strings"
	"testing"
)

func TestCollect(t *testing.T) {
	r := New()
	r.Gauge("a_first", "Before.", func() float64 { return 1 })
	r.GaugeSeries("z_last", `k="v"`, "After.").Set(2)
	rows := map[string]float64{"r1": 3, "r2": 0.5}
	r.Collect([]GaugeFamily{{"m_rows", "Rows by name."}, {"m_total_rows", "All rows."}}, func(emit func(string, string, float64)) {
		sum := 0.0
		for name, v := range rows {
			emit("m_rows", Labels("name", name), v)
			sum += v
		}
		emit("m_total_rows", "", sum)
	})
	want := `# HELP a_first Before.
# TYPE a_first gauge
a_first 1
# HELP m_rows Rows by name.
# TYPE m_rows gauge
m_rows{name="r1"} 3
m_rows{name="r2"} 0.5
# HELP m_total_rows All rows.
# TYPE m_total_rows gauge
m_total_rows 3.5
# HELP z_last After.
# TYPE z_last gauge
z_last{k="v"} 2
`
	if got := write(t, r); got != want {
		t.Fatalf("exposition:\n%s\nwant:\n%s", got, want)
	}
	// A series no longer reported is no longer written, and nothing of a
	// family is written when it reports nothing.
	delete(rows, "r1")
	rows["r3"] = 1
	got := write(t, r)
	if strings.Contains(got, `"r1"`) || !strings.Contains(got, `m_rows{name="r3"} 1`) {
		t.Fatalf("after r1 went:\n%s", got)
	}
	clear(rows)
	if got := write(t, r); strings.Contains(got, "m_rows") || !strings.Contains(got, "m_total_rows 0\n") {
		t.Fatalf("with no rows:\n%s", got)
	}
}

func TestCollectCapAndDuplicates(t *testing.T) {
	r := New()
	r.LimitFamily("m", 2)
	n := 5
	r.Collect([]GaugeFamily{{"m", "M."}}, func(emit func(string, string, float64)) {
		for i := range n {
			emit("m", Labels("i", fmt.Sprint(i)), float64(i))
		}
		emit("m", `i="0"`, 10) // reported twice: added up
	})
	got := write(t, r)
	for _, line := range []string{`m{i="0"} 10`, `m{i="1"} 1`, `m{overflow="true"} 9`, `authz_metrics_overflow_total{metric="m"} 3`} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	if strings.Contains(got, `i="2"`) {
		t.Errorf("past the cap:\n%s", got)
	}
	// The cap holds per Write: series under the cap are not held over.
	n = 1
	got = write(t, r)
	if strings.Contains(got, `m{overflow="true"}`) || !strings.Contains(got, `m{i="0"} 10`) {
		t.Errorf("second write:\n%s", got)
	}
	// The fold count is cumulative, like every other family's.
	if !strings.Contains(got, `authz_metrics_overflow_total{metric="m"} 3`) {
		t.Errorf("fold count:\n%s", got)
	}
}

// Registering the same families again replaces the collector, as Gauge
// replaces a function, so a component rebuilt on a shared registry
// reports its own state.
func TestCollectReplaces(t *testing.T) {
	r := New()
	fams := []GaugeFamily{{"m", "M."}, {"n", "N."}}
	r.Collect(fams, func(emit func(string, string, float64)) { emit("m", "", 1) })
	r.Collect(fams, func(emit func(string, string, float64)) { emit("n", "", 2) })
	if got := write(t, r); strings.Contains(got, "m 1") || !strings.Contains(got, "n 2\n") {
		t.Fatalf("after replacing:\n%s", got)
	}
}

func TestCollectMisuse(t *testing.T) {
	one := []GaugeFamily{{"m", "M."}}
	nop := func(func(string, string, float64)) {}
	emitting := func(name, labels string) func(*Registry) {
		return func(r *Registry) {
			r.Collect(one, func(emit func(string, string, float64)) { emit(name, labels, 1) })
			write(t, r)
		}
	}
	cases := []struct {
		name string
		fn   func(r *Registry)
		want string
	}{
		{"no families", func(r *Registry) { r.Collect(nil, nop) }, "no families"},
		{"invalid name", func(r *Registry) { r.Collect([]GaugeFamily{{"a b", ""}}, nop) }, "invalid metric name"},
		{"family with series", func(r *Registry) {
			r.GaugeSeries("m", "", "M.")
			r.Collect(one, nop)
		}, "already has series of its own"},
		{"counter family", func(r *Registry) {
			r.Counter("m", "", "M.")
			r.Collect(one, nop)
		}, "already has series of its own"},
		{"other collector", func(r *Registry) {
			r.Collect([]GaugeFamily{{"m", "M."}, {"n", "N."}}, nop)
			r.Collect(one, nop)
		}, "reported by another collector"},
		{"settable on a collected family", func(r *Registry) {
			r.Collect(one, nop)
			r.GaugeSeries("m", `a="1"`, "M.")
		}, "reported by a collector"},
		{"gauge func on a collected family", func(r *Registry) {
			r.Collect(one, nop)
			r.Gauge("m", "M.", func() float64 { return 0 })
		}, "reported by a collector"},
		{"counter on a collected family", func(r *Registry) {
			r.Collect(one, nop)
			r.Counter("m", "", "M.")
		}, "m is a gauge, not a counter"},
		{"emit unknown name", emitting("n", ""), "reported n"},
		{"emit bad labels", emitting("m", `a=1`), "m{a=1}"},
		{"emit overflow labels", emitting("m", OverflowLabels), "the overflow series is the registry's"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p == nil || !strings.Contains(fmt.Sprint(p), tc.want) {
					t.Fatalf("panic %v, want one containing %q", p, tc.want)
				}
			}()
			tc.fn(New())
		})
	}
}

// A LimitFamily before Collect is kept: the family is not yet typed.
func TestCollectAfterLimitFamily(t *testing.T) {
	r := New()
	r.LimitFamily("m", 1)
	r.Collect([]GaugeFamily{{"m", "M."}}, func(emit func(string, string, float64)) {
		emit("m", `a="1"`, 1)
		emit("m", `a="2"`, 1)
	})
	if got := write(t, r); !strings.Contains(got, `m{overflow="true"} 1`) {
		t.Fatalf("cap lost:\n%s", got)
	}
}
