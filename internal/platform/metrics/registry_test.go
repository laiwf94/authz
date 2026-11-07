package metrics

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/tracks.golden")

func write(t testing.TB, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestTracksGolden: the exposition of every family the three tracks register
// is byte for byte what the old packages wrote (the golden file was recorded
// with internal/metrics before it was removed).
func TestTracksGolden(t *testing.T) {
	r := New()
	registerTracks(r)
	got := write(t, r)
	path := filepath.Join("testdata", "tracks.golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("exposition differs from %s:\n%s", path, lineDiff(string(want), got))
	}
	// Registering everything again, as each subcommand would on its own
	// registry, finds the same series and changes nothing but the values.
	registerTracks(r)
	if again := write(t, r); strings.Count(again, "\n") != strings.Count(got, "\n") {
		t.Errorf("re-registering changed the series:\n%s", lineDiff(got, again))
	}
}

func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < max(len(w), len(g)); i++ {
		var a, c string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			c = g[i]
		}
		if a != c {
			fmt.Fprintf(&b, "line %d:\n  want %q\n  got  %q\n", i+1, a, c)
		}
	}
	return b.String()
}

// TestTrackNames: every metric name registered anywhere in the three tracks'
// sources is in the golden exposition, so the golden file is the union of
// their names and a new metric must be added to it.
func TestTrackNames(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "tracks.golden"))
	if err != nil {
		t.Fatal(err)
	}
	families := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (\S+) `).FindAllSubmatch(golden, -1) {
		families[string(m[1])] = true
	}
	methods := map[string]bool{"Counter": true, "Histogram": true, "HistogramBuckets": true, "Gauge": true, "GaugeSeries": true, "count": true}
	names := map[string]string{}  // name -> where
	suffixes := map[string]bool{} // Prefix + "_suffix"
	var prefixes []string
	fset := token.NewFileSet()
	for _, tree := range []string{"../../authz", "../../authn", "../../agents", "../../../cmd/authz"} {
		err := filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.KeyValueExpr:
					if id, ok := n.Key.(*ast.Ident); ok && id.Name == "Prefix" {
						if s, ok := stringLit(n.Value); ok {
							prefixes = append(prefixes, s)
						}
					}
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if !ok || !methods[sel.Sel.Name] || len(n.Args) < 2 {
						return true
					}
					if s, ok := stringLit(n.Args[0]); ok {
						names[s] = fset.Position(n.Pos()).String()
					} else if be, ok := n.Args[0].(*ast.BinaryExpr); ok && be.Op == token.ADD {
						if s, ok := stringLit(be.Y); ok {
							suffixes[s] = true
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(names) < 25 || len(suffixes) < 2 || len(prefixes) < 2 {
		t.Fatalf("source scan found too little: %d names, %d suffixes, %d prefixes", len(names), len(suffixes), len(prefixes))
	}
	for s := range suffixes {
		for _, p := range prefixes {
			names[p+s] = "Prefix " + strconv.Quote(p) + " + " + strconv.Quote(s)
		}
	}
	for n, where := range names {
		if !families[n] {
			t.Errorf("%s registers %s, which testdata/tracks.golden lacks; add it to registerTracks", where, n)
		}
	}
	for f := range families {
		if _, ok := names[f]; !ok {
			t.Errorf("testdata/tracks.golden has %s, which no track registers any more", f)
		}
	}
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

func TestSeriesCap(t *testing.T) {
	r := New()
	r.Limit(3)
	var cs []*Counter
	for i := range 5 {
		cs = append(cs, r.Counter("tool_calls_total", Labels("tool", fmt.Sprint("t", i)), "Tool calls."))
	}
	for _, c := range cs {
		c.Inc()
	}
	if cs[3] != cs[4] {
		t.Fatal("label sets past the cap are not folded into one series")
	}
	if again := r.Counter("tool_calls_total", Labels("tool", "t0"), "Tool calls."); again != cs[0] {
		t.Fatal("a series under the cap was not reused")
	}
	// The overflow series asked for by name is the same one.
	if r.Counter("tool_calls_total", OverflowLabels, "Tool calls.") != cs[3] {
		t.Fatal("overflow series not shared")
	}
	r.Histogram("lat_seconds", "", "L.").Observe(time.Millisecond)
	r.LimitFamily("lat_seconds", 1)
	r.Histogram("lat_seconds", `a="1"`, "L.").Observe(time.Millisecond)
	r.Histogram("lat_seconds", `a="2"`, "L.").Observe(time.Millisecond)
	r.GaugeSeries("depth", `q="a"`, "D.").Set(1)
	r.LimitFamily("depth", 1)
	r.GaugeSeries("depth", `q="b"`, "D.").Set(2)
	r.GaugeSeries("depth", `q="c"`, "D.").Add(3)

	out := write(t, r)
	for _, want := range []string{
		`tool_calls_total{tool="t0"} 1`,
		`tool_calls_total{tool="t2"} 1`,
		`tool_calls_total{overflow="true"} 2`,
		`lat_seconds_count 1`,
		`lat_seconds_count{overflow="true"} 2`,
		`depth{q="a"} 1`,
		`depth{overflow="true"} 5`,
		"# TYPE authz_metrics_overflow_total counter",
		`authz_metrics_overflow_total{metric="depth"} 2`,
		`authz_metrics_overflow_total{metric="lat_seconds"} 2`,
		`authz_metrics_overflow_total{metric="tool_calls_total"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `t3`) || strings.Contains(out, `q="b"`) {
		t.Errorf("a series past the cap was created:\n%s", out)
	}

	// A family registered through LimitFamily first takes the type of its
	// first series.
	r2 := New()
	r2.LimitFamily("later_total", 1)
	r2.Counter("later_total", `a="1"`, "Later.").Inc()
	r2.Counter("later_total", `a="2"`, "Later.").Inc()
	if out := write(t, r2); !strings.Contains(out, "# HELP later_total Later.\n# TYPE later_total counter\n") ||
		!strings.Contains(out, `later_total{overflow="true"} 1`) {
		t.Errorf("LimitFamily before registration:\n%s", out)
	}
	if out := write(t, New()); out != "" {
		t.Errorf("empty registry wrote %q", out)
	}
}

func TestDefaultLimit(t *testing.T) {
	r := New()
	for i := range DefaultLimit + 10 {
		r.Counter("c_total", Labels("i", strconv.Itoa(i)), "C.").Inc()
	}
	out := write(t, r)
	if n := strings.Count(out, "\nc_total{i="); n != DefaultLimit {
		t.Errorf("%d series kept, want %d", n, DefaultLimit)
	}
	if !strings.Contains(out, `c_total{overflow="true"} 10`) {
		t.Error("overflow series missing")
	}
}

func TestGaugeSeries(t *testing.T) {
	r := New()
	g := r.GaugeSeries("inflight", `server="gateway"`, "In-flight requests.")
	if r.GaugeSeries("inflight", `server="gateway"`, "In-flight requests.") != g {
		t.Fatal("gauge not reused")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				g.Inc()
				g.Add(0.5)
				g.Dec()
			}
		}()
	}
	wg.Wait()
	if g.Value() != 4000 {
		t.Fatalf("value %v after concurrent updates, want 4000", g.Value())
	}
	g.Set(-1.25)
	r.GaugeSeries("inflight", `server="admin"`, "In-flight requests.").Set(math.Inf(1))
	r.Gauge("up", "Up.", func() float64 { return 1 })
	r.Gauge("up", "Up.", func() float64 { return 2 }) // replaced
	r.Gauge("weird", "W.", func() float64 { return math.NaN() })
	r.GaugeSeries("low", "", "L.").Set(math.Inf(-1))
	out := write(t, r)
	want := "# HELP inflight In-flight requests.\n# TYPE inflight gauge\n" +
		"inflight{server=\"admin\"} +Inf\ninflight{server=\"gateway\"} -1.25\n" +
		"# HELP low L.\n# TYPE low gauge\nlow -Inf\n" +
		"# HELP up Up.\n# TYPE up gauge\nup 2\n" +
		"# HELP weird W.\n# TYPE weird gauge\nweird NaN\n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// TestGaugeFuncUsesRegistry: a gauge function runs without the lock held, so
// it can read or create other metrics. Counters are written before gauges,
// so the second scrape shows the increment the first one made.
func TestGaugeFuncUsesRegistry(t *testing.T) {
	r := New()
	c := r.Counter("hits_total", "", "Hits.")
	c.Add(3)
	r.Gauge("hits_seen", "Hits seen.", func() float64 {
		r.Counter("scrapes_total", "", "Scrapes.").Inc()
		return float64(r.Counter("hits_total", "", "Hits.").Value())
	})
	done := make(chan string)
	go func() { done <- write(t, r) }()
	select {
	case out := <-done:
		if !strings.Contains(out, "hits_seen 3\n") {
			t.Errorf("gauge value missing:\n%s", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write deadlocked on a gauge function that uses the registry")
	}
	if !strings.Contains(write(t, r), "scrapes_total 1\n") {
		t.Error("counter created from a gauge function not written")
	}
}

func TestHistogramBuckets(t *testing.T) {
	r := New()
	bounds := []float64{0.001, 0.01, 0.1}
	h := r.HistogramBuckets("wal_fsync_seconds", `stream="relationships"`, "Fsync latency.", bounds)
	bounds[0] = 99 // the registry keeps its own copy
	h.Observe(500 * time.Microsecond)
	h.Observe(50 * time.Millisecond)
	h.Observe(time.Second)
	h.Observe(-time.Second) // counts as zero
	if r.HistogramBuckets("wal_fsync_seconds", `stream="relationships"`, "Fsync latency.", []float64{0.001, 0.01, 0.1}) != h {
		t.Fatal("histogram not reused")
	}
	out := write(t, r)
	want := "# HELP wal_fsync_seconds Fsync latency.\n# TYPE wal_fsync_seconds histogram\n" +
		`wal_fsync_seconds_bucket{stream="relationships",le="0.001"} 2` + "\n" +
		`wal_fsync_seconds_bucket{stream="relationships",le="0.01"} 2` + "\n" +
		`wal_fsync_seconds_bucket{stream="relationships",le="0.1"} 3` + "\n" +
		`wal_fsync_seconds_bucket{stream="relationships",le="+Inf"} 4` + "\n" +
		`wal_fsync_seconds_sum{stream="relationships"} 1.0505` + "\n" +
		`wal_fsync_seconds_count{stream="relationships"} 4` + "\n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestMisusePanics(t *testing.T) {
	cases := []struct {
		name string
		fn   func(r *Registry)
		want string
	}{
		{"counter then histogram", func(r *Registry) {
			r.Counter("x_total", "", "X.")
			r.Histogram("x_total", "", "X.")
		}, "x_total is a counter, not a histogram"},
		{"histogram then gauge", func(r *Registry) {
			r.Histogram("x", "", "X.")
			r.GaugeSeries("x", `a="1"`, "X.")
		}, "x is a histogram, not a gauge"},
		{"gauge func then counter", func(r *Registry) {
			r.Gauge("x", "X.", func() float64 { return 0 })
			r.Counter("x", `a="1"`, "X.")
		}, "x is a gauge, not a counter"},
		{"gauge func then settable", func(r *Registry) {
			r.Gauge("x", "X.", func() float64 { return 0 })
			r.GaugeSeries("x", "", "X.")
		}, "already a gauge read from a function"},
		{"settable then gauge func", func(r *Registry) {
			r.GaugeSeries("x", "", "X.")
			r.Gauge("x", "X.", func() float64 { return 0 })
		}, "already a settable gauge"},
		{"two bucket layouts", func(r *Registry) {
			r.Histogram("x", `a="1"`, "X.")
			r.HistogramBuckets("x", `a="2"`, "X.", []float64{1, 2})
		}, "already has buckets"},
		{"no buckets", func(r *Registry) { r.HistogramBuckets("x", "", "X.", nil) }, "no buckets"},
		{"unsorted buckets", func(r *Registry) { r.HistogramBuckets("x", "", "X.", []float64{1, 1}) }, "strictly increasing"},
		{"infinite bucket", func(r *Registry) { r.HistogramBuckets("x", "", "X.", []float64{1, math.Inf(1)}) }, "not finite"},
		{"NaN bucket", func(r *Registry) { r.HistogramBuckets("x", "", "X.", []float64{math.NaN()}) }, "not finite"},
		{"le on a histogram", func(r *Registry) { r.Histogram("x", `le="1"`, "X.") }, "reserved"},
		{"empty name", func(r *Registry) { r.Counter("", "", "X.") }, "invalid metric name"},
		{"name with dash", func(r *Registry) { r.Counter("a-b", "", "X.") }, "invalid metric name"},
		{"name with digit first", func(r *Registry) { r.Gauge("1a", "X.", nil) }, "invalid metric name"},
		{"LimitFamily bad name", func(r *Registry) { r.LimitFamily("a b", 1) }, "invalid metric name"},
		{"LimitFamily zero", func(r *Registry) { r.LimitFamily("a", 0) }, "below 1"},
		{"Limit zero", func(r *Registry) { r.Limit(0) }, "below 1"},
		{"odd Labels", func(r *Registry) { Labels(strings.Fields("a")...) }, "pairs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				p := recover()
				if p == nil || !strings.Contains(fmt.Sprint(p), tc.want) {
					t.Fatalf("panic %v, want one containing %q", p, tc.want)
				}
			}()
			tc.fn(New())
		})
	}
}

func TestCheckLabels(t *testing.T) {
	good := []string{
		"",
		`a="b"`,
		`a="",b="c"`,
		`route="/v1/check",code="200"`,
		`v="quote \" backslash \\ newline \n"`,
		`_x9="é ✓"`,
		`le="1"`, // only reserved on histograms
	}
	for _, s := range good {
		if err := checkLabels(s, false); err != nil {
			t.Errorf("checkLabels(%q) = %v", s, err)
		}
	}
	bad := map[string]string{
		`a`:              "expected name",
		`a=b`:            "expected name",
		`="b"`:           "invalid label name",
		`1a="b"`:         "invalid label name",
		`a-b="c"`:        "invalid label name",
		`__name__="x"`:   "invalid label name",
		`a="b",a="c"`:    "repeated",
		`a="b`:           "unterminated",
		`a="b\"`:         "unterminated",
		`a="\t"`:         "invalid escape",
		`a="\`:           "invalid escape",
		"a=\"x\ny\"":     "raw line feed",
		"a=\"\xff\"":     "not UTF-8",
		`a="b"b="c"`:     "expected a comma",
		`a="b",`:         "expected a comma",
		`a="b",,c="d"`:   "invalid label name",
		`a="b" , c="d"`:  "expected a comma",
		`a="b"}{c="d"`:   "expected a comma",
		`a="b",c="d"x`:   "expected a comma",
		`a="x\u0001"`:    "invalid escape",
		`a="x\\"y"`:      "expected a comma",
		`a="b",c="d",e=`: "expected name",
	}
	for s, want := range bad {
		err := checkLabels(s, false)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("checkLabels(%q) = %v, want an error containing %q", s, err, want)
		}
	}
	// Each failure panics at registration with the series in the message.
	defer func() {
		if p := recover(); p == nil || !strings.Contains(fmt.Sprint(p), `x_total{a="b}`) {
			t.Errorf("panic %v", p)
		}
	}()
	New().Counter("x_total", `a="b`, "X.")
}

// TestLabels: Labels escapes any value into a label set checkLabels accepts,
// and for printable values it renders what the old %q-built sets did.
func TestLabels(t *testing.T) {
	for _, v := range []string{"", "files", "/v1/check", `say "hi"`, `back\slash`, "multi\nline", "é ✓ 漢字", "tab\there", "nul\x00", "bad\xffutf8"} {
		if l := Labels("upstream", "u", "tool", v); checkLabels(l, false) != nil {
			t.Errorf("Labels(%q) = %s: %v", v, l, checkLabels(l, false))
		}
	}
	for _, v := range []string{"", "files", "/v1/check", "tools/call", `say "hi"`, `back\slash`, "multi\nline", "é ✓ 漢字"} {
		if l, old := Labels("upstream", "u", "tool", v), fmt.Sprintf(`upstream=%q,tool=%q`, "u", v); l != old {
			t.Errorf("Labels(%q) = %s, %%q gave %s", v, l, old)
		}
	}
	if got := Labels("a", "x\"y\\z\nw", "b", "\xff"); got != `a="x\"y\\z\nw",b="`+"\uFFFD"+`"` {
		t.Errorf("Labels = %s", got)
	}
	if Labels() != "" {
		t.Error("Labels() not empty")
	}
	r := New()
	r.Counter("tool_calls_total", Labels("tool", "evil\"} 999\nfake_metric 1"), "Calls.").Inc()
	out := write(t, r)
	if strings.Contains(out, "\nfake_metric") {
		t.Errorf("a label value injected a line:\n%s", out)
	}
}

func TestHelpEscaped(t *testing.T) {
	r := New()
	r.Counter("x_total", "", "Line one\nline two \\ end.").Inc()
	if out := write(t, r); !strings.HasPrefix(out, `# HELP x_total Line one\nline two \\ end.`+"\n") {
		t.Errorf("help not escaped:\n%s", out)
	}
}

func TestFormatFloatSpecial(t *testing.T) {
	for in, want := range map[float64]string{math.Inf(1): "+Inf", math.Inf(-1): "-Inf", -2.5: "-2.5", 1e-7: "0", 1234567: "1234567"} {
		if got := formatFloat(in); got != want {
			t.Errorf("formatFloat(%v) = %q, want %q", in, got, want)
		}
	}
	if formatFloat(math.NaN()) != "NaN" {
		t.Error("NaN")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("disk full") }

func TestWriteError(t *testing.T) {
	r := New()
	r.Counter("x_total", "", "X.").Inc()
	if err := r.Write(failWriter{}); err == nil || err.Error() != "disk full" {
		t.Fatalf("Write = %v", err)
	}
}

// TestConcurrent registers, updates and scrapes from many goroutines under
// the race detector; the totals must add up.
func TestConcurrent(t *testing.T) {
	r := New()
	r.Limit(16)
	const workers, rounds = 8, 2000
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range rounds {
				l := Labels("tool", strconv.Itoa((w*rounds+i)%32))
				r.Counter("calls_total", l, "Calls.").Inc()
				r.Histogram("lat_seconds", l, "Latency.").Observe(time.Duration(i) * time.Microsecond)
				r.GaugeSeries("open", l, "Open.").Inc()
				if i%500 == 0 {
					var b bytes.Buffer
					if err := r.Write(&b); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()
	out := write(t, r)
	var sum uint64
	for _, m := range regexp.MustCompile(`(?m)^calls_total\{[^}]*\} (\d+)$`).FindAllStringSubmatch(out, -1) {
		n, _ := strconv.ParseUint(m[1], 10, 64)
		sum += n
	}
	if sum != workers*rounds {
		t.Errorf("counters sum to %d, want %d", sum, workers*rounds)
	}
	if n := strings.Count(out, "\ncalls_total{"); n != 17 {
		t.Errorf("%d counter series, want 16 and the overflow series", n)
	}
	if !strings.Contains(out, fmt.Sprintf(`lat_seconds_count{overflow="true"} %d`, workers*rounds/2)) {
		t.Errorf("overflow histogram count wrong:\n%s", out)
	}
}

// BenchmarkCounterLookup is the hot path every request takes: find the
// series by name and labels, then add one.
func BenchmarkCounterLookup(b *testing.B) {
	r := New()
	registerTracks(r)
	labels := `route="/v1/check",code="200"`
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.Counter("grantd_http_requests_total", labels, "HTTP requests.").Inc()
		}
	})
}

func BenchmarkHistogramObserve(b *testing.B) {
	h := New().Histogram("lat_seconds", `route="/x"`, "L.")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.Observe(300 * time.Microsecond)
		}
	})
}

func BenchmarkWrite(b *testing.B) {
	r := New()
	registerTracks(r)
	for i := range 500 {
		r.Counter("toolgate_tool_calls_total", Labels("upstream", "u", "tool", strconv.Itoa(i), "outcome", "allowed"), "Tool calls by outcome.").Inc()
	}
	var buf bytes.Buffer
	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		if err := r.Write(&buf); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(buf.Len()))
}
