//go:build ignore

// bench-limit holds micro-benchmarks under fixed limits: the targets the
// roadmap sets for one operation, such as a gateway decision under 2 µs
// with no allocations (#82).
//
//	go test -run '^$' -bench '^BenchmarkDecide$' -benchmem -count 5 ./internal/authn/policy \
//	  | go run scripts/bench-limit.go -limit 'BenchmarkDecide:ns=2000,allocs=0'
//
// It reads `go test -bench -benchmem` output on stdin and copies it to
// stdout. Each -limit names a benchmark (without the -N GOMAXPROCS suffix)
// and its limits: ns, the most nanoseconds per operation, held against the
// median of the runs so one run on a busy machine does not decide; allocs
// and bytes, the most allocations and bytes per operation, held against
// every run. A limited benchmark that did not run, or ran without
// -benchmem when allocs or bytes are limited, fails too.
//
// These are absolute limits, a floor every runner must meet. Regressions
// relative to a baseline are bench/thresholds.json's job (#86).
//
// Exit status: 0 within every limit, 1 over one, 2 usage or input error.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type limit struct {
	name                 string
	ns, allocs, bytes    float64 // -1: no limit
	nsRuns               []float64
	allocsRuns, bytesRun []float64
}

type limits []*limit

func (l *limits) String() string { return "" }

func (l *limits) Set(v string) error {
	name, spec, ok := strings.Cut(v, ":")
	if !ok || name == "" || spec == "" {
		return fmt.Errorf("want NAME:ns=N,allocs=N,bytes=N, got %q", v)
	}
	lim := &limit{name: name, ns: -1, allocs: -1, bytes: -1}
	for _, kv := range strings.Split(spec, ",") {
		k, val, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseFloat(val, 64)
		if !ok || err != nil || n < 0 {
			return fmt.Errorf("bad limit %q in %q", kv, v)
		}
		switch k {
		case "ns":
			lim.ns = n
		case "allocs":
			lim.allocs = n
		case "bytes":
			lim.bytes = n
		default:
			return fmt.Errorf("unknown limit %q in %q: use ns, allocs or bytes", k, v)
		}
	}
	*l = append(*l, lim)
	return nil
}

// A result line: name, iterations, then value-unit pairs.
var line = regexp.MustCompile(`^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+(.*)$`)

func main() {
	var ls limits
	flag.Var(&ls, "limit", "NAME:ns=N,allocs=N,bytes=N (repeatable)")
	flag.Parse()
	if len(ls) == 0 || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: go test -bench ... -benchmem | go run scripts/bench-limit.go -limit NAME:ns=N,allocs=N,bytes=N ...")
		os.Exit(2)
	}
	if err := read(io.TeeReader(os.Stdin, os.Stdout), ls); err != nil {
		fmt.Fprintln(os.Stderr, "bench-limit:", err)
		os.Exit(2)
	}
	if !check(os.Stdout, ls) {
		os.Exit(1)
	}
}

func read(r io.Reader, ls limits) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m := line.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var lim *limit
		for _, l := range ls {
			if l.name == m[1] {
				lim = l
			}
		}
		if lim == nil {
			continue
		}
		f := strings.Fields(m[2])
		if len(f)%2 != 0 {
			return fmt.Errorf("cannot read %q", sc.Text())
		}
		for i := 0; i < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return fmt.Errorf("cannot read %q: %v", sc.Text(), err)
			}
			switch f[i+1] {
			case "ns/op":
				lim.nsRuns = append(lim.nsRuns, v)
			case "allocs/op":
				lim.allocsRuns = append(lim.allocsRuns, v)
			case "B/op":
				lim.bytesRun = append(lim.bytesRun, v)
			}
		}
	}
	return sc.Err()
}

func check(w io.Writer, ls limits) bool {
	ok := true
	fail := func(format string, args ...any) {
		fmt.Fprintf(w, "FAIL "+format+"\n", args...)
		ok = false
	}
	for _, l := range ls {
		if len(l.nsRuns) == 0 {
			fail("%s: did not run", l.name)
			continue
		}
		if l.ns >= 0 {
			runs := slices.Clone(l.nsRuns)
			slices.Sort(runs)
			med := runs[len(runs)/2]
			if len(runs)%2 == 0 {
				med = (runs[len(runs)/2-1] + runs[len(runs)/2]) / 2
			}
			if med > l.ns {
				fail("%s: median %.1f ns/op over %d runs, limit %g", l.name, med, len(runs), l.ns)
			} else {
				fmt.Fprintf(w, "ok   %s: median %.1f ns/op over %d runs, limit %g\n", l.name, med, len(runs), l.ns)
			}
		}
		for _, c := range []struct {
			unit string
			max  float64
			runs []float64
		}{{"allocs/op", l.allocs, l.allocsRuns}, {"B/op", l.bytes, l.bytesRun}} {
			if c.max < 0 {
				continue
			}
			if len(c.runs) != len(l.nsRuns) {
				fail("%s: no %s in every run (run with -benchmem)", l.name, c.unit)
				continue
			}
			worst := slices.Max(c.runs)
			if worst > c.max {
				fail("%s: %g %s, limit %g", l.name, worst, c.unit, c.max)
			} else {
				fmt.Fprintf(w, "ok   %s: at most %g %s, limit %g\n", l.name, worst, c.unit, c.max)
			}
		}
	}
	return ok
}
