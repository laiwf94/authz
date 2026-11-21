// Package load is an open-loop load generator. Requests are scheduled at a
// fixed rate (or a Poisson process of that rate) decided before the run
// starts, not when the previous request returns, so a slow server cannot
// slow the offered load down. Each request's latency is measured from the
// time it was scheduled to be sent, not from when a worker got round to
// sending it: when the server stalls, the requests queued behind the stall
// are charged for the wait. That is the coordinated-omission correction of
// wrk2 and HdrHistogram, done by construction instead of by back-filling.
// The time from the actual send is kept as well, as service time, so the
// difference between the two shows how much of the latency was queueing in
// the generator.
//
// A run that cannot keep up, because every worker is busy for longer than
// the backlog allows, says so: requests not sent by the end of the drain
// window are counted as Unsent, and Lag is the largest delay between a
// request's scheduled time and the moment a worker took it.
package load

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/laiwf94/authz/bench/hdr"
)

// Op is one kind of request in a mix.
type Op interface {
	// Name labels the operation in results: check, bulk_check, ...
	Name() string
	// Do sends one request and returns an error if the answer was not the
	// expected one. worker is the calling worker's index, in [0, Workers),
	// so an operation can keep per-worker state without locks; rng is the
	// worker's own source.
	Do(ctx context.Context, worker int, rng *rand.Rand) error
}

// Weighted is an operation and its share of the mix.
type Weighted struct {
	Op     Op
	Weight int
}

// Arrival is how scheduled send times are spaced.
type Arrival string

// Arrival processes.
const (
	// Uniform spaces requests exactly 1/Rate apart.
	Uniform Arrival = "uniform"
	// Poisson draws exponential gaps of mean 1/Rate, the arrivals of many
	// independent clients.
	Poisson Arrival = "poisson"
)

// Config is one run.
type Config struct {
	Mix []Weighted
	// Rate is the offered load in requests per second, over all operations.
	Rate float64
	// Warmup requests are sent but not recorded; Duration is the measured
	// part that follows.
	Warmup, Duration time.Duration
	// Workers is the most requests in flight at once.
	Workers int
	// Backlog is how many scheduled requests may wait for a worker before
	// the scheduler waits too; 0 means 4 per worker. Waiting requests are
	// still charged from their scheduled time.
	Backlog int
	// Drain is how long after the last scheduled time requests may still be
	// sent and answered; 0 means 10s. Requests not sent by then are Unsent,
	// and requests still running are cancelled and recorded as errors.
	Drain   time.Duration
	Arrival Arrival
	// Seed makes the schedule, the choice of operation for each slot and
	// every worker's source reproducible.
	Seed uint64
	// Timeout bounds each request; 0 means no limit beyond Drain.
	Timeout time.Duration
	// Highest is the highest latency histograms track; 0 means one minute.
	Highest time.Duration
	// Now and Sleep are the clock, for tests; nil means the real one.
	Now   func() time.Time
	Sleep func(time.Duration)
}

// OpResult is one operation's measurements.
type OpResult struct {
	Name string
	// Latency is from the scheduled send time to the answer: the corrected
	// figure. Service is from the actual send to the answer.
	Latency, Service *hdr.Histogram
	OK, Errors       int64
	// ErrorSamples are the first distinct error messages, at most five.
	ErrorSamples []string
}

// Result is a whole run.
type Result struct {
	Ops []*OpResult // in mix order
	// Scheduled counts measured requests the schedule asked for; Sent of
	// those were sent; Unsent were not sent before the drain ended.
	Scheduled, Sent, Unsent int64
	// Lag is the largest delay between a scheduled time and a worker
	// starting the request, over the measured part.
	Lag time.Duration
	// Elapsed is from the start of the measured part to its last answer.
	Elapsed time.Duration
	Start   time.Time
}

// Achieved is the rate of answered requests over the measured part.
func (r *Result) Achieved() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	var n int64
	for _, o := range r.Ops {
		n += o.OK + o.Errors
	}
	return float64(n) / r.Elapsed.Seconds()
}

// Total merges every operation's histograms and counts into one.
func (r *Result) Total() *OpResult {
	t := &OpResult{Name: "all"}
	for _, o := range r.Ops {
		if t.Latency == nil {
			t.Latency, t.Service = clone(o.Latency), clone(o.Service)
		} else {
			t.Latency.Merge(o.Latency)
			t.Service.Merge(o.Service)
		}
		t.OK += o.OK
		t.Errors += o.Errors
	}
	return t
}

func clone(h *hdr.Histogram) *hdr.Histogram {
	b, _ := h.MarshalJSON()
	var c hdr.Histogram
	c.UnmarshalJSON(b)
	return &c
}

type job struct {
	op    int
	at    time.Time
	timed bool // in the measured part
}

type workerStats struct {
	lat, svc []*hdr.Histogram
	ok, errs []int64
	samples  [][]string
	lag      time.Duration
	sent     int64
	last     time.Time
}

func (c *Config) validate() error {
	if len(c.Mix) == 0 {
		return errors.New("load: empty mix")
	}
	for _, w := range c.Mix {
		if w.Op == nil || w.Weight <= 0 {
			return errors.New("load: every operation in the mix needs a positive weight")
		}
	}
	if c.Rate <= 0 {
		return errors.New("load: rate must be positive")
	}
	if c.Duration <= 0 || c.Warmup < 0 {
		return errors.New("load: duration must be positive and warmup not negative")
	}
	if c.Workers <= 0 {
		return errors.New("load: workers must be positive")
	}
	switch c.Arrival {
	case "", Uniform, Poisson:
	default:
		return fmt.Errorf("load: unknown arrival process %q", c.Arrival)
	}
	return nil
}

// Run offers the load and returns the measurements. It returns early with
// ctx's error if ctx ends; the partial result is not returned then.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	now, sleep := cfg.Now, cfg.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	backlog := cfg.Backlog
	if backlog <= 0 {
		backlog = 4 * cfg.Workers
	}
	drain := cfg.Drain
	if drain <= 0 {
		drain = 10 * time.Second
	}
	highest := cfg.Highest
	if highest <= 0 {
		highest = time.Minute
	}
	if _, err := hdr.New(highest, 3); err != nil {
		return nil, err
	}

	// The cumulative weights pick an operation per slot.
	cum := make([]int, len(cfg.Mix))
	total := 0
	for i, w := range cfg.Mix {
		total += w.Weight
		cum[i] = total
	}
	sched := rand.New(rand.NewPCG(cfg.Seed, 0x5eed))
	pick := func() int {
		n := sched.IntN(total)
		return sort.SearchInts(cum, n+1)
	}

	start := now()
	measured := start.Add(cfg.Warmup)
	end := measured.Add(cfg.Duration)
	deadline := end.Add(drain)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan job, backlog)
	stats := make([]*workerStats, cfg.Workers)
	var wg sync.WaitGroup
	for w := range cfg.Workers {
		st := &workerStats{ok: make([]int64, len(cfg.Mix)), errs: make([]int64, len(cfg.Mix)), samples: make([][]string, len(cfg.Mix))}
		for range cfg.Mix {
			st.lat = append(st.lat, hdr.MustNew(highest, 3))
			st.svc = append(st.svc, hdr.MustNew(highest, 3))
		}
		stats[w] = st
		rng := rand.New(rand.NewPCG(cfg.Seed, uint64(w)+1))
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := range jobs {
				began := now()
				if j.timed {
					if l := began.Sub(j.at); l > st.lag {
						st.lag = l
					}
					st.sent++
				}
				opCtx := runCtx
				var opCancel context.CancelFunc
				if cfg.Timeout > 0 {
					opCtx, opCancel = context.WithTimeout(runCtx, cfg.Timeout)
				}
				err := cfg.Mix[j.op].Op.Do(opCtx, w, rng)
				if opCancel != nil {
					opCancel()
				}
				done := now()
				if !j.timed {
					continue
				}
				if done.After(st.last) {
					st.last = done
				}
				st.lat[j.op].Record(done.Sub(j.at))
				st.svc[j.op].Record(done.Sub(began))
				if err != nil {
					st.errs[j.op]++
					if s := err.Error(); len(st.samples[j.op]) < 5 && !contains(st.samples[j.op], s) {
						st.samples[j.op] = append(st.samples[j.op], s)
					}
				} else {
					st.ok[j.op]++
				}
			}
		}(w)
	}
	// Cancel requests still running at the deadline.
	stop := make(chan struct{})
	go func() {
		if cfg.Now != nil {
			// A test clock: the scheduler enforces the deadline alone.
			<-stop
			return
		}
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		select {
		case <-t.C:
			cancel()
		case <-stop:
		}
	}()

	var scheduled, unsent int64
	interval := float64(time.Second) / cfg.Rate
	var offset float64 // nanoseconds from start
	var err error
	for {
		at := start.Add(time.Duration(offset))
		if !at.Before(end) {
			break
		}
		if cfg.Arrival == Poisson {
			offset += sched.ExpFloat64() * interval
		} else {
			offset += interval
		}
		j := job{op: pick(), at: at, timed: !at.Before(measured)}
		if j.timed {
			scheduled++
		}
		if d := at.Sub(now()); d > 0 {
			sleep(d)
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			break
		}
		if !now().Before(deadline) {
			if j.timed {
				unsent++
			}
			continue
		}
		select {
		case jobs <- j:
		case <-runCtx.Done():
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if j.timed {
				unsent++
			}
		}
		if err != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	close(stop)
	if err != nil {
		return nil, err
	}

	res := &Result{Scheduled: scheduled, Unsent: unsent, Start: measured}
	var last time.Time
	for i, w := range cfg.Mix {
		o := &OpResult{Name: w.Op.Name(), Latency: hdr.MustNew(highest, 3), Service: hdr.MustNew(highest, 3)}
		for _, st := range stats {
			o.Latency.Merge(st.lat[i])
			o.Service.Merge(st.svc[i])
			o.OK += st.ok[i]
			o.Errors += st.errs[i]
			for _, s := range st.samples[i] {
				if len(o.ErrorSamples) < 5 && !contains(o.ErrorSamples, s) {
					o.ErrorSamples = append(o.ErrorSamples, s)
				}
			}
		}
		res.Ops = append(res.Ops, o)
	}
	for _, st := range stats {
		res.Sent += st.sent
		if st.lag > res.Lag {
			res.Lag = st.lag
		}
		if st.last.After(last) {
			last = st.last
		}
	}
	// Requests the drain cut off were sent but never sent back in time:
	// they are in Errors already. Elapsed covers at least the window.
	res.Elapsed = cfg.Duration
	if e := last.Sub(measured); e > res.Elapsed {
		res.Elapsed = e
	}
	return res, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
