package load

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a clock that moves only when the scheduler sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) sleep(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type funcOp struct {
	name string
	n    atomic.Int64
	do   func(ctx context.Context, n int64) error
}

func (f *funcOp) Name() string { return f.name }
func (f *funcOp) Do(ctx context.Context, _ int, _ *rand.Rand) error {
	n := f.n.Add(1)
	if f.do == nil {
		return nil
	}
	return f.do(ctx, n)
}

// A uniform schedule asks for exactly rate × duration measured requests,
// sends warmup requests without recording them, and splits the mix by
// weight the same way for the same seed.
func TestUniformScheduleAndMix(t *testing.T) {
	run := func(seed uint64) (*Result, int64) {
		clk := &fakeClock{t: time.Unix(1000, 0)}
		a, b := &funcOp{name: "a"}, &funcOp{name: "b"}
		res, err := Run(context.Background(), Config{
			Mix:  []Weighted{{a, 3}, {b, 1}},
			Rate: 200, Warmup: 500 * time.Millisecond, Duration: 2 * time.Second, Workers: 4, Seed: seed,
			Now: clk.now, Sleep: clk.sleep})
		if err != nil {
			t.Fatal(err)
		}
		return res, a.n.Load() + b.n.Load()
	}
	res, calls := run(7)
	if res.Scheduled != 400 || res.Sent != 400 || res.Unsent != 0 {
		t.Fatalf("scheduled %d sent %d unsent %d, want 400 400 0", res.Scheduled, res.Sent, res.Unsent)
	}
	if calls != 500 {
		t.Fatalf("%d calls, want 500 with the warmup", calls)
	}
	a, b := res.Ops[0], res.Ops[1]
	if a.Name != "a" || b.Name != "b" || a.OK+b.OK != 400 || a.Errors+b.Errors != 0 {
		t.Fatalf("ops %+v %+v", a, b)
	}
	if a.OK < 260 || a.OK > 340 {
		t.Fatalf("a got %d of 400 with weight 3 of 4", a.OK)
	}
	if a.Latency.Count() != a.OK || a.Service.Count() != a.OK {
		t.Fatalf("histograms count %d and %d, want %d", a.Latency.Count(), a.Service.Count(), a.OK)
	}
	again, _ := run(7)
	if again.Ops[0].OK != a.OK {
		t.Fatalf("same seed split %d then %d", a.OK, again.Ops[0].OK)
	}
	if res.Elapsed != 2*time.Second || res.Achieved() != 200 {
		t.Fatalf("elapsed %v achieved %v", res.Elapsed, res.Achieved())
	}
	tot := res.Total()
	if tot.OK != 400 || tot.Latency.Count() != 400 || tot.Service.Count() != 400 {
		t.Fatalf("total %+v", tot)
	}
	// Total copies the histograms: the operations' own are unchanged.
	if a.Latency.Count() != a.OK {
		t.Fatal("Total changed an operation's histogram")
	}
}

// Poisson arrivals average the rate and are reproducible.
func TestPoissonSchedule(t *testing.T) {
	count := func(seed uint64) int64 {
		clk := &fakeClock{t: time.Unix(0, 0)}
		res, err := Run(context.Background(), Config{Mix: []Weighted{{&funcOp{name: "x"}, 1}}, Rate: 1000,
			Duration: 5 * time.Second, Workers: 2, Arrival: Poisson, Seed: seed, Now: clk.now, Sleep: clk.sleep})
		if err != nil {
			t.Fatal(err)
		}
		return res.Scheduled
	}
	n := count(3)
	if n < 4700 || n > 5300 {
		t.Fatalf("%d arrivals in 5s at 1000/s", n)
	}
	if count(3) != n {
		t.Fatal("same seed, different schedule")
	}
	if count(4) == n {
		t.Fatal("different seeds, same count")
	}
}

// A stall charges every request scheduled behind it from its due time: the
// corrected latency shows the queue the stall built while service time,
// measured from the send, does not.
func TestStallIsChargedToQueuedRequests(t *testing.T) {
	op := &funcOp{name: "stall", do: func(_ context.Context, n int64) error {
		if n == 10 {
			time.Sleep(300 * time.Millisecond)
		}
		return nil
	}}
	res, err := Run(context.Background(), Config{Mix: []Weighted{{op, 1}}, Rate: 100, Duration: time.Second,
		Workers: 1, Backlog: 2, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	o := res.Ops[0]
	if res.Unsent != 0 || o.OK != res.Scheduled || o.OK < 99 {
		t.Fatalf("ok %d of %d, unsent %d", o.OK, res.Scheduled, res.Unsent)
	}
	// About 30 requests were due during the stall, waiting 290 ms down to
	// 10 ms: well over a tenth of the run is above 100 ms.
	if p := o.Latency.Quantile(0.9); p < 100*time.Millisecond {
		t.Fatalf("corrected p90 %v, want the queue behind the stall", p)
	}
	if m := o.Latency.Max(); m < 300*time.Millisecond {
		t.Fatalf("corrected max %v, want at least the stall", m)
	}
	if p := o.Service.Quantile(0.9); p > 50*time.Millisecond {
		t.Fatalf("service p90 %v, want only the stalled request slow", p)
	}
	if res.Lag < 250*time.Millisecond {
		t.Fatalf("lag %v, want the time requests waited", res.Lag)
	}
}

// A server that never answers: requests are cut off at the drain deadline
// and counted as errors, and the ones never sent as unsent.
func TestDrainCutsOffAndCountsUnsent(t *testing.T) {
	op := &funcOp{name: "hang", do: func(ctx context.Context, _ int64) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	start := time.Now()
	res, err := Run(context.Background(), Config{Mix: []Weighted{{op, 1}}, Rate: 100, Duration: 200 * time.Millisecond,
		Workers: 2, Backlog: 1, Drain: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("run took %v with a 300ms deadline", d)
	}
	o := res.Ops[0]
	if o.OK != 0 || o.Errors == 0 || res.Unsent == 0 || res.Sent+res.Unsent != res.Scheduled {
		t.Fatalf("ok %d errors %d sent %d unsent %d scheduled %d", o.OK, o.Errors, res.Sent, res.Unsent, res.Scheduled)
	}
	if len(o.ErrorSamples) != 1 || o.ErrorSamples[0] != context.Canceled.Error() {
		t.Fatalf("samples %q", o.ErrorSamples)
	}
	if res.Elapsed < 200*time.Millisecond {
		t.Fatalf("elapsed %v", res.Elapsed)
	}
}

// Each request has its own timeout, and error samples keep the first five
// distinct messages.
func TestTimeoutAndErrorSamples(t *testing.T) {
	op := &funcOp{name: "e", do: func(ctx context.Context, n int64) error {
		if n%2 == 0 {
			<-ctx.Done()
			return ctx.Err()
		}
		return fmt.Errorf("bad answer %d", n%14)
	}}
	res, err := Run(context.Background(), Config{Mix: []Weighted{{op, 1}}, Rate: 400, Duration: 250 * time.Millisecond,
		Workers: 8, Timeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	o := res.Ops[0]
	if o.Errors != res.Scheduled || o.OK != 0 {
		t.Fatalf("errors %d of %d", o.Errors, res.Scheduled)
	}
	if len(o.ErrorSamples) != 5 {
		t.Fatalf("samples %q, want 5", o.ErrorSamples)
	}
	seen := map[string]bool{}
	for _, s := range o.ErrorSamples {
		if seen[s] {
			t.Fatalf("duplicate sample %q", s)
		}
		seen[s] = true
	}
}

func TestCancelledRunReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	op := &funcOp{name: "x", do: func(_ context.Context, n int64) error {
		if n == 5 {
			cancel()
		}
		return nil
	}}
	_, err := Run(ctx, Config{Mix: []Weighted{{op, 1}}, Rate: 1000, Duration: 10 * time.Second, Workers: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want context.Canceled", err)
	}
	// Blocked on a full backlog when the run is cancelled.
	ctx, cancel = context.WithCancel(context.Background())
	release := make(chan struct{})
	hang := &funcOp{name: "h", do: func(_ context.Context, n int64) error {
		if n == 1 {
			time.AfterFunc(50*time.Millisecond, cancel)
		}
		<-release
		return nil
	}}
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, Config{Mix: []Weighted{{hang, 1}}, Rate: 1000, Duration: 10 * time.Second, Workers: 1, Backlog: 1})
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want context.Canceled", err)
	}
}

func TestConfigErrors(t *testing.T) {
	op := &funcOp{name: "x"}
	good := Config{Mix: []Weighted{{op, 1}}, Rate: 1, Duration: time.Second, Workers: 1}
	for name, mod := range map[string]func(*Config){
		"empty mix":   func(c *Config) { c.Mix = nil },
		"nil op":      func(c *Config) { c.Mix = []Weighted{{nil, 1}} },
		"zero weight": func(c *Config) { c.Mix = []Weighted{{op, 0}} },
		"rate":        func(c *Config) { c.Rate = 0 },
		"duration":    func(c *Config) { c.Duration = 0 },
		"warmup":      func(c *Config) { c.Warmup = -1 },
		"workers":     func(c *Config) { c.Workers = 0 },
		"arrival":     func(c *Config) { c.Arrival = "bursty" },
		"highest":     func(c *Config) { c.Highest = 1 },
	} {
		c := good
		mod(&c)
		if _, err := Run(context.Background(), c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
