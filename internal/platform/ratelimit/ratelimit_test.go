package ratelimit

import (
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newFake(t0 time.Time, maxKeys int) (*fakeClock, *Limiter) {
	clk := &fakeClock{t: t0}
	return clk, New(Options{Now: clk.now, MaxKeys: maxKeys})
}

// The gateway's per-agent bucket test (internal/agents/ratelimit), run
// against the platform limiter.
func TestBucket(t *testing.T) {
	clk, l := newFake(time.Unix(1000, 0), 0)
	lim := Limit{Rate: 2, Burst: 3}
	for i := range 3 {
		if ok, _ := l.Take("a", lim); !ok {
			t.Fatalf("burst take %d refused", i)
		}
	}
	if ok, wait := l.Take("a", lim); ok || wait != 500*time.Millisecond {
		t.Fatalf("empty bucket: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Take("b", lim); !ok {
		t.Fatal("keys are not independent")
	}
	clk.add(250 * time.Millisecond)
	if ok, wait := l.Take("a", lim); ok || wait != 250*time.Millisecond {
		t.Fatalf("half refilled: ok=%v wait=%v", ok, wait)
	}
	clk.add(250 * time.Millisecond)
	if ok, _ := l.Take("a", lim); !ok {
		t.Fatal("refilled token refused")
	}
	clk.add(time.Hour)
	for range 3 {
		if ok, _ := l.Take("a", lim); !ok {
			t.Fatal("refill must cap at burst, and allow burst")
		}
	}
	if ok, _ := l.Take("a", lim); ok {
		t.Fatal("refill exceeded burst")
	}
	if ok, _ := l.Take("u", Limit{}); !ok {
		t.Fatal("zero rate must be unlimited")
	}
	if ok, _ := l.Take("z", Limit{Rate: 1}); !ok {
		t.Fatal("burst 0 must behave as 1")
	}
	clk.add(-time.Minute) // a clock step backwards must not mint tokens
	if ok, _ := l.Take("z", Limit{Rate: 1}); ok {
		t.Fatal("backwards clock refilled")
	}
}

// The sign-on gateway's login limiter test (internal/authn/server): 60 a
// minute per client, and a clock stepping backwards must not drain a bucket.
func TestPerMinute(t *testing.T) {
	clk, l := newFake(time.Unix(1000, 0), 0)
	lim := PerMinute(60)
	for i := 0; i < 60; i++ {
		if ok, _ := l.Take("a", lim); !ok {
			t.Fatalf("burst refused at %d", i)
		}
	}
	if ok, wait := l.Take("a", lim); ok || wait != time.Second {
		t.Fatalf("over the limit: %v %v", ok, wait)
	}
	if ok, _ := l.Take("b", lim); !ok {
		t.Fatal("limits are per client")
	}
	clk.add(-time.Hour)
	if ok, _ := l.Take("b", lim); !ok {
		t.Fatal("clock step backwards drained the bucket")
	}
	clk.add(time.Hour + time.Second)
	if ok, _ := l.Take("a", lim); !ok {
		t.Fatal("refill")
	}
	clk.add(2 * time.Minute)
	l.Sweep()
	if l.Len() != 0 {
		t.Fatal("sweep keeps full buckets")
	}
}

// Over any schedule, with clock steps both ways, a bucket admits exactly
// what a reference token bucket on a clock that never goes back admits.
func TestBucketRandomSchedules(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewPCG(seed, 2))
	for iter := 0; iter < 300; iter++ {
		clk, l := newFake(time.Unix(0, 0), 0)
		// Rates whose interval is a whole number of nanoseconds, so the
		// reference is exact.
		lim := Limit{Rate: float64(pick(rng, []int{1, 2, 4, 5, 8, 10, 16, 20, 25, 40, 50, 100})), Burst: 1 + rng.IntN(10)}
		scale := int64(time.Second) / int64(lim.Rate)
		full := int64(lim.Burst) * scale
		ref, refLast := full, clk.now()
		taken, start := 0, clk.now()
		for range 300 {
			d := time.Duration(rng.IntN(200)) * time.Millisecond
			if rng.IntN(10) == 0 {
				d = -d
			}
			clk.add(d)
			now := clk.now()
			if now.After(refLast) {
				ref = min(full, ref+now.Sub(refLast).Nanoseconds())
				refLast = now
			}
			n := 1
			if rng.IntN(4) == 0 {
				n = 1 + rng.IntN(lim.Burst)
			}
			ok, wait := l.TakeN("k", lim, n)
			refOK := ref >= int64(n)*scale
			if refOK {
				ref -= int64(n) * scale
			} else if want := time.Duration(int64(n)*scale - ref); wait != want {
				t.Fatalf("seed %d: wait %v, reference %v", seed, wait, want)
			}
			if ok != refOK {
				t.Fatalf("seed %d: take %d at %v: limiter %v, reference %v (rate %v burst %d)", seed, n, now.Sub(start), ok, refOK, lim.Rate, lim.Burst)
			}
			if ok {
				taken += n
			}
			if bound := float64(lim.Burst) + lim.Rate*refLast.Sub(start).Seconds(); float64(taken) > bound+1e-9 {
				t.Fatalf("seed %d: %d takes exceeds bound %.2f", seed, taken, bound)
			}
		}
	}
}

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.IntN(len(xs))] }

func TestTakeN(t *testing.T) {
	_, l := newFake(time.Unix(0, 0), 0)
	lim := Limit{Rate: 10, Burst: 5}
	if ok, _ := l.TakeN("k", lim, 0); !ok {
		t.Fatal("n=0 refused")
	}
	if ok, wait := l.TakeN("k", lim, 6); ok || wait != time.Duration(math.MaxInt64) {
		t.Fatalf("n above burst: %v %v", ok, wait)
	}
	if l.Len() != 0 {
		t.Fatal("refused take stored a key")
	}
	if ok, _ := l.TakeN("k", lim, 4); !ok {
		t.Fatal("4 of 5 refused")
	}
	// Two left wanted, one held: all or nothing.
	if ok, wait := l.TakeN("k", lim, 2); ok || wait != 100*time.Millisecond {
		t.Fatalf("partial take: %v %v", ok, wait)
	}
	if ok, _ := l.Take("k", lim); !ok {
		t.Fatal("refused take consumed tokens")
	}
}

func TestSweepOnGrowth(t *testing.T) {
	clk, l := newFake(time.Unix(0, 0), 0)
	lim := Limit{Rate: 1, Burst: 1}
	for i := range minSweep - 1 {
		l.Take(fmt.Sprint("k", i), lim)
	}
	slow := Limit{Rate: 0.001, Burst: 5}
	l.Take("hot", slow) // slow refill: must survive the sweep
	clk.add(2 * time.Second)
	l.Take("trigger", lim)
	if n := l.Len(); n != 2 {
		t.Fatalf("after sweep %d keys remain, want 2 (hot, trigger)", n)
	}
	if tok, ok := l.Tokens("hot", slow); !ok || tok < 4 || tok >= 4.01 {
		t.Fatalf("hot bucket: %v %v", tok, ok)
	}
	if l.Evicted() != 0 {
		t.Fatal("a sweep counted as eviction")
	}
}

// When the table is full of live keys, the half closest to full goes and
// the busiest keys keep their state; memory never exceeds MaxKeys.
func TestEvictHalfClosestToFull(t *testing.T) {
	const maxKeys = 2000
	clk, l := newFake(time.Unix(0, 0), maxKeys)
	lim := Limit{Rate: 1, Burst: 1000}
	for i := range maxKeys {
		// Key i has taken i+1 tokens: higher i is further from full.
		l.Set(strconv.Itoa(i), lim, float64(1000-(i%1000)-1), clk.now())
	}
	if l.Len() != maxKeys {
		t.Fatalf("set %d keys, hold %d", maxKeys, l.Len())
	}
	if ok, _ := l.Take("new", lim); !ok {
		t.Fatal("new key refused")
	}
	if n := l.Len(); n != maxKeys/2+1 {
		t.Fatalf("after eviction %d keys, want %d", n, maxKeys/2+1)
	}
	if l.Evicted() != maxKeys/2 {
		t.Fatalf("evicted %d", l.Evicted())
	}
	for _, k := range []string{"999", "1999", "500", "1500"} {
		if _, ok := l.Tokens(k, lim); !ok {
			t.Errorf("busy key %s forgotten", k)
		}
	}
	for _, k := range []string{"0", "1000", "499", "1499"} {
		if _, ok := l.Tokens(k, lim); ok {
			t.Errorf("near-full key %s kept", k)
		}
	}
	// Many more keys than the bound, all live: the table stays bounded.
	for i := range 20 * maxKeys {
		l.Take("x"+strconv.Itoa(i), lim)
		if l.Len() > maxKeys {
			t.Fatalf("%d keys held, bound %d", l.Len(), maxKeys)
		}
	}
}

func TestEvictTies(t *testing.T) {
	clk, l := newFake(time.Unix(0, 0), 10)
	lim := Limit{Rate: 1, Burst: 10}
	for i := range 10 {
		l.Set(strconv.Itoa(i), lim, 0, clk.now()) // all the same TAT
	}
	l.Take("new", lim)
	if n := l.Len(); n != 6 {
		t.Fatalf("after evicting ties %d keys, want 6", n)
	}
	_, one := newFake(time.Unix(0, 0), 1)
	one.Take("a", lim)
	one.Take("b", lim)
	if one.Len() != 1 || one.Evicted() != 1 {
		t.Fatalf("MaxKeys 1: len %d evicted %d", one.Len(), one.Evicted())
	}
}

func TestSetAndTokens(t *testing.T) {
	clk, l := newFake(time.Unix(50, 0), 0)
	lim := Limit{Rate: 2, Burst: 4}
	if tok, ok := l.Tokens("k", lim); ok || tok != 4 {
		t.Fatalf("unknown key: %v %v", tok, ok)
	}
	l.Set("k", lim, 1, clk.now().Add(-time.Second)) // 1 token a second ago: 3 now
	if tok, _ := l.Tokens("k", lim); tok != 3 {
		t.Fatalf("tokens %v, want 3", tok)
	}
	l.Set("k", lim, -5, clk.now())
	if tok, _ := l.Tokens("k", lim); tok != 0 {
		t.Fatalf("negative tokens not clamped: %v", tok)
	}
	if ok, wait := l.Take("k", lim); ok || wait != 500*time.Millisecond {
		t.Fatalf("empty restored bucket: %v %v", ok, wait)
	}
	l.Set("k", lim, 99, clk.now())
	if tok, _ := l.Tokens("k", lim); tok != 4 {
		t.Fatalf("tokens above burst not clamped: %v", tok)
	}
	l.Set("u", Limit{}, 1, clk.now())
	if tok, ok := l.Tokens("u", Limit{}); ok || !math.IsInf(tok, 1) {
		t.Fatalf("unlimited: %v %v", tok, ok)
	}
}

// The default clock is monotonic, measured from New.
func TestRealClock(t *testing.T) {
	l := New(Options{})
	lim := Limit{Rate: 1000, Burst: 2}
	l.Take("k", lim)
	l.Take("k", lim)
	ok, wait := l.Take("k", lim)
	if ok || wait <= 0 || wait > time.Millisecond {
		t.Fatalf("third take: %v %v", ok, wait)
	}
	if !strings.Contains(l.base.String(), " m=") {
		t.Fatal("default clock carries no monotonic reading")
	}
}

func TestLimitHelpers(t *testing.T) {
	if !(Limit{}).Unlimited() || !(Limit{Rate: math.NaN()}).Unlimited() || (Limit{Rate: 1e-9}).Unlimited() {
		t.Fatal("Unlimited")
	}
	if got := (Limit{Rate: 1e12}).interval(); got != 1 {
		t.Fatalf("huge rate interval %d", got)
	}
	if got := (Limit{Rate: 3}).interval(); got != 333_333_333 {
		t.Fatalf("rate 3 interval %d", got)
	}
	if p := PerMinute(30); p.Burst != 30 || p.Rate != 0.5 {
		t.Fatalf("PerMinute: %+v", p)
	}
}

func TestKey(t *testing.T) {
	seen := map[string][]string{}
	for _, dims := range [][]string{
		{}, {""}, {"", ""}, {"a"}, {"a", ""}, {"", "a"}, {"a:b", "c"}, {"a", "b:c"},
		{"1:a"}, {"1", "a"}, {"agent", "x\x00y"}, {"agent\x00x", "y"}, {"10:aaaaaaaaaa"},
	} {
		k := Key(dims...)
		if prev, dup := seen[k]; dup {
			t.Fatalf("%q and %q share key %q", prev, dims, k)
		}
		seen[k] = dims
	}
	if got := Key("agent", "a1", "tool"); got != "5:agent2:a14:tool" {
		t.Fatalf("Key = %q", got)
	}
	if got := string(AppendKey([]byte("p|"), "x")); got != "p|1:x" {
		t.Fatalf("AppendKey = %q", got)
	}
}

func TestConcurrentTakes(t *testing.T) {
	l := New(Options{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := map[string]int{}
	for g := range 50 {
		wg.Go(func() {
			for i := range 40 {
				k := Key("agent", strconv.Itoa((g+i)%4))
				if ok, _ := l.Take(k, Limit{Rate: 0.0001, Burst: 100}); ok {
					mu.Lock()
					admitted[k]++
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	for k, n := range admitted {
		if n != 100 {
			t.Fatalf("%s admitted %d, want exactly the burst of 100", k, n)
		}
	}
	if len(admitted) != 4 {
		t.Fatalf("keys %v", admitted)
	}
}

// The allowed path on a held key allocates nothing.
func TestTakeAllocs(t *testing.T) {
	l := New(Options{})
	lim := Limit{Rate: 1e9, Burst: 1e9}
	l.Take("agent:tool", lim)
	if n := testing.AllocsPerRun(1000, func() { l.Take("agent:tool", lim) }); n != 0 {
		t.Fatalf("Take allocates %v times", n)
	}
}

func BenchmarkTake(b *testing.B) {
	l := New(Options{})
	lim := Limit{Rate: 1e9, Burst: 1e9}
	for b.Loop() {
		l.Take("agent:tool", lim)
	}
}

func BenchmarkTakeParallel(b *testing.B) {
	l := New(Options{})
	lim := Limit{Rate: 1e9, Burst: 1e9}
	keys := make([]string, 64)
	for i := range keys {
		keys[i] = Key("agent", strconv.Itoa(i))
	}
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			l.Take(keys[i%len(keys)], lim)
			i++
		}
	})
}

// New keys past MaxKeys, every one live: the cost of sweeping and evicting
// amortised over inserts.
func BenchmarkTakeNewKeysFull(b *testing.B) {
	l := New(Options{MaxKeys: 100_000})
	lim := Limit{Rate: 1e-3, Burst: 10}
	keys := make([]string, 1<<18)
	for i := range keys {
		keys[i] = strconv.Itoa(i)
	}
	i := 0
	for b.Loop() {
		l.Take(keys[i%len(keys)], lim)
		i++
	}
}
