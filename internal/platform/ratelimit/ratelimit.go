// Package ratelimit is the platform's one request rate limiter: a GCRA
// (generic cell rate algorithm) limiter keyed by arbitrary dimensions, with
// bounded memory. It replaced the gateway's per-agent and per-tool buckets
// (internal/agents/ratelimit), the sign-on gateway's per-client login
// limiter (internal/authn/server) and backs authz serve's per-API-key limit.
//
// Each key stores only its theoretical arrival time (TAT) in integer
// nanoseconds. With emission interval T = 1/Rate and tolerance
// tau = T*(Burst-1), a take at time t is admitted when max(TAT, t) - t <= tau,
// and then TAT = max(TAT, t) + T. That is exactly a token bucket holding at
// most Burst tokens and refilling Rate per second, with no floating-point
// refill to drift and one int64 of state per key.
//
// Time is measured from the limiter's creation. With the default clock that
// uses Go's monotonic reading, so a wall clock stepped backwards or forwards
// neither drains nor refills buckets. An injected clock without a monotonic
// reading is clamped to the latest time the limiter has seen, which keeps
// both properties: a step backwards mints no tokens and drains none.
//
// Memory is bounded. A key whose TAT has passed is a full bucket, which is
// the same as no entry, so such entries are swept whenever the table has
// doubled since the last sweep, and by Sweep. When the table still holds
// MaxKeys entries, the half closest to full is forgotten: a forgotten key
// starts again with a full bucket, and the keys nearest to full lose the
// least.
package ratelimit

import (
	"math"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Limit is a token bucket: Rate tokens per second, holding at most Burst.
// A Rate of zero or less means unlimited; a Burst below 1 means 1.
type Limit struct {
	Rate  float64
	Burst int
}

// PerMinute is n requests a minute with a burst of n, the shape of the
// sign-on gateway's login limit.
func PerMinute(n int) Limit { return Limit{Rate: float64(n) / 60, Burst: n} }

// Unlimited reports whether l admits everything.
func (l Limit) Unlimited() bool { return !(l.Rate > 0) }

// interval is the emission interval in nanoseconds, at least 1.
func (l Limit) interval() int64 {
	if l.Rate >= float64(time.Second) {
		return 1
	}
	return max(int64(math.Round(float64(time.Second)/l.Rate)), 1)
}

func (l Limit) burst() int64 { return int64(max(l.Burst, 1)) }

// DefaultMaxKeys is the table size used when Options.MaxKeys is zero.
const DefaultMaxKeys = 100_000

// minSweep is the table size below which no automatic sweep runs.
const minSweep = 1024

// Options configures a Limiter.
type Options struct {
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// MaxKeys bounds the number of keys held (0 means DefaultMaxKeys).
	MaxKeys int
}

// Limiter keeps one GCRA bucket per key. It is safe for concurrent use.
type Limiter struct {
	now     func() time.Time
	base    time.Time
	maxKeys int

	mu      sync.Mutex
	tat     map[string]int64 // nanoseconds since base
	high    int64            // latest time seen, since base
	sweepAt int
	evicted uint64
}

// New returns an empty limiter.
func New(o Options) *Limiter {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = DefaultMaxKeys
	}
	return &Limiter{now: o.Now, base: o.Now(), maxKeys: o.MaxKeys,
		tat: map[string]int64{}, sweepAt: minSweep}
}

// clockLocked returns the current time since base, never earlier than any
// time returned before.
func (l *Limiter) clockLocked() int64 {
	t := int64(l.now().Sub(l.base))
	if t < l.high {
		return l.high
	}
	l.high = t
	return t
}

// Take removes one token from key's bucket. When the bucket is empty it
// returns false and how long until a token is available.
func (l *Limiter) Take(key string, lim Limit) (bool, time.Duration) {
	return l.TakeN(key, lim, 1)
}

// TakeN removes n tokens from key's bucket at once, or none. When they are
// not all available it returns false and how long until they are; n above
// the burst can never be admitted and waits forever (math.MaxInt64). n of
// zero or less always succeeds.
func (l *Limiter) TakeN(key string, lim Limit, n int) (bool, time.Duration) {
	if lim.Unlimited() || n <= 0 {
		return true, 0
	}
	if int64(n) > lim.burst() {
		return false, time.Duration(math.MaxInt64)
	}
	interval := lim.interval()
	tau := interval * (lim.burst() - 1)
	cost := interval * int64(n)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clockLocked()
	tat, ok := l.tat[key]
	tat = max(tat, now)
	// Admitted when the new TAT is within tau + one interval of now.
	if over := tat + cost - interval - now - tau; over > 0 {
		return false, time.Duration(over)
	}
	if !ok {
		l.makeRoomLocked(now)
	}
	l.tat[key] = tat + cost
	return true, 0
}

// makeRoomLocked runs before a new key is inserted: it sweeps when the table
// has doubled since the last sweep and evicts when it is full.
func (l *Limiter) makeRoomLocked(now int64) {
	if len(l.tat) >= l.sweepAt {
		l.sweepLocked(now)
	}
	if len(l.tat) >= l.maxKeys {
		l.evictLocked()
	}
}

// Sweep drops every key whose bucket has refilled completely. Callers with
// a periodic maintenance tick may call it; Take also sweeps on its own.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(l.clockLocked())
}

func (l *Limiter) sweepLocked(now int64) {
	for k, tat := range l.tat {
		if tat <= now {
			delete(l.tat, k)
		}
	}
	l.sweepAt = max(minSweep, 2*len(l.tat))
}

// evictLocked forgets the half of the keys with the earliest TAT, the ones
// closest to a full bucket, so the table is at most half full afterwards.
func (l *Limiter) evictLocked() {
	keep := l.maxKeys / 2
	if keep == 0 {
		l.evicted += uint64(len(l.tat))
		clear(l.tat)
		return
	}
	tats := make([]int64, 0, len(l.tat))
	for _, tat := range l.tat {
		tats = append(tats, tat)
	}
	slices.Sort(tats)
	cut := tats[len(tats)-keep] // keep keys with TAT >= cut, at most keep of them
	for k, tat := range l.tat {
		if tat < cut {
			delete(l.tat, k)
			l.evicted++
		}
	}
	// Ties at cut: drop the surplus so the bound holds whatever the TATs.
	for k, tat := range l.tat {
		if len(l.tat) <= keep {
			break
		}
		if tat == cut {
			delete(l.tat, k)
			l.evicted++
		}
	}
}

// Set gives key's bucket the given number of tokens as of time at (clamped
// to [0, Burst]), for restoring state handed over from elsewhere. It evicts
// when the table is full but does not sweep.
func (l *Limiter) Set(key string, lim Limit, tokens float64, at time.Time) {
	if lim.Unlimited() {
		return
	}
	interval := lim.interval()
	missing := float64(lim.burst()) - min(max(tokens, 0), float64(lim.burst()))
	tat := int64(at.Sub(l.base)) + int64(math.Round(missing*float64(interval)))
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tat[key]; !ok && len(l.tat) >= l.maxKeys {
		l.evictLocked()
	}
	l.tat[key] = tat
}

// Tokens returns how many tokens key's bucket holds now, and whether the
// limiter holds an entry for key. A key without an entry has a full bucket.
func (l *Limiter) Tokens(key string, lim Limit) (float64, bool) {
	l.mu.Lock()
	tat, ok := l.tat[key]
	now := l.clockLocked()
	l.mu.Unlock()
	if lim.Unlimited() {
		return math.Inf(1), ok
	}
	if !ok || tat <= now {
		return float64(lim.burst()), ok
	}
	return max(float64(lim.burst())-float64(tat-now)/float64(lim.interval()), 0), true
}

// Len returns the number of keys held, for metrics and tests.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tat)
}

// Evicted returns how many keys have been forgotten because the table was
// full, for metrics.
func (l *Limiter) Evicted() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.evicted
}

// Key joins dimensions into one limiter key that no other list of
// dimensions produces: each is written as its length, a colon and its
// bytes, so ("a:b", "c") and ("a", "b:c") stay apart.
func Key(dims ...string) string {
	n := 0
	for _, d := range dims {
		n += len(d) + 4
	}
	return string(AppendKey(make([]byte, 0, n), dims...))
}

// AppendKey appends Key(dims...) to dst, for callers that reuse a buffer.
func AppendKey(dst []byte, dims ...string) []byte {
	for _, d := range dims {
		dst = strconv.AppendInt(dst, int64(len(d)), 10)
		dst = append(dst, ':')
		dst = append(dst, d...)
	}
	return dst
}
