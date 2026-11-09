package clock

import (
	"context"
	"sync"
	"time"
)

// Fake is a Clock that only moves when Advance or Set is called. Timers,
// tickers and AfterFunc calls come due in deadline order as it moves, with
// Now reading each deadline as it fires, and creation order breaking ties.
//
// Channel sends never block: like time.Timer and time.Ticker, each channel
// holds one value and a tick the receiver has not taken yet is dropped.
// AfterFunc functions that come due during Advance run on the goroutine
// calling Advance, one after the other, before it returns; one created with
// a duration of zero or less runs at once on its own goroutine, as
// time.AfterFunc does. They may use the clock, including creating timers.
//
// A Fake is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	seq     uint64
	pending []*fakeTimer
	changed chan struct{} // closed and replaced when pending grows
}

// NewFake returns a Fake reading t.
func NewFake(t time.Time) *Fake {
	return &Fake{now: t, changed: make(chan struct{})}
}

// Now returns the fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Since returns Now().Sub(t).
func (f *Fake) Since(t time.Time) time.Duration { return f.Now().Sub(t) }

// NewTimer returns a timer that fires when the clock reaches Now()+d.
func (f *Fake) NewTimer(d time.Duration) Timer {
	t := &fakeTimer{f: f, c: make(chan time.Time, 1)}
	f.mu.Lock()
	f.schedule(t, d)
	f.mu.Unlock()
	return t
}

// AfterFunc returns a timer that calls fn when the clock reaches Now()+d.
func (f *Fake) AfterFunc(d time.Duration, fn func()) Timer {
	t := &fakeTimer{f: f, fn: fn}
	f.mu.Lock()
	f.schedule(t, d)
	f.mu.Unlock()
	return t
}

// NewTicker returns a ticker that fires every d of fake time.
func (f *Fake) NewTicker(d time.Duration) Ticker {
	if d <= 0 {
		panic("clock: non-positive interval for NewTicker")
	}
	t := &fakeTimer{f: f, c: make(chan time.Time, 1), period: d}
	f.mu.Lock()
	f.schedule(t, d)
	f.mu.Unlock()
	return fakeTicker{t}
}

// Advance moves the clock forward by d, firing everything that comes due
// on the way. It panics if d is negative: timers measure elapsed time,
// which does not run backwards.
func (f *Fake) Advance(d time.Duration) {
	if d < 0 {
		panic("clock: Advance with a negative duration")
	}
	f.mu.Lock()
	target := f.now.Add(d)
	for {
		t := f.next(target)
		if t == nil {
			break
		}
		f.now = t.when
		if fn := f.fire(t); fn != nil {
			f.mu.Unlock()
			fn()
			f.mu.Lock()
		}
	}
	if target.After(f.now) {
		f.now = target
	}
	f.mu.Unlock()
}

// Set moves the clock forward to t, as Advance(t.Sub(Now())). It panics
// if t is before Now.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	d := t.Sub(f.now)
	f.mu.Unlock()
	f.Advance(d)
}

// Pending returns the number of timers, tickers and AfterFunc calls that
// have not fired or been stopped.
func (f *Fake) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending)
}

// BlockUntil waits until at least n timers, tickers and AfterFunc calls
// are pending, so a test can tell that the goroutine it started is
// waiting on the clock before it advances it. It returns ctx.Err() if ctx
// ends first.
func (f *Fake) BlockUntil(ctx context.Context, n int) error {
	for {
		f.mu.Lock()
		if len(f.pending) >= n {
			f.mu.Unlock()
			return nil
		}
		ch := f.changed
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}
}

// schedule makes t pending at now+d, or fires it at once when d <= 0.
// f.mu is held.
func (f *Fake) schedule(t *fakeTimer, d time.Duration) {
	f.seq++
	t.seq = f.seq
	t.when = f.now.Add(d)
	if d <= 0 && t.period == 0 {
		if fn := f.fire(t); fn != nil {
			go fn()
		}
		return
	}
	f.pending = append(f.pending, t)
	t.index = len(f.pending) - 1
	close(f.changed)
	f.changed = make(chan struct{})
}

// next returns the earliest pending timer due at or before target, or
// nil. f.mu is held.
func (f *Fake) next(target time.Time) *fakeTimer {
	var best *fakeTimer
	for _, t := range f.pending {
		if t.when.After(target) {
			continue
		}
		if best == nil || t.when.Before(best.when) || (t.when.Equal(best.when) && t.seq < best.seq) {
			best = t
		}
	}
	return best
}

// fire delivers t at f.now: a ticker is rescheduled one period on, a timer
// leaves the pending list. It returns the AfterFunc function to call, if
// any. f.mu is held.
func (f *Fake) fire(t *fakeTimer) func() {
	if t.period > 0 {
		t.when = t.when.Add(t.period)
		f.seq++
		t.seq = f.seq
	} else {
		f.remove(t)
	}
	if t.fn != nil {
		return t.fn
	}
	select {
	case t.c <- f.now:
	default: // the receiver has not taken the last one: drop this one
	}
	return nil
}

// remove takes t off the pending list and reports whether it was there.
// f.mu is held.
func (f *Fake) remove(t *fakeTimer) bool {
	i := t.index
	if i < 0 || i >= len(f.pending) || f.pending[i] != t {
		return false
	}
	last := len(f.pending) - 1
	f.pending[i] = f.pending[last]
	f.pending[i].index = i
	f.pending[last] = nil
	f.pending = f.pending[:last]
	t.index = -1
	return true
}

type fakeTimer struct {
	f      *Fake
	c      chan time.Time
	fn     func()
	period time.Duration // > 0 for tickers
	when   time.Time
	seq    uint64
	index  int // in f.pending, or -1
}

func (t *fakeTimer) C() <-chan time.Time {
	if t.c == nil {
		return nil
	}
	return t.c
}

func (t *fakeTimer) Stop() bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	was := t.f.remove(t)
	t.drain()
	return was
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	was := t.f.remove(t)
	t.drain()
	t.f.schedule(t, d)
	return was
}

// drain empties the channel so no value from before a Stop or Reset is
// received after it. f.mu is held.
func (t *fakeTimer) drain() {
	if t.c == nil {
		return
	}
	select {
	case <-t.c:
	default:
	}
}

type fakeTicker struct{ t *fakeTimer }

func (k fakeTicker) C() <-chan time.Time { return k.t.c }
func (k fakeTicker) Stop()               { k.t.Stop() }

func (k fakeTicker) Reset(d time.Duration) {
	if d <= 0 {
		panic("clock: non-positive interval for Ticker.Reset")
	}
	k.t.f.mu.Lock()
	defer k.t.f.mu.Unlock()
	k.t.f.remove(k.t)
	k.t.drain()
	k.t.period = d
	k.t.f.schedule(k.t, d)
}
