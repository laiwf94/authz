// Package clock is the platform's injectable clock: the wall clock in
// production and a fake one that tests move by hand.
//
// Code that reads the time or waits on it takes a Clock instead of calling
// time.Now, time.NewTicker or time.AfterFunc, so a test can step through
// key rotations, session lifetimes and reload intervals without sleeping.
// A nil Clock is not valid; Or turns an optional field into one.
package clock

import "time"

// Clock tells the time and makes timers and tickers that fire on it.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// Since returns the time elapsed since t.
	Since(t time.Time) time.Duration
	// NewTimer returns a Timer that sends the time on its channel once d
	// has passed. A d of zero or less fires at once.
	NewTimer(d time.Duration) Timer
	// AfterFunc calls f once d has passed and returns a Timer whose Stop
	// cancels the call. Its C is nil.
	AfterFunc(d time.Duration, f func()) Timer
	// NewTicker returns a Ticker that sends the time every d. It panics if
	// d is not positive, as time.NewTicker does.
	NewTicker(d time.Duration) Ticker
}

// Timer is a single event, as time.Timer.
type Timer interface {
	// C is the channel the time is sent on; nil for AfterFunc timers.
	C() <-chan time.Time
	// Stop prevents the timer from firing. It reports whether the timer
	// was still pending. After Stop no stale value is received from C.
	Stop() bool
	// Reset makes the timer fire d from now. It reports whether the timer
	// was still pending. After Reset no stale value is received from C.
	Reset(d time.Duration) bool
}

// Ticker is a repeating event, as time.Ticker. A receiver too slow for
// the period misses ticks rather than queueing them.
type Ticker interface {
	// C is the channel ticks are sent on.
	C() <-chan time.Time
	// Stop turns the ticker off. No tick is sent after Stop returns.
	Stop()
	// Reset stops the ticker and restarts it with period d. It panics if
	// d is not positive.
	Reset(d time.Duration)
}

// Real returns the wall clock. Durations it measures use Go's monotonic
// clock, so a step of the system clock does not stretch or shrink them.
func Real() Clock { return real{} }

// Or returns c, or the wall clock when c is nil: the default for an
// optional Clock field.
func Or(c Clock) Clock {
	if c == nil {
		return Real()
	}
	return c
}

type real struct{}

func (real) Now() time.Time                  { return time.Now() }
func (real) Since(t time.Time) time.Duration { return time.Since(t) }

func (real) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

func (real) AfterFunc(d time.Duration, f func()) Timer {
	return realFuncTimer{time.AfterFunc(d, f)}
}

func (real) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time        { return r.t.C }
func (r realTimer) Stop() bool                 { return r.t.Stop() }
func (r realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }

type realFuncTimer struct{ t *time.Timer }

func (realFuncTimer) C() <-chan time.Time          { return nil }
func (r realFuncTimer) Stop() bool                 { return r.t.Stop() }
func (r realFuncTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }

type realTicker struct{ t *time.Ticker }

func (r realTicker) C() <-chan time.Time   { return r.t.C }
func (r realTicker) Stop()                 { r.t.Stop() }
func (r realTicker) Reset(d time.Duration) { r.t.Reset(d) }
