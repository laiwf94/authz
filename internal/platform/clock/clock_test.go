package clock

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

func recv(t *testing.T, c <-chan time.Time) (time.Time, bool) {
	t.Helper()
	select {
	case v := <-c:
		return v, true
	default:
		return time.Time{}, false
	}
}

func TestOr(t *testing.T) {
	if _, ok := Or(nil).(real); !ok {
		t.Error("Or(nil) is not the wall clock")
	}
	f := NewFake(t0)
	if Or(f) != Clock(f) {
		t.Error("Or(f) did not return f")
	}
}

func TestReal(t *testing.T) {
	c := Real()
	before := time.Now()
	if n := c.Now(); n.Before(before) {
		t.Errorf("Now %v before %v", n, before)
	}
	if d := c.Since(before); d < 0 {
		t.Errorf("Since = %v", d)
	}

	tm := c.NewTimer(time.Millisecond)
	select {
	case <-tm.C():
	case <-time.After(5 * time.Second):
		t.Fatal("timer never fired")
	}
	if tm.Stop() {
		t.Error("Stop of a fired timer reported pending")
	}
	if tm.Reset(time.Hour) {
		t.Error("Reset of a fired timer reported pending")
	}
	if !tm.Stop() {
		t.Error("Stop of a reset timer reported not pending")
	}

	ran := make(chan struct{})
	ft := c.AfterFunc(time.Millisecond, func() { close(ran) })
	if ft.C() != nil {
		t.Error("AfterFunc timer has a channel")
	}
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("AfterFunc never ran")
	}
	if ft.Reset(time.Hour) {
		t.Error("Reset of a run AfterFunc reported pending")
	}
	if !ft.Stop() {
		t.Error("Stop of a reset AfterFunc reported not pending")
	}

	tk := c.NewTicker(time.Millisecond)
	for range 2 {
		select {
		case <-tk.C():
		case <-time.After(5 * time.Second):
			t.Fatal("ticker never ticked")
		}
	}
	tk.Reset(time.Hour)
	tk.Stop()
}

func TestFakeNow(t *testing.T) {
	f := NewFake(t0)
	if !f.Now().Equal(t0) {
		t.Errorf("Now = %v", f.Now())
	}
	f.Advance(90 * time.Second)
	if want := t0.Add(90 * time.Second); !f.Now().Equal(want) {
		t.Errorf("Now = %v, want %v", f.Now(), want)
	}
	if d := f.Since(t0); d != 90*time.Second {
		t.Errorf("Since = %v", d)
	}
	f.Set(t0.Add(time.Hour))
	if want := t0.Add(time.Hour); !f.Now().Equal(want) {
		t.Errorf("after Set Now = %v, want %v", f.Now(), want)
	}
	f.Advance(0)
	if want := t0.Add(time.Hour); !f.Now().Equal(want) {
		t.Errorf("Advance(0) moved the clock to %v", f.Now())
	}
}

func TestFakeBackwardsPanics(t *testing.T) {
	for name, fn := range map[string]func(*Fake){
		"Advance":         func(f *Fake) { f.Advance(-time.Nanosecond) },
		"Set":             func(f *Fake) { f.Set(t0.Add(-time.Second)) },
		"NewTicker(0)":    func(f *Fake) { f.NewTicker(0) },
		"Ticker.Reset(0)": func(f *Fake) { f.NewTicker(time.Second).Reset(0) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			fn(NewFake(t0))
		})
	}
}

func TestFakeTimer(t *testing.T) {
	f := NewFake(t0)
	tm := f.NewTimer(time.Minute)
	if f.Pending() != 1 {
		t.Fatalf("Pending = %d", f.Pending())
	}
	f.Advance(time.Minute - time.Nanosecond)
	if _, ok := recv(t, tm.C()); ok {
		t.Fatal("fired early")
	}
	f.Advance(time.Hour)
	v, ok := recv(t, tm.C())
	if !ok {
		t.Fatal("did not fire")
	}
	if want := t0.Add(time.Minute); !v.Equal(want) {
		t.Errorf("fired with %v, want its deadline %v", v, want)
	}
	if f.Pending() != 0 {
		t.Errorf("a fired timer is still pending")
	}
	if tm.Stop() {
		t.Error("Stop of a fired timer reported pending")
	}

	// Reset re-arms from now; Stop cancels.
	if tm.Reset(time.Second) {
		t.Error("Reset of a fired timer reported pending")
	}
	if !tm.Stop() {
		t.Error("Stop of an armed timer reported not pending")
	}
	f.Advance(time.Hour)
	if _, ok := recv(t, tm.C()); ok {
		t.Error("a stopped timer fired")
	}

	// A value not yet received is drained by Stop and Reset.
	tm.Reset(time.Second)
	f.Advance(time.Second)
	tm.Reset(time.Second)
	if _, ok := recv(t, tm.C()); ok {
		t.Error("stale value received after Reset")
	}
	f.Advance(time.Second)
	tm.Stop()
	if _, ok := recv(t, tm.C()); ok {
		t.Error("stale value received after Stop")
	}

	// Zero and negative durations fire at once.
	for _, d := range []time.Duration{0, -time.Second} {
		if _, ok := recv(t, f.NewTimer(d).C()); !ok {
			t.Errorf("NewTimer(%v) did not fire at once", d)
		}
	}
	if f.Pending() != 0 {
		t.Errorf("Pending = %d", f.Pending())
	}
}

func TestFakeTicker(t *testing.T) {
	f := NewFake(t0)
	tk := f.NewTicker(10 * time.Second)
	for i := 1; i <= 3; i++ {
		f.Advance(10 * time.Second)
		v, ok := recv(t, tk.C())
		if !ok {
			t.Fatalf("tick %d missing", i)
		}
		if want := t0.Add(time.Duration(i) * 10 * time.Second); !v.Equal(want) {
			t.Errorf("tick %d = %v, want %v", i, v, want)
		}
	}
	// A slow receiver gets one tick, the first one it missed, and drops
	// the rest, as time.Ticker does.
	f.Advance(time.Minute)
	v, _ := recv(t, tk.C())
	if want := t0.Add(40 * time.Second); !v.Equal(want) {
		t.Errorf("first missed tick = %v, want %v", v, want)
	}
	if _, ok := recv(t, tk.C()); ok {
		t.Error("missed ticks were queued")
	}
	// Reset changes the period from now.
	tk.Reset(time.Second)
	f.Advance(time.Second)
	if v, _ := recv(t, tk.C()); !v.Equal(t0.Add(91 * time.Second)) {
		t.Errorf("tick after Reset = %v", v)
	}
	tk.Stop()
	f.Advance(time.Hour)
	if _, ok := recv(t, tk.C()); ok {
		t.Error("a stopped ticker ticked")
	}
	if f.Pending() != 0 {
		t.Errorf("Pending = %d", f.Pending())
	}
}

// TestFakeOrder checks that timers fire in deadline order with Now at each
// deadline, ties in creation order, and that a function run by Advance can
// schedule more work that comes due within the same Advance.
func TestFakeOrder(t *testing.T) {
	f := NewFake(t0)
	var got []string
	at := func(name string) func() {
		return func() { got = append(got, name+"@"+f.Since(t0).String()) }
	}
	f.AfterFunc(3*time.Second, at("c"))
	f.AfterFunc(time.Second, at("a"))
	f.AfterFunc(time.Second, at("b"))
	f.AfterFunc(2*time.Second, func() {
		at("chain")()
		f.AfterFunc(2*time.Second, at("chained")) // due at 4s
	})
	stopped := f.AfterFunc(2*time.Second, at("stopped"))
	if !stopped.Stop() {
		t.Fatal("Stop of a pending AfterFunc reported not pending")
	}
	if stopped.C() != nil {
		t.Error("AfterFunc timer has a channel")
	}
	f.Advance(10 * time.Second)
	want := []string{"a@1s", "b@1s", "chain@2s", "c@3s", "chained@4s"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if !f.Now().Equal(t0.Add(10 * time.Second)) {
		t.Errorf("Now = %v", f.Now())
	}
}

func TestFakeAfterFuncNow(t *testing.T) {
	f := NewFake(t0)
	ran := make(chan struct{})
	f.AfterFunc(0, func() { close(ran) })
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("AfterFunc(0) did not run at once")
	}
	var n atomic.Int32
	tm := f.AfterFunc(time.Second, func() { n.Add(1) })
	f.Advance(time.Second)
	if tm.Reset(time.Second) {
		t.Error("Reset of a run AfterFunc reported pending")
	}
	f.Advance(time.Second)
	if n.Load() != 2 {
		t.Errorf("ran %d times, want 2", n.Load())
	}
}

func TestBlockUntil(t *testing.T) {
	f := NewFake(t0)
	ticked := make(chan time.Time)
	go func() {
		tk := f.NewTicker(time.Minute)
		defer tk.Stop()
		ticked <- <-tk.C()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.BlockUntil(ctx, 1); err != nil {
		t.Fatal(err)
	}
	f.Advance(time.Minute)
	if v := <-ticked; !v.Equal(t0.Add(time.Minute)) {
		t.Errorf("tick = %v", v)
	}

	short, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	if err := f.BlockUntil(short, 5); err != context.DeadlineExceeded {
		t.Errorf("BlockUntil = %v, want deadline exceeded", err)
	}
}

// TestFakeConcurrent runs timers, tickers and readers against one clock
// under the race detector.
func TestFakeConcurrent(t *testing.T) {
	f := NewFake(t0)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var fired atomic.Int64
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tk := f.NewTicker(time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tk.C():
					fired.Add(1)
					tm := f.NewTimer(time.Microsecond)
					if fired.Load()%2 == 0 {
						tm.Stop()
					}
					_ = f.Now()
				}
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.BlockUntil(ctx, 8); err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		f.Advance(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if fired.Load() == 0 {
		t.Error("no tick was received")
	}
}
