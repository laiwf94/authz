package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func mustZone(t testing.TB, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func newDaily(t0 time.Time, maxKeys int) (*fakeClock, *Daily) {
	clk := &fakeClock{t: t0}
	return clk, NewDaily(Options{Now: clk.now, MaxKeys: maxKeys})
}

func TestDailyCountsAndResetsAtMidnight(t *testing.T) {
	loc := mustZone(t, "Europe/Berlin")
	clk, q := newDaily(time.Date(2026, 6, 10, 22, 0, 0, 0, loc), 0)
	for i := range 3 {
		if ok, _ := q.Take("a", 3, loc); !ok {
			t.Fatalf("take %d refused", i)
		}
	}
	ok, wait := q.Take("a", 3, loc)
	if ok || wait != 2*time.Hour {
		t.Fatalf("over the quota: ok=%v wait=%v, want refused for 2h", ok, wait)
	}
	if ok, _ := q.Take("b", 3, loc); !ok {
		t.Fatal("keys are not independent")
	}
	if n, end := q.Used("a"); n != 3 || !end.Equal(time.Date(2026, 6, 11, 0, 0, 0, 0, loc)) {
		t.Fatalf("Used = %d, %v", n, end)
	}
	clk.add(2*time.Hour - time.Nanosecond)
	if ok, wait := q.Take("a", 3, loc); ok || wait != time.Nanosecond {
		t.Fatalf("a nanosecond before midnight: ok=%v wait=%v", ok, wait)
	}
	clk.add(time.Nanosecond)
	if n, end := q.Used("a"); n != 0 || !end.IsZero() {
		t.Fatalf("Used after midnight = %d, %v", n, end)
	}
	if ok, _ := q.Take("a", 3, loc); !ok {
		t.Fatal("not reset at midnight in Berlin")
	}
	if ok, _ := q.Take("u", 0, loc); !ok || q.Len() != 2 {
		t.Fatal("a zero limit must admit without counting")
	}
}

// The day a quota counts is the calendar day of its zone, so it lasts 23 or
// 25 hours on the days the clocks change, in either hemisphere.
func TestDailyAcrossDSTInThreeZones(t *testing.T) {
	for _, c := range []struct {
		zone       string
		start      time.Time // midnight of a day with a clock change, in zone
		dayLength  time.Duration
		otherStart time.Time
		otherLen   time.Duration
	}{
		{"America/New_York", time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC), 23 * time.Hour,
			time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), 25 * time.Hour},
		{"Europe/Berlin", time.Date(2026, 3, 29, 0, 0, 0, 0, time.UTC), 23 * time.Hour,
			time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC), 25 * time.Hour},
		{"Australia/Sydney", time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), 23 * time.Hour,
			time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), 25 * time.Hour},
	} {
		loc := mustZone(t, c.zone)
		for _, day := range []struct {
			start time.Time
			n     time.Duration
		}{{c.start, c.dayLength}, {c.otherStart, c.otherLen}} {
			y, m, d := day.start.Date()
			midnight := time.Date(y, m, d, 0, 0, 0, 0, loc)
			if got := EndOfDay(midnight, loc).Sub(midnight); got != day.n {
				t.Fatalf("%s %s: day is %v long, want %v", c.zone, midnight.Format(time.DateOnly), got, day.n)
			}
			clk, q := newDaily(midnight.Add(time.Minute), 0)
			if ok, _ := q.Take("k", 1, loc); !ok {
				t.Fatalf("%s: first take refused", c.zone)
			}
			if ok, wait := q.Take("k", 1, loc); ok || wait != day.n-time.Minute {
				t.Fatalf("%s %s: wait %v, want %v", c.zone, midnight.Format(time.DateOnly), wait, day.n-time.Minute)
			}
			// 24 hours after midnight is still the same day on a 25-hour
			// day, and already the next one on a 23-hour day.
			clk.add(24*time.Hour - time.Minute)
			ok, _ := q.Take("k", 1, loc)
			if want := day.n < 24*time.Hour; ok != want {
				t.Fatalf("%s %s: 24h after midnight admitted=%v, want %v", c.zone, midnight.Format(time.DateOnly), ok, want)
			}
		}
	}
}

func TestDailyZonesAreSeparateDays(t *testing.T) {
	// 23:30 UTC is already the next day in Sydney and still the same day in
	// New York: each key counts the day of the zone it is taken in.
	clk, q := newDaily(time.Date(2026, 6, 10, 23, 30, 0, 0, time.UTC), 0)
	syd, ny := mustZone(t, "Australia/Sydney"), mustZone(t, "America/New_York")
	q.Take("syd", 1, syd)
	q.Take("ny", 1, ny)
	q.Take("utc", 1, nil)
	_, endSyd := q.Used("syd")
	_, endNY := q.Used("ny")
	_, endUTC := q.Used("utc")
	if !endSyd.Equal(time.Date(2026, 6, 12, 0, 0, 0, 0, syd)) || !endNY.Equal(time.Date(2026, 6, 11, 0, 0, 0, 0, ny)) ||
		!endUTC.Equal(time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("ends %v %v %v", endSyd, endNY, endUTC)
	}
	clk.add(time.Hour) // past midnight UTC
	if ok, _ := q.Take("utc", 1, nil); !ok {
		t.Fatal("UTC day did not end")
	}
	if ok, _ := q.Take("ny", 1, ny); ok {
		t.Fatal("New York day ended early")
	}
}

func TestDailyRefundAndClockSteps(t *testing.T) {
	clk, q := newDaily(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC), 0)
	q.Take("a", 2, nil)
	q.Take("a", 2, nil)
	q.Refund("a")
	if n, _ := q.Used("a"); n != 1 {
		t.Fatalf("after refund used %d", n)
	}
	q.Refund("nobody") // no entry: nothing happens
	// A clock stepped back does not start the day again.
	q.Take("a", 2, nil)
	clk.add(-48 * time.Hour)
	if ok, _ := q.Take("a", 2, nil); ok {
		t.Fatal("stepping the clock back reset the count")
	}
	// A refund for a day that has ended gives nothing back to the new day.
	clk.add(48*time.Hour + 12*time.Hour)
	q.Refund("a")
	if n, _ := q.Used("a"); n != 0 {
		t.Fatalf("refund after the day ended: used %d", n)
	}
	if ok, _ := q.Take("a", 2, nil); !ok {
		t.Fatal("new day refused")
	}
	for range 3 {
		q.Refund("a")
	}
	if n, _ := q.Used("a"); n != 0 {
		t.Fatalf("refund below zero: used %d", n)
	}
}

func TestDailySweepAndEvict(t *testing.T) {
	clk, q := newDaily(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC), 0)
	for i := range minSweep {
		q.Take(fmt.Sprint("old", i), 10, nil)
	}
	clk.add(24 * time.Hour)
	q.Take("new", 10, nil) // the table has reached minSweep: the old day goes
	if q.Len() != 1 {
		t.Fatalf("after growth sweep: %d keys", q.Len())
	}
	q.Take("x", 10, nil)
	clk.add(24 * time.Hour)
	q.Sweep()
	if q.Len() != 0 {
		t.Fatalf("after Sweep: %d keys", q.Len())
	}

	_, q = newDaily(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC), 10)
	for i := range 10 {
		for range i + 1 {
			q.Take(fmt.Sprint("k", i), 100, nil)
		}
	}
	q.Take("k10", 100, nil) // full: the five lowest counts go, then k10 is added
	if q.Len() != 6 || q.Evicted() != 5 {
		t.Fatalf("after evict: %d keys, %d evicted", q.Len(), q.Evicted())
	}
	for i := range 5 {
		if n, _ := q.Used(fmt.Sprint("k", i)); n != 0 {
			t.Errorf("k%d kept with %d", i, n)
		}
	}
	for i := 5; i < 10; i++ {
		if n, _ := q.Used(fmt.Sprint("k", i)); n != i+1 {
			t.Errorf("k%d has %d, want %d", i, n, i+1)
		}
	}

	// Ties: the bound holds when every count is the same.
	_, q = newDaily(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC), 4)
	for i := range 5 {
		q.Take(fmt.Sprint("t", i), 100, nil)
	}
	if q.Len() > 4 {
		t.Fatalf("ties: %d keys", q.Len())
	}
	_, q = newDaily(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC), 1)
	q.Take("a", 100, nil)
	q.Take("b", 100, nil)
	if q.Len() != 1 || q.Evicted() != 1 {
		t.Fatalf("one key: %d keys, %d evicted", q.Len(), q.Evicted())
	}
}

func TestDailyConcurrent(t *testing.T) {
	_, q := newDaily(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC), 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if ok, _ := q.Take("shared", 500, time.UTC); ok {
					mu.Lock()
					admitted++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if n, _ := q.Used("shared"); admitted != 500 || n != 500 {
		t.Fatalf("admitted %d of 800 (counted %d) with a quota of 500", admitted, n)
	}
}

func TestDailyRealClock(t *testing.T) {
	q := NewDaily(Options{})
	if ok, _ := q.Take("a", 1, nil); !ok {
		t.Fatal("refused")
	}
	if n, end := q.Used("a"); n != 1 || !end.After(time.Now()) {
		t.Fatalf("Used = %d, %v", n, end)
	}
}

func BenchmarkDailyTake(b *testing.B) {
	loc := mustZone(b, "Europe/Berlin")
	q := NewDaily(Options{})
	for b.Loop() {
		q.Take("agent", 1<<30, loc)
	}
}
