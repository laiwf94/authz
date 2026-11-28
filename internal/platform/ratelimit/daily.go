package ratelimit

import (
	"slices"
	"sync"
	"time"
)

// Daily counts calls per key per calendar day, where the day is the one of
// the time zone each Take names: a quota of 100 a day in Europe/Berlin
// starts again at midnight in Berlin, which is 23 or 25 hours after the
// previous midnight on the days the clocks change.
//
// Each key holds its count and the instant its day ends. A key whose day
// has ended counts from zero again, so the wall clock (Options.Now) is the
// clock that matters: stepping it backwards within a day changes nothing,
// and no count starts again until the clock reaches the end of the day it
// was counted in.
//
// Memory is bounded like Limiter's. Keys whose day has ended are swept when
// the table has doubled since the last sweep, and by Sweep. When the table
// still holds MaxKeys entries, the half with the lowest counts is
// forgotten: a forgotten key starts its day again from zero, and the keys
// that have used the least lose the least.
type Daily struct {
	now     func() time.Time
	maxKeys int

	mu      sync.Mutex
	days    map[string]dayCount
	sweepAt int
	evicted uint64
}

type dayCount struct {
	count int
	end   int64 // Unix nanoseconds of the next midnight in the key's zone
}

// NewDaily returns an empty day counter. Options.MaxKeys bounds it as for
// New.
func NewDaily(o Options) *Daily {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = DefaultMaxKeys
	}
	return &Daily{now: o.Now, maxKeys: o.MaxKeys, days: map[string]dayCount{}, sweepAt: minSweep}
}

// EndOfDay returns the first instant of the day after t's day in loc
// (nil means UTC). On a day whose midnight a clock change skips, that is
// the first instant of the next day that exists.
func EndOfDay(t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	y, m, d := t.In(loc).Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, loc)
}

// Take counts one call for key in today's count in loc, unless limit calls
// have been counted already: then it returns false and how long until the
// day ends. A limit of zero or less admits everything and counts nothing.
func (q *Daily) Take(key string, limit int, loc *time.Location) (bool, time.Duration) {
	if limit <= 0 {
		return true, 0
	}
	now := q.now()
	t := now.UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	c, ok := q.days[key]
	if !ok || t >= c.end {
		c = dayCount{end: EndOfDay(now, loc).UnixNano()}
	}
	if c.count >= limit {
		return false, time.Duration(c.end - t)
	}
	if !ok {
		q.makeRoomLocked(t)
	}
	c.count++
	q.days[key] = c
	return true, 0
}

// Refund gives back one call counted for key today, for a call that was
// counted and then not made. A call counted on a day that has ended is not
// given back.
func (q *Daily) Refund(key string) {
	t := q.now().UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	if c, ok := q.days[key]; ok && t < c.end && c.count > 0 {
		c.count--
		q.days[key] = c
	}
}

// Used returns how many calls key has counted today and when its day ends.
// A key with nothing counted today returns zero and the zero time.
func (q *Daily) Used(key string) (int, time.Time) {
	t := q.now().UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	c, ok := q.days[key]
	if !ok || t >= c.end {
		return 0, time.Time{}
	}
	return c.count, time.Unix(0, c.end)
}

// Sweep drops every key whose day has ended.
func (q *Daily) Sweep() {
	t := q.now().UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked(t)
}

func (q *Daily) sweepLocked(t int64) {
	for k, c := range q.days {
		if t >= c.end {
			delete(q.days, k)
		}
	}
	q.sweepAt = max(minSweep, 2*len(q.days))
}

func (q *Daily) makeRoomLocked(t int64) {
	if len(q.days) >= q.sweepAt {
		q.sweepLocked(t)
	}
	if len(q.days) >= q.maxKeys {
		q.evictLocked()
	}
}

// evictLocked forgets the half of the keys with the lowest counts.
func (q *Daily) evictLocked() {
	keep := q.maxKeys / 2
	if keep == 0 {
		q.evicted += uint64(len(q.days))
		clear(q.days)
		return
	}
	counts := make([]int, 0, len(q.days))
	for _, c := range q.days {
		counts = append(counts, c.count)
	}
	slices.Sort(counts)
	cut := counts[len(counts)-keep]
	for k, c := range q.days {
		if c.count < cut {
			delete(q.days, k)
			q.evicted++
		}
	}
	for k, c := range q.days {
		if len(q.days) <= keep {
			break
		}
		if c.count == cut {
			delete(q.days, k)
			q.evicted++
		}
	}
}

// Len returns the number of keys held.
func (q *Daily) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.days)
}

// Evicted returns how many keys have been forgotten because the table was
// full.
func (q *Daily) Evicted() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.evicted
}

// Range calls fn for each key that has counted calls in a day that has
// not ended, with the count and the end of that day, until fn returns
// false. As with Limiter.Range, fn runs with the lock held and must not
// use the counter.
func (q *Daily) Range(fn func(key string, count int, end time.Time) bool) {
	t := q.now().UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	for k, c := range q.days {
		if t < c.end && c.count > 0 && !fn(k, c.count, time.Unix(0, c.end)) {
			return
		}
	}
}
