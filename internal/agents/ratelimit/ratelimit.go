// Package ratelimit provides the gateway's three admission controls: token
// buckets (per agent and per agent+tool, from the platform limiter), a daily
// call quota per agent, and a concurrency limit per upstream.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// Limit is a token bucket: Rate tokens per second, holding at most Burst.
// A zero Rate means unlimited.
type Limit = ratelimit.Limit

// Limiter keeps one token bucket per key: the platform's GCRA limiter
// (internal/platform/ratelimit), with its bounded table and monotonic clock.
// Keys are built with ratelimit.Key from the agent and tool.
type Limiter = ratelimit.Limiter

// NewLimiter returns an empty limiter holding up to
// ratelimit.DefaultMaxKeys buckets. now may be nil for time.Now.
func NewLimiter(now func() time.Time) *Limiter {
	return ratelimit.New(ratelimit.Options{Now: now})
}

// Quota counts calls per key per UTC day. It is safe for concurrent use.
type Quota struct {
	mu     sync.Mutex
	day    int64
	counts map[string]int
	now    func() time.Time
}

// NewQuota returns an empty quota counter. now may be nil for time.Now.
func NewQuota(now func() time.Time) *Quota {
	if now == nil {
		now = time.Now
	}
	return &Quota{counts: map[string]int{}, now: now}
}

const day = 24 * time.Hour

// Take counts one call against key's daily limit (0 means unlimited). When
// the limit is reached it returns false and the time until the next UTC day.
func (q *Quota) Take(key string, limit int) (bool, time.Duration) {
	if limit <= 0 {
		return true, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	if d := now.Unix() / int64(day/time.Second); d != q.day {
		q.day, q.counts = d, map[string]int{}
	}
	if q.counts[key] >= limit {
		return false, now.Truncate(day).Add(day).Sub(now)
	}
	q.counts[key]++
	return true, 0
}

// Refund gives back one call taken today, when the call was then refused for
// another reason before reaching the upstream.
func (q *Quota) Refund(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.counts[key] > 0 {
		q.counts[key]--
	}
}

// Used returns key's count for the current day.
func (q *Quota) Used(key string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.now().UTC().Unix()/int64(day/time.Second) != q.day {
		return 0
	}
	return q.counts[key]
}

// Semaphore bounds concurrent calls to one upstream.
type Semaphore struct{ ch chan struct{} }

// NewSemaphore allows n concurrent holders (n >= 1).
func NewSemaphore(n int) *Semaphore { return &Semaphore{ch: make(chan struct{}, max(n, 1))} }

// Acquire waits up to maxWait (and no longer than ctx) for a slot.
func (s *Semaphore) Acquire(ctx context.Context, maxWait time.Duration) bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(maxWait)
	defer t.Stop()
	select {
	case s.ch <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Release frees a slot taken by Acquire.
func (s *Semaphore) Release() { <-s.ch }

// InUse returns the number of slots held.
func (s *Semaphore) InUse() int { return len(s.ch) }
