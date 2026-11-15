package saml

import (
	"sync"
	"time"
)

// DefaultReplayCapacity bounds the replay cache.
const DefaultReplayCapacity = 100_000

// ReplayCache remembers assertion IDs until they expire, so a captured
// assertion can be used once (SAML Profiles section 4.1.4.5). When full of
// unexpired IDs it refuses new ones: failing closed beats forgetting.
type ReplayCache struct {
	now      func() time.Time
	capacity int

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewReplayCache returns a cache holding at most capacity IDs (0 means the
// default).
func NewReplayCache(capacity int, now func() time.Time) *ReplayCache {
	if capacity <= 0 {
		capacity = DefaultReplayCapacity
	}
	if now == nil {
		now = time.Now
	}
	return &ReplayCache{now: now, capacity: capacity, seen: map[string]time.Time{}}
}

// Claim records id until expires. It returns false if id was already seen
// (a replay) or the cache is full.
func (c *ReplayCache) Claim(id string, expires time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if exp, ok := c.seen[id]; ok && now.Before(exp) {
		return false
	}
	if len(c.seen) >= c.capacity {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.capacity {
			return false
		}
	}
	c.seen[id] = expires
	return true
}

// Len returns the number of remembered IDs.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// Cap returns how many IDs the cache holds at most.
func (c *ReplayCache) Cap() int { return c.capacity }
