package check

import (
	"container/list"
	"hash/maphash"
	"sync"
)

// Cache is a sharded LRU of check results. Keys include the revision, and a
// snapshot never changes, so a cached answer is never stale for its key.
// Results that depended on a check's caveat context have the context's
// hash in their key as well.
type Cache struct {
	seed   maphash.Seed
	shards []*shard
}

type shard struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type item struct {
	key string
	val Result
}

const cacheShards = 16

// NewCache returns a cache holding about capacity entries. capacity <= 0
// returns nil, which disables caching.
func NewCache(capacity int) *Cache {
	if capacity <= 0 {
		return nil
	}
	per := capacity / cacheShards
	if per < 1 {
		per = 1
	}
	c := &Cache{seed: maphash.MakeSeed(), shards: make([]*shard, cacheShards)}
	for i := range c.shards {
		c.shards[i] = &shard{cap: per, ll: list.New(), items: map[string]*list.Element{}}
	}
	return c
}

func (c *Cache) shard(key string) *shard {
	return c.shards[maphash.String(c.seed, key)%cacheShards]
}

// Get returns whether the cached result for key is allowed.
func (c *Cache) Get(key string) (bool, bool) {
	r, ok := c.get(key)
	return r.Allowed(), ok
}

// Put stores an allowed or denied result, evicting the least recently used
// entry when full.
func (c *Cache) Put(key string, val bool) {
	r := denied
	if val {
		r = allowed
	}
	c.put(key, r)
}

func (c *Cache) get(key string) (Result, bool) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.items[key]
	if !ok {
		return denied, false
	}
	s.ll.MoveToFront(el)
	return el.Value.(*item).val, true
}

func (c *Cache) put(key string, val Result) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		el.Value.(*item).val = val
		s.ll.MoveToFront(el)
		return
	}
	s.items[key] = s.ll.PushFront(&item{key, val})
	if s.ll.Len() > s.cap {
		last := s.ll.Back()
		s.ll.Remove(last)
		delete(s.items, last.Value.(*item).key)
	}
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	n := 0
	for _, s := range c.shards {
		s.mu.Lock()
		n += s.ll.Len()
		s.mu.Unlock()
	}
	return n
}
