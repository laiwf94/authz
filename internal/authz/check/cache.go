package check

import (
	"container/list"
	"hash/maphash"
	"sync"
)

// Cache is a sharded LRU of check results. Keys include the revision, and a
// snapshot never changes, so a cached answer is never stale for its key.
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
	val bool
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

// Get returns the cached value for key.
func (c *Cache) Get(key string) (bool, bool) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.items[key]
	if !ok {
		return false, false
	}
	s.ll.MoveToFront(el)
	return el.Value.(*item).val, true
}

// Put stores a value, evicting the least recently used entry when full.
func (c *Cache) Put(key string, val bool) {
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
