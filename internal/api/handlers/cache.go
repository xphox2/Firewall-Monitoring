package handlers

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ttlCache is a tiny in-process TTL cache with singleflight de-duplication. It
// exists so expensive, fleet-wide, read-only aggregates (the dashboard health
// composite) are computed at most once per TTL no matter how many browser tabs,
// rapid refreshes, or workstations hit the endpoint at the same time:
//
//   - within TTL: every caller gets the cached value with zero DB work;
//   - on a cold/expired key: concurrent callers collapse into ONE computation
//     (singleflight) and all receive its result — no thundering herd.
//
// It is intended for GLOBAL aggregates keyed by a constant string (plus any
// query params that change the result, e.g. an hours window). Do NOT use it for
// per-request or per-user data — the whole point is that one value is shared.
type ttlCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	group   singleflight.Group
}

type cacheEntry struct {
	val     interface{}
	expires time.Time
}

func newTTLCache() *ttlCache {
	return &ttlCache{entries: make(map[string]cacheEntry)}
}

// get returns the cached value for key if it is still fresh, computing it via
// compute otherwise. Concurrent misses on the same key run compute once and
// share the result. A compute error is returned to the caller and not cached,
// so the next call retries. now is injected for testability.
func (c *ttlCache) get(key string, ttl time.Duration, compute func() (interface{}, error)) (interface{}, error) {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e.val, nil
	}
	c.mu.Unlock()

	// singleflight collapses concurrent misses into one compute per key.
	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		// Re-check under the lock: a racer may have populated the entry while we
		// waited to become the leader.
		c.mu.Lock()
		if e, ok := c.entries[key]; ok && time.Now().Before(e.expires) {
			c.mu.Unlock()
			return e.val, nil
		}
		c.mu.Unlock()

		val, err := compute()
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.entries[key] = cacheEntry{val: val, expires: time.Now().Add(ttl)}
		c.mu.Unlock()
		return val, nil
	})
	return v, err
}
