package handlers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTTLCacheDedupesConcurrentLoad is the core guarantee behind the dashboard's
// "rapid refresh / many workstations can't overload the server" fix: within a
// TTL, N concurrent callers on the same key trigger exactly ONE computation and
// all receive its value.
func TestTTLCacheDedupesConcurrentLoad(t *testing.T) {
	c := newTTLCache()
	var computes int32

	compute := func() (interface{}, error) {
		atomic.AddInt32(&computes, 1)
		time.Sleep(20 * time.Millisecond) // simulate a real aggregate query
		return "payload", nil
	}

	const callers = 50
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			v, err := c.get("k", time.Minute, compute)
			if err != nil || v != "payload" {
				t.Errorf("get returned (%v, %v), want (payload, nil)", v, err)
			}
		}()
	}
	wg.Wait()

	// singleflight + TTL: the 50 concurrent misses collapse to one compute.
	if got := atomic.LoadInt32(&computes); got != 1 {
		t.Fatalf("expected exactly 1 computation for %d concurrent callers, got %d", callers, got)
	}

	// A subsequent call within TTL is served from cache (still 1 total).
	if _, err := c.get("k", time.Minute, compute); err != nil {
		t.Fatalf("cached get errored: %v", err)
	}
	if got := atomic.LoadInt32(&computes); got != 1 {
		t.Fatalf("cached read recomputed: computes=%d, want 1", got)
	}
}

// TestTTLCacheRecomputesAfterExpiry verifies the value is refreshed once the TTL
// lapses (data isn't frozen forever).
func TestTTLCacheRecomputesAfterExpiry(t *testing.T) {
	c := newTTLCache()
	var computes int32
	compute := func() (interface{}, error) {
		atomic.AddInt32(&computes, 1)
		return int(atomic.LoadInt32(&computes)), nil
	}

	if _, err := c.get("k", 10*time.Millisecond, compute); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := c.get("k", 10*time.Millisecond, compute); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&computes); got != 2 {
		t.Fatalf("expected 2 computations across a TTL boundary, got %d", got)
	}
}

// TestTTLCacheErrorNotCached ensures a failed computation is retried next call
// rather than caching the failure.
func TestTTLCacheErrorNotCached(t *testing.T) {
	c := newTTLCache()
	var calls int32
	compute := func() (interface{}, error) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return nil, errTest
		}
		return "ok", nil
	}
	if _, err := c.get("k", time.Minute, compute); err == nil {
		t.Fatal("expected error on first call")
	}
	v, err := c.get("k", time.Minute, compute)
	if err != nil || v != "ok" {
		t.Fatalf("retry returned (%v, %v), want (ok, nil)", v, err)
	}
}

var errTest = &cacheTestErr{}

type cacheTestErr struct{}

func (*cacheTestErr) Error() string { return "boom" }
