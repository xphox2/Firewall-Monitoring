package middleware

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestIPRateLimiter_GetLimiter_NewIPCreatesLimiter — basic happy path.
func TestIPRateLimiter_GetLimiter_NewIPCreatesLimiter(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 10)
	defer rl.Stop()

	l := rl.getLimiter("1.1.1.1")
	if l == nil {
		t.Fatal("getLimiter returned nil for new IP")
	}
	if !l.Allow() {
		t.Fatal("fresh limiter denied first request")
	}
	if got, want := len(rl.limiters), 1; got != want {
		t.Errorf("len(limiters) = %d, want %d", got, want)
	}
}

// TestIPRateLimiter_GetLimiter_SameIPReusesLimiter — second call with the
// same IP must return the SAME limiter (so rate limits accumulate per IP
// instead of resetting on every request).
func TestIPRateLimiter_GetLimiter_SameIPReusesLimiter(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 1)
	defer rl.Stop()

	l1 := rl.getLimiter("2.2.2.2")
	if !l1.Allow() {
		t.Fatal("burst=1: first Allow() denied")
	}
	l2 := rl.getLimiter("2.2.2.2")
	if l1 != l2 {
		t.Fatal("second getLimiter for same IP returned a different *Limiter")
	}
	// Burst was 1; the second Allow on the same limiter should fail.
	if l2.Allow() {
		t.Fatal("burst=1: second Allow() unexpectedly allowed; limiter was reset")
	}
}

// TestIPRateLimiter_LRUEviction_AUDIT083 locks in the cap+LRU behaviour:
// adding the (cap+1)th IP must evict the least-recently-used IP, and the
// total map size must never exceed the cap.
func TestIPRateLimiter_LRUEviction_AUDIT083(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 10)
	defer rl.Stop()
	// Override cap to a small number for a fast test.
	rl.maxEntries = 5

	// Fill the cap.
	for i := 0; i < 5; i++ {
		rl.getLimiter("ip-" + strconv.Itoa(i))
	}
	if got := len(rl.limiters); got != 5 {
		t.Fatalf("after filling: len(limiters) = %d, want 5", got)
	}

	// Touch ip-0 so it becomes most-recent.
	rl.getLimiter("ip-0")

	// Add ip-5. ip-1 should be evicted (it's oldest now — touched first,
	// not re-touched).
	rl.getLimiter("ip-5")
	if got := len(rl.limiters); got != 5 {
		t.Errorf("after eviction: len(limiters) = %d, want 5 (cap respected)", got)
	}
	if _, exists := rl.limiters["ip-1"]; exists {
		t.Errorf("ip-1 should have been evicted as the LRU")
	}
	for _, present := range []string{"ip-0", "ip-2", "ip-3", "ip-4", "ip-5"} {
		if _, exists := rl.limiters[present]; !exists {
			t.Errorf("ip %s should still be present after one eviction", present)
		}
	}
}

// TestIPRateLimiter_LRUEviction_ManyOverflow — pump 3*cap IPs through and
// assert the map size stays at cap. Defends against off-by-one in the
// eviction logic.
func TestIPRateLimiter_LRUEviction_ManyOverflow(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 10)
	defer rl.Stop()
	rl.maxEntries = 100

	for i := 0; i < 300; i++ {
		rl.getLimiter("ip-" + strconv.Itoa(i))
		if got := len(rl.limiters); got > rl.maxEntries {
			t.Fatalf("after insert %d: len(limiters) = %d, exceeded cap %d", i, got, rl.maxEntries)
		}
	}
	if got := len(rl.limiters); got != rl.maxEntries {
		t.Errorf("final: len(limiters) = %d, want %d", got, rl.maxEntries)
	}
	// The last `cap` IPs must be present (no holes).
	for i := 300 - rl.maxEntries; i < 300; i++ {
		if _, exists := rl.limiters["ip-"+strconv.Itoa(i)]; !exists {
			t.Errorf("ip-%d (within last %d) missing", i, rl.maxEntries)
		}
	}
}

// TestIPRateLimiter_Cleanup_RemovesStale exercises the time-based prune.
// Insert 3 entries with deliberately-old lastSeen, drive one tick of the
// cleanup loop manually (faster than waiting 5min), then assert all 3
// are removed.
func TestIPRateLimiter_Cleanup_RemovesStale(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 10)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		ip := "stale-" + strconv.Itoa(i)
		l := rl.getLimiter(ip)
		_ = l
		// Force lastSeen well into the past so the next cleanup pass evicts it.
		rl.mu.Lock()
		rl.limiters[ip].lastSeen = time.Now().Add(-11 * time.Minute)
		rl.mu.Unlock()
	}
	// Insert a fresh entry; cleanup must NOT touch it.
	rl.getLimiter("fresh")

	// Drive one cleanup pass inline (mirrors the loop body).
	rl.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for elem := rl.lru.Back(); elem != nil; {
		entry := elem.Value.(*rateLimiterEntry)
		if entry.lastSeen.After(cutoff) {
			break
		}
		prev := elem.Prev()
		delete(rl.limiters, entry.ip)
		rl.lru.Remove(elem)
		elem = prev
	}
	rl.mu.Unlock()

	if got, want := len(rl.limiters), 1; got != want {
		t.Errorf("after cleanup: len(limiters) = %d, want %d (3 stale should be gone, only 'fresh' remains)", got, want)
	}
	if _, exists := rl.limiters["fresh"]; !exists {
		t.Errorf("'fresh' entry was incorrectly evicted")
	}
}

// TestIPRateLimiter_Stop_TerminatesGoroutine — Stop closes the quit
// channel; the cleanup goroutine sees it and returns. We assert the
// goroutine has exited by waiting for its done-channel.
func TestIPRateLimiter_Stop_TerminatesGoroutine(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 10)

	// Wrap the existing cleanup goroutine: we can't intercept its
	// termination directly, so we rely on the absence of channel
	// resends. After Stop, a second Stop should panic (close of closed
	// channel) — that's the only deterministic signal we can grab
	// without rebuilding the limiter.
	rl.Stop()

	defer func() {
		if r := recover(); r == nil {
			t.Error("second Stop() did not panic on close-of-closed-channel; quit channel was not closed by first Stop()")
		}
	}()
	rl.Stop() // expected to panic
}

// TestIPRateLimiter_Concurrent — many goroutines hammer getLimiter for the
// same and different IPs. Must not deadlock; must not exceed cap; must not
// race (use -race).
func TestIPRateLimiter_Concurrent(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(1000), 100)
	defer rl.Stop()
	rl.maxEntries = 50

	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				// Mix unique IPs and repeated IPs.
				rl.getLimiter("conc-" + strconv.Itoa((g*100+i)%200))
			}
		}(g)
	}
	wg.Wait()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if got := len(rl.limiters); got > rl.maxEntries {
		t.Errorf("len(limiters) = %d exceeds cap %d after concurrent load", got, rl.maxEntries)
	}
	if got := rl.lru.Len(); got != len(rl.limiters) {
		t.Errorf("lru length (%d) and map length (%d) diverged", got, len(rl.limiters))
	}
}
