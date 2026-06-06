package relay

import (
	"testing"
	"time"
)

// TestJitter_BoundsAndSpread_AUDIT088 verifies the retry-backoff jitter
// helper: the result is always in [d, 2d) and is not constant across calls
// (so many probes retrying after a shared outage de-synchronize instead of
// hammering the server in lock-step).
func TestJitter_BoundsAndSpread_AUDIT088(t *testing.T) {
	const base = time.Second
	seen := make(map[time.Duration]struct{})
	for i := 0; i < 200; i++ {
		got := jitter(base)
		if got < base || got >= 2*base {
			t.Fatalf("jitter(%v) = %v, want in [%v, %v)", base, got, base, 2*base)
		}
		seen[got] = struct{}{}
	}
	// With 200 samples over a 1s ([0,1e9) ns) range, a working RNG yields
	// many distinct values; a constant (broken) jitter yields exactly one.
	if len(seen) < 10 {
		t.Errorf("jitter produced only %d distinct values over 200 calls — backoff is effectively constant, defeating AUDIT-088 (thundering-herd de-sync)", len(seen))
	}
}

// TestJitter_NonPositive_AUDIT088 pins the guard: a non-positive base is
// returned unchanged (no panic from big.NewInt(0)).
func TestJitter_NonPositive_AUDIT088(t *testing.T) {
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0) = %v, want 0", got)
	}
	if got := jitter(-5 * time.Second); got != -5*time.Second {
		t.Errorf("jitter(-5s) = %v, want -5s", got)
	}
}
