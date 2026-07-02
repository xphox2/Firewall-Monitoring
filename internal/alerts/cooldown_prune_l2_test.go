package alerts

import (
	"testing"
	"time"
)

// TestPruneExpired_RespectsPerKeyCooldown_L2 pins the 2026-07-01 audit L2 fix:
// prune must evict a key only once it is past its OWN effective cooldown, not a
// fixed 2×base threshold — otherwise an operator-set long cooldown (e.g. 60m to
// quiet a noisy detector) was truncated to ~10m by the prune, re-alerting early.
func TestPruneExpired_RespectsPerKeyCooldown_L2(t *testing.T) {
	am, _ := newTestManager(t) // base alertCooldown = 5m

	t0 := time.Unix(1_000_000, 0)
	am.mu.Lock()
	am.recordCooldownLocked("long", t0, 60*time.Minute) // operator-set long cooldown
	am.recordCooldownLocked("short", t0, 0)             // no explicit → base 5m
	am.mu.Unlock()

	// 15 minutes later: the long-cooldown key must SURVIVE (15m < 60m), the
	// base-cooldown key must be gone (15m > 5m). Pre-fix, both were evicted at
	// the fixed 10m threshold, truncating the 60m cooldown.
	am.mu.Lock()
	am.pruneExpiredLocked(t0.Add(15 * time.Minute))
	_, longAlive := am.lastAlert["long"]
	_, shortAlive := am.lastAlert["short"]
	am.mu.Unlock()
	if !longAlive {
		t.Error("60m-cooldown key was evicted after 15m — its configured cooldown got truncated")
	}
	if shortAlive {
		t.Error("5m-cooldown key should have been evicted after 15m")
	}

	// Past its own window the long key is finally evicted (and its cooldownFor
	// entry cleaned up).
	am.mu.Lock()
	am.pruneExpiredLocked(t0.Add(61 * time.Minute))
	_, stillLong := am.lastAlert["long"]
	_, stillCd := am.cooldownFor["long"]
	am.mu.Unlock()
	if stillLong || stillCd {
		t.Error("60m-cooldown key should be evicted (and its cooldownFor cleared) after 61m")
	}
}
