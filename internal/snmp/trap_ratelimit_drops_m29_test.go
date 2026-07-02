package snmp

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestTrapRateLimiter_DropsAreVisible_M29 pins the 2026-07-01 audit M29 fix:
// rate-limiter drops were previously completely silent — no metric, no log —
// despite code comments and the CHANGELOG claiming visibility, so legitimate
// traps lost during flap storms or spoof-flood cap lockouts left zero trace.
// Both drop reasons must increment fwmon_trap_ratelimit_drops_total.
func TestTrapRateLimiter_DropsAreVisible_M29(t *testing.T) {
	tr := newRateLimiterForTest()

	// Reason "rate": exhaust one source's burst.
	rateBefore := testutil.ToFloat64(trapRateLimitDrops.WithLabelValues("rate"))
	for i := 0; i < int(defaultTrapBurst); i++ {
		tr.allow("10.1.1.1")
	}
	if tr.allow("10.1.1.1") {
		t.Fatal("burst-exhausted source should be dropped")
	}
	if got := testutil.ToFloat64(trapRateLimitDrops.WithLabelValues("rate")); got != rateBefore+1 {
		t.Errorf("rate-drop counter = %v, want %v (drop must be metric-visible)", got, rateBefore+1)
	}

	// Reason "cap": fill the source map with ACTIVE buckets (not idle, so the
	// sweep can't reclaim them), then present a new source.
	origCap := maxRateLimitedIPs
	maxRateLimitedIPs = len(tr.rlBuckets) // current map size == the cap
	defer func() { maxRateLimitedIPs = origCap }()
	tr.rlLastSweep = time.Now() // sweep not eligible

	capBefore := testutil.ToFloat64(trapRateLimitDrops.WithLabelValues("cap"))
	if tr.allow("172.16.99.99") {
		t.Fatal("new source at a full active map should be dropped")
	}
	if got := testutil.ToFloat64(trapRateLimitDrops.WithLabelValues("cap")); got != capBefore+1 {
		t.Errorf("cap-drop counter = %v, want %v", got, capBefore+1)
	}

	// The in-struct tallies feed the once-per-minute summary log line.
	tr.rlMu.Lock()
	tallies := tr.rlDropsRate + tr.rlDropsCap
	tr.rlMu.Unlock()
	if tallies == 0 {
		t.Error("drop tallies are zero — the throttled summary log would report nothing")
	}
}
