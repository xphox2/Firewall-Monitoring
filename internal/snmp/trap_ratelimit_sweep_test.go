package snmp

import (
	"fmt"
	"testing"
	"time"
)

func newRateLimiterForTest() *TrapReceiver {
	return &TrapReceiver{
		rlBuckets: make(map[string]*ipBucket),
		rlRate:    defaultTrapRatePerSec,
		rlBurst:   defaultTrapBurst,
	}
}

// TestTrapRateLimiter_IdleSweepRecoversFromFlood_M9 is the regression for the
// 2026-06-23 audit M9 finding: once a spoofed-IP flood filled the bucket map to
// the cap, every NEW legitimate device IP was rejected forever (until restart).
// The cap now sweeps idle buckets first, so a past flood does not permanently
// lock out new devices.
func TestTrapRateLimiter_IdleSweepRecoversFromFlood_M9(t *testing.T) {
	orig := maxRateLimitedIPs
	maxRateLimitedIPs = 3
	defer func() { maxRateLimitedIPs = orig }()

	tr := newRateLimiterForTest()
	stale := time.Now().Add(-10 * time.Minute) // idle past rlBucketIdleTTL
	for i := 0; i < maxRateLimitedIPs; i++ {
		tr.rlBuckets[fmt.Sprintf("10.0.0.%d", i)] = &ipBucket{tokens: defaultTrapBurst, last: stale}
	}
	tr.rlLastSweep = time.Now().Add(-2 * time.Minute) // sweep is eligible

	if !tr.allow("192.168.1.1") {
		t.Error("new IP rejected at cap even though every existing bucket is idle (M9 lockout not fixed)")
	}
}

// TestTrapRateLimiter_ActiveBucketsNotSwept_M9 confirms the sweep only evicts
// IDLE buckets — a sustained flood of *active* IPs still rejects new IPs rather
// than degrading legitimate, currently-active senders.
func TestTrapRateLimiter_ActiveBucketsNotSwept_M9(t *testing.T) {
	orig := maxRateLimitedIPs
	maxRateLimitedIPs = 3
	defer func() { maxRateLimitedIPs = orig }()

	tr := newRateLimiterForTest()
	now := time.Now()
	for i := 0; i < maxRateLimitedIPs; i++ {
		tr.rlBuckets[fmt.Sprintf("10.0.0.%d", i)] = &ipBucket{tokens: defaultTrapBurst, last: now} // active
	}
	tr.rlLastSweep = now.Add(-2 * time.Minute) // sweep eligible, but nothing is idle

	if tr.allow("192.168.1.1") {
		t.Error("new IP admitted by evicting an ACTIVE bucket; the sweep must only drop idle buckets")
	}
}
