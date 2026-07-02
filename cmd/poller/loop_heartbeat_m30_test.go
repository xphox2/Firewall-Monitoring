package main

import (
	"testing"
	"time"
)

// TestPollerLoopHeartbeat_M30 pins the /readyz loop-liveness signal from the
// 2026-07-01 audit M30 finding: a panicked-and-halted poller loop previously
// kept green health checks forever. LoopAliveWithin must be stale for a
// never-stamped or long-idle heartbeat and alive right after a stamp.
func TestPollerLoopHeartbeat_M30(t *testing.T) {
	p := &Poller{}

	if p.LoopAliveWithin(time.Minute) {
		t.Fatal("zero (never-stamped) heartbeat must read as stale")
	}

	p.markLoopAlive()
	if !p.LoopAliveWithin(time.Minute) {
		t.Fatal("freshly stamped heartbeat must read as alive")
	}

	p.loopBeat.Store(time.Now().Add(-2 * time.Hour).Unix())
	if p.LoopAliveWithin(10 * time.Minute) {
		t.Fatal("2h-old heartbeat must read as stale against a 10m window")
	}
}
