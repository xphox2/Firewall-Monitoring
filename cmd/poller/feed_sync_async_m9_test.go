package main

import (
	"testing"
	"time"
)

// TestStartThreatFeedSyncAsync_OffLoopAndCleansUp_M9 pins the 2026-07-01 audit
// M9 fix: the threat-feed sync runs OFF the poller's select loop and clears its
// in-flight guard when done. A nil-db poller's runThreatFeedSync returns
// immediately, so the async launch must flip feedSyncRunning true→false without
// the caller blocking.
func TestStartThreatFeedSyncAsync_OffLoopAndCleansUp_M9(t *testing.T) {
	p := &Poller{} // db nil ⇒ runThreatFeedSync is a fast no-op

	// The call must not block (it launches a goroutine and returns).
	done := make(chan struct{})
	go func() { p.startThreatFeedSyncAsync(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("startThreatFeedSyncAsync blocked the caller — it must run off the loop")
	}

	// The guard must clear once the async sync finishes.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !p.feedSyncRunning.Load() {
			return // cleaned up as expected
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("feedSyncRunning never cleared — the guard would wedge all future syncs")
}

// TestStartThreatFeedSyncAsync_NoStacking_M9 verifies overlapping intervals
// don't stack: while one sync is in flight, a second launch is a no-op.
func TestStartThreatFeedSyncAsync_NoStacking_M9(t *testing.T) {
	p := &Poller{}
	// Simulate an in-flight sync.
	p.feedSyncRunning.Store(true)

	// A second launch must return immediately and leave the flag set (it did
	// not spawn a competing goroutine that would clear it).
	p.startThreatFeedSyncAsync()
	if !p.feedSyncRunning.Load() {
		t.Error("a re-entrant launch cleared the in-flight guard — intervals could stack")
	}
	p.feedSyncRunning.Store(false) // cleanup
}
