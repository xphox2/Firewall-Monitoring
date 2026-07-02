package handlers

import (
	"testing"
	"time"
)

// TestNOCHub_ComputesOnFirstSubscribe_M11 pins the 2026-07-01 audit M11 fix:
// the hub idles (no per-tick aggregate scans) while nobody watches, so the
// 0→1 subscriber transition must compute a fresh snapshot inline — otherwise
// the first viewer would see nothing (or an hours-stale frame) until the next
// tick.
func TestNOCHub_ComputesOnFirstSubscribe_M11(t *testing.T) {
	_, db := setupTestHandler(t)
	hub := newNOCHub(db, time.Hour) // ticker effectively never fires in-test

	ch, latest := hub.subscribe()
	defer hub.unsubscribe(ch)

	if latest == nil {
		t.Fatal("first subscriber got no snapshot — the idle hub must compute on the 0→1 transition")
	}

	// Second subscriber while one is active: no fresh compute required, the
	// cached latest is returned.
	ch2, latest2 := hub.subscribe()
	defer hub.unsubscribe(ch2)
	if latest2 == nil {
		t.Fatal("second subscriber must receive the cached snapshot")
	}
}
