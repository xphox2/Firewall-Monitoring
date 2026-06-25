package logging

import (
	"testing"
	"time"
)

// TestSafeGoRecoversPanic proves SafeGo contains a panic to its goroutine: the
// function's own deferred cleanup still runs, and the panic does not propagate
// (if it did, the whole test process would crash). REL-01.
func TestSafeGoRecoversPanic(t *testing.T) {
	cleanupRan := make(chan struct{})
	SafeGo("test-panic", func() {
		defer close(cleanupRan) // must still run during the panic unwind
		panic("boom")
	})
	select {
	case <-cleanupRan:
	case <-time.After(2 * time.Second):
		t.Fatal("SafeGo goroutine never ran its deferred cleanup")
	}
	// Reaching here at all means the panic was recovered, not propagated.
}

// TestSafeGoRunsNormally confirms the non-panicking path still executes fn.
func TestSafeGoRunsNormally(t *testing.T) {
	done := make(chan struct{})
	SafeGo("test-normal", func() { close(done) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SafeGo did not run fn")
	}
}

// TestRecoverSwallowsPanic confirms a direct `defer Recover(...)` lets the
// surrounding function return normally after a panic.
func TestRecoverSwallowsPanic(t *testing.T) {
	survived := func() (ok bool) {
		defer Recover("test-direct")
		panic("x")
	}()
	_ = survived // never assigned because we panicked; the point is we got here
}
