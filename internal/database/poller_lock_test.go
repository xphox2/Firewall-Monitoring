package database

import (
	"testing"
)

// TestPollerWorkLock_SQLiteAlwaysAcquires verifies the no-op behavior on
// the SQLite test backend. AUDIT-007's actual cross-process semantics
// only kick in on Postgres (pg_try_advisory_lock has no SQLite
// equivalent); SQLite must return true so single-process tests / dev
// runs are not artificially blocked.
//
// Cross-process Postgres semantics are intentionally NOT unit-tested
// here because the test harness runs entirely in SQLite (AUDIT-118
// notes the production/test parity gap). The functional contract is
// documented in the doc comments of TryAcquirePollerWorkLock; integration
// coverage will land when AUDIT-118's testcontainers-go harness arrives.
func TestPollerWorkLock_SQLiteAlwaysAcquires(t *testing.T) {
	db := NewDatabaseForTesting(t)

	// First acquire: must succeed.
	if !db.TryAcquirePollerWorkLock() {
		t.Fatal("first TryAcquirePollerWorkLock() returned false on SQLite; must return true (no-op)")
	}

	// Second acquire on the same db must ALSO succeed (no actual lock
	// being held in SQLite). Mirrors single-process behaviour where the
	// same poller's tickers chain back-to-back.
	if !db.TryAcquirePollerWorkLock() {
		t.Fatal("second TryAcquirePollerWorkLock() returned false on SQLite; should be true (no-op)")
	}

	// Release must not panic.
	db.ReleasePollerWorkLock()
	db.ReleasePollerWorkLock() // double-release also safe on SQLite
}

// TestPollerWorkLock_ReleaseAfterAcquireDoesNotPanic exercises the defer
// release pattern documented on TryAcquirePollerWorkLock.
func TestPollerWorkLock_ReleaseAfterAcquireDoesNotPanic(t *testing.T) {
	db := NewDatabaseForTesting(t)

	func() {
		if !db.TryAcquirePollerWorkLock() {
			t.Fatal("acquire failed")
		}
		defer db.ReleasePollerWorkLock()
		// Simulate work.
	}()
	// If we get here without panic, the defer fired cleanly.
}
