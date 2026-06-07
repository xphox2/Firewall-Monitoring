package database

import "testing"

// TestAcquireAPISingletonLock_SQLiteNoOp_AUDIT040 pins that the API singleton
// guard is inert on the SQLite test backend (single-process): it always reports
// acquired with a non-nil no-op release. The real cross-process contention is
// exercised against Postgres in the integration suite.
func TestAcquireAPISingletonLock_SQLiteNoOp_AUDIT040(t *testing.T) {
	d := NewDatabaseForTesting(t)

	release, acquired, err := d.AcquireAPISingletonLock()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !acquired {
		t.Fatal("SQLite must report acquired=true (single-process; guard inert)")
	}
	if release == nil {
		t.Fatal("release must be a non-nil no-op")
	}
	release() // must not panic

	// A second acquire is also true on SQLite (no real lock).
	if _, ok2, _ := d.AcquireAPISingletonLock(); !ok2 {
		t.Fatal("SQLite second acquire must also be true (no-op)")
	}
}
