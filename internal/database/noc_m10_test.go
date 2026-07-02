package database

import (
	"testing"
	"time"
)

// TestGetNOCSnapshot_PropagatesCoreErrors_M10 pins the 2026-07-01 audit M10
// fix: GetNOCSnapshotFiltered previously discarded every query error and
// unconditionally returned (snap, nil), so during a DB failure the NOC hub
// broadcast an all-zero snapshot — overwriting the last good one — while the
// dashboard badge said "live". The core flow aggregate's failure must now
// surface as an error so the hub's keep-last-good branch actually runs.
func TestGetNOCSnapshot_PropagatesCoreErrors_M10(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// Healthy DB: snapshot succeeds.
	if _, err := d.GetNOCSnapshot(5 * time.Minute); err != nil {
		t.Fatalf("healthy snapshot: %v", err)
	}

	// Break the core table the way a statement_timeout/outage breaks it.
	if err := d.db.Exec("DROP TABLE flow_samples").Error; err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := d.GetNOCSnapshot(5 * time.Minute); err == nil {
		t.Fatal("want an error when the core flow aggregate fails — pre-fix this returned an all-zero snapshot with err=nil, feeding a fake 'live' dashboard")
	}
}
