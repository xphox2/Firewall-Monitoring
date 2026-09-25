//go:build integration

package database

import (
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestRetentionDeleteIntegration_DeletesOldestFirst is the behavioural pin for the
// ordered subquery, which the SQLite lane cannot provide: there the planner picks
// the timestamp index for this predicate whether or not the query asks for an
// order, so every behavioural assertion passes with the fix reverted (seeding
// newest-first to break the tie does not help — the index is still used).
//
// On PostgreSQL, a small freshly-inserted table with no ANALYZE is seq-scanned in
// physical order. Insert newest-first and physical order is the reverse of time
// order, so an UNORDERED batch deletes the NEWEST rows and an ordered one the
// oldest — an observable difference.
//
// Oldest-first is also the behaviour retention wants on its own terms: a pass that
// can only partly keep up should be removing the oldest data, not an arbitrary
// slice of it.
func TestRetentionDeleteIntegration_DeletesOldestFirst(t *testing.T) {
	d := NewIntegrationDB(t)

	base := time.Now().Add(-48 * time.Hour)
	const rows = 10
	// Newest first, so rowid/physical order is the reverse of timestamp order.
	for i := rows - 1; i >= 0; i-- {
		if err := d.Gorm().Create(&models.SyslogMessage{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Message:   "m", Severity: 6,
		}).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	origBatch, origSleep := cleanupDeleteBatchSize, batchDeleteInterSleep
	cleanupDeleteBatchSize, batchDeleteInterSleep = rows/2, 0
	defer func() { cleanupDeleteBatchSize, batchDeleteInterSleep = origBatch, origSleep }()

	// Let exactly one batch commit, then abort with an error the loop does not
	// retry, so precisely half the rows are gone.
	stop := errors.New("stop after the first batch")
	calls := 0
	cleanupBatchHook = func(int) error {
		calls++
		if calls > 1 {
			return stop
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); !errors.Is(err, stop) {
		t.Fatalf("expected the injected error to surface, got %v", err)
	}

	var survivors []models.SyslogMessage
	if err := d.Gorm().Order("timestamp").Find(&survivors).Error; err != nil {
		t.Fatal(err)
	}
	if len(survivors) != rows/2 {
		t.Fatalf("survivors = %d, want %d (one committed batch)", len(survivors), rows/2)
	}
	// The surviving half must be the NEWEST half: the oldest survivor is the
	// row at index rows/2.
	want := base.Add(time.Duration(rows/2) * time.Minute).Truncate(time.Second)
	if got := survivors[0].Timestamp.Truncate(time.Second); !got.Equal(want) {
		t.Errorf("oldest survivor is %s, want %s — an unordered batch takes whatever the "+
			"scan reaches first (here the newest rows), which is the seq-scan behaviour "+
			"that made each batch cost more than the last until one blew the timeout",
			got.UTC(), want.UTC())
	}
}
