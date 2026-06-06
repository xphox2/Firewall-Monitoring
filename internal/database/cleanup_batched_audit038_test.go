package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBatchedDeleteOlderThan_AUDIT038 verifies the cleanup deletes old rows in
// bounded batches (no single giant DELETE) and leaves newer rows intact. The
// batch size is shrunk so 12 stale rows take multiple iterations, exercising
// the loop.
func TestBatchedDeleteOlderThan_AUDIT038(t *testing.T) {
	d := NewDatabaseForTesting(t)

	orig := cleanupDeleteBatchSize
	cleanupDeleteBatchSize = 5
	defer func() { cleanupDeleteBatchSize = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ { // stale (before cutoff)
		if err := d.db.Create(&models.SystemStatus{DeviceID: 1, Timestamp: cutoff.Add(-time.Hour)}).Error; err != nil {
			t.Fatalf("seed old: %v", err)
		}
	}
	for i := 0; i < 3; i++ { // recent (after cutoff) — must survive
		if err := d.db.Create(&models.SystemStatus{DeviceID: 1, Timestamp: cutoff.Add(time.Hour)}).Error; err != nil {
			t.Fatalf("seed new: %v", err)
		}
	}

	if err := d.batchedDeleteOlderThan(&models.SystemStatus{}, cutoff); err != nil {
		t.Fatalf("batchedDeleteOlderThan: %v", err)
	}

	var total, stale int64
	d.db.Model(&models.SystemStatus{}).Count(&total)
	d.db.Model(&models.SystemStatus{}).Where("timestamp < ?", cutoff).Count(&stale)
	if stale != 0 {
		t.Errorf("%d stale rows survived batched cleanup", stale)
	}
	if total != 3 {
		t.Errorf("total rows = %d, want 3 (recent rows must be kept)", total)
	}
}
