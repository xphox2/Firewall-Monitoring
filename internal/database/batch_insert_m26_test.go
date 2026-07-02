package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBatchInsertWithFallback_M26 pins the 2026-07-01 audit M26 fix: a batch
// containing one poison row must not reject the whole batch. The multi-row
// INSERT fails, the per-row fallback saves every good row and drops only the
// poison one, and the caller gets nil (a 200, not a retry-forever 500). Only
// when EVERY row fails does the helper return an error.
//
// models.ProcessedBatch's unique (probe_id, batch_id) index provides a
// deterministic poison row on both SQLite and Postgres: a duplicate of an
// already-persisted key fails the insert.
func TestBatchInsertWithFallback_M26(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.ProcessedBatch{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Now()
	// Pre-existing row whose key the poison row duplicates.
	if err := d.db.Create(&models.ProcessedBatch{ProbeID: 1, BatchID: "dup", Timestamp: now}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	batch := []models.ProcessedBatch{
		{ProbeID: 1, BatchID: "good-1", Timestamp: now},
		{ProbeID: 1, BatchID: "dup", Timestamp: now}, // poison: unique violation
		{ProbeID: 1, BatchID: "good-2", Timestamp: now},
	}
	if err := batchInsertWithFallback(d.db, "test_batch", batch); err != nil {
		t.Fatalf("one poison row must not fail the batch (pre-fix behavior): %v", err)
	}

	var n int64
	d.db.Model(&models.ProcessedBatch{}).Where("batch_id LIKE 'good-%'").Count(&n)
	if n != 2 {
		t.Errorf("good rows saved = %d, want 2 (fallback must salvage every non-poison row)", n)
	}
	d.db.Model(&models.ProcessedBatch{}).Where("batch_id = 'dup'").Count(&n)
	if n != 1 {
		t.Errorf("dup rows = %d, want 1 (poison row dropped, not duplicated)", n)
	}

	// All-poison batch → systemic failure → error (retryable 500 is correct).
	allBad := []models.ProcessedBatch{
		{ProbeID: 1, BatchID: "dup", Timestamp: now},
		{ProbeID: 1, BatchID: "good-1", Timestamp: now},
	}
	if err := batchInsertWithFallback(d.db, "test_batch", allBad); err == nil {
		t.Error("a batch where every row fails must return an error")
	}
}
