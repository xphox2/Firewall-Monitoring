package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBatchedDeleteOlderThanWhere_SyslogSeverity is the regression for the
// 2026-06-23 CTO-loop H6 finding: the syslog retention deletes were single
// unbounded DELETEs on syslog_messages (the table that dominates DB size).
// They now route through batchedDeleteOlderThanWhere with a severity predicate.
// This verifies the predicate is honored (only matching severities deleted) and
// that the loop deletes in bounded batches (batch size shrunk so the stale rows
// span multiple iterations).
func TestBatchedDeleteOlderThanWhere_SyslogSeverity(t *testing.T) {
	d := NewDatabaseForTesting(t)

	orig := cleanupDeleteBatchSize
	cleanupDeleteBatchSize = 4
	defer func() { cleanupDeleteBatchSize = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-time.Hour)
	recent := cutoff.Add(time.Hour)

	// 10 stale critical (severity < 6) — should be deleted by the "severity < 6" pass.
	for i := 0; i < 10; i++ {
		if err := d.db.Create(&models.SyslogMessage{DeviceID: 1, Severity: 2, Timestamp: old}).Error; err != nil {
			t.Fatalf("seed stale critical: %v", err)
		}
	}
	// 5 stale informational (severity >= 6) — must survive the critical pass.
	for i := 0; i < 5; i++ {
		if err := d.db.Create(&models.SyslogMessage{DeviceID: 1, Severity: 6, Timestamp: old}).Error; err != nil {
			t.Fatalf("seed stale info: %v", err)
		}
	}
	// 3 recent critical — must survive (after cutoff).
	for i := 0; i < 3; i++ {
		if err := d.db.Create(&models.SyslogMessage{DeviceID: 1, Severity: 1, Timestamp: recent}).Error; err != nil {
			t.Fatalf("seed recent critical: %v", err)
		}
	}

	// Critical pass: delete stale severity < 6 only.
	if err := d.batchedDeleteOlderThanWhere(&models.SyslogMessage{}, cutoff, "severity < 6"); err != nil {
		t.Fatalf("batched critical delete: %v", err)
	}

	var staleCritical, staleInfo, recentCritical int64
	d.db.Model(&models.SyslogMessage{}).Where("timestamp < ? AND severity < 6", cutoff).Count(&staleCritical)
	d.db.Model(&models.SyslogMessage{}).Where("timestamp < ? AND severity >= 6", cutoff).Count(&staleInfo)
	d.db.Model(&models.SyslogMessage{}).Where("timestamp >= ?", cutoff).Count(&recentCritical)

	if staleCritical != 0 {
		t.Errorf("stale critical survived: %d, want 0", staleCritical)
	}
	if staleInfo != 5 {
		t.Errorf("stale info count = %d, want 5 (severity predicate must spare info rows)", staleInfo)
	}
	if recentCritical != 3 {
		t.Errorf("recent critical count = %d, want 3 (cutoff must spare recent rows)", recentCritical)
	}
}
