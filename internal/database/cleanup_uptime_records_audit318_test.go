package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// AUDIT-318: uptime_records gained an active writer (the 15m uptime-snapshot
// worker) but shipped with no retention path. It must be in CleanupOldData's
// entries slice so it doesn't grow unbounded — it rides StatusDays like its
// source table system_status.
func TestCleanupOldData_CoversUptimeRecords_AUDIT318(t *testing.T) {
	d := NewDatabaseForTesting(t)
	stale := time.Now().AddDate(0, 0, -60)
	recent := time.Now().AddDate(0, 0, -1)

	if err := d.Gorm().Create(&models.UptimeRecord{DeviceID: 1, Timestamp: stale, UptimePercent: 99}).Error; err != nil {
		t.Fatalf("seed stale uptime_records: %v", err)
	}
	if err := d.Gorm().Create(&models.UptimeRecord{DeviceID: 1, Timestamp: recent, UptimePercent: 99}).Error; err != nil {
		t.Fatalf("seed recent uptime_records: %v", err)
	}

	if err := d.CleanupOldData(config.RetentionConfig{StatusDays: 30}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var count int64
	if err := d.Gorm().Model(&models.UptimeRecord{}).Count(&count).Error; err != nil {
		t.Fatalf("count uptime_records after cleanup: %v", err)
	}
	if count != 1 {
		t.Errorf("uptime_records has %d row(s) after cleanup, want 1 (stale pruned, recent kept) — AUDIT-318: the table must be in CleanupOldData's entries slice", count)
	}
}
