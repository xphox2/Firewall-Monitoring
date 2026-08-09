package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// Summary pruning used to reuse the per-severity RAW windows. Aggregation
// creates a summary from rows already older than that same window, so every
// summary was born past its own prune cutoff and the next cleanup destroyed it.
// Production showed the result exactly: 282 rows, every one stamped at the
// 7-day raw cutoff, in a table that had never retained a row for a full day.
//
// These pin that summaries now outlive their source under their own window.

func seedSummary(t *testing.T, d *Database, sev int, ts time.Time) {
	t.Helper()
	if err := d.db.Create(&models.SyslogSummary{
		Timestamp: ts, DeviceID: 1, IntervalType: "1h", Severity: sev,
		AppName: "traffic", MessagePattern: "p", Count: 10, SampleMessage: "x",
	}).Error; err != nil {
		t.Fatalf("seed summary sev=%d: %v", sev, err)
	}
}

// TestSummariesSurviveTheirOwnCreation is the direct regression. A summary
// aggregated from rows just past the 7-day raw window must NOT be deleted by the
// cleanup that immediately follows.
func TestSummariesSurviveTheirOwnCreation(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}, &models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Exactly the production shape: raw window 7 days, summary stamped at it.
	ret := config.RetentionConfig{DefaultDays: 90, SyslogInfoDays: 7, SyslogCriticalDays: 30}
	seedSummary(t, d, 6, time.Now().AddDate(0, 0, -8))

	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var n int64
	d.db.Model(&models.SyslogSummary{}).Count(&n)
	if n != 1 {
		t.Errorf("summary rows after cleanup = %d, want 1. A summary is created from "+
			"rows OLDER than the raw window, so pruning it on that same window "+
			"destroys it the moment it is written — which is why syslog_summaries "+
			"sat empty in production.", n)
	}
}

// TestSummaryRetentionIsIndependentOfRawWindows pins that the two are decoupled:
// a very short raw window must not drag summaries down with it.
func TestSummaryRetentionIsIndependentOfRawWindows(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}, &models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ret := config.RetentionConfig{DefaultDays: 90, SyslogInfoDays: 1, SyslogCriticalDays: 1}
	// Far older than any raw window, far inside the 365-day summary default.
	seedSummary(t, d, 6, time.Now().AddDate(0, 0, -200))

	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var n int64
	d.db.Model(&models.SyslogSummary{}).Count(&n)
	if n != 1 {
		t.Errorf("summary rows = %d, want 1 — summaries must be governed by their "+
			"own window, not by the raw per-severity windows", n)
	}
}

// TestSummaryRetentionWindowIsEnforced — the window still has to actually prune.
func TestSummaryRetentionWindowIsEnforced(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}, &models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := d.db.Create(&models.SystemSetting{Key: SyslogSummaryRetentionKey, Value: "30"}).Error; err != nil {
		t.Fatalf("set window: %v", err)
	}

	seedSummary(t, d, 6, time.Now().AddDate(0, 0, -40)) // beyond 30 → deleted
	seedSummary(t, d, 6, time.Now().AddDate(0, 0, -10)) // inside 30 → kept

	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 90, SyslogInfoDays: 7}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var n int64
	d.db.Model(&models.SyslogSummary{}).Count(&n)
	if n != 1 {
		t.Errorf("summary rows = %d, want 1 (the 40-day-old row pruned, the 10-day one kept)", n)
	}
}

// TestSummaryRetentionZeroKeepsForever mirrors the raw windows' semantics.
func TestSummaryRetentionZeroKeepsForever(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}, &models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := d.db.Create(&models.SystemSetting{Key: SyslogSummaryRetentionKey, Value: "0"}).Error; err != nil {
		t.Fatalf("set window: %v", err)
	}

	seedSummary(t, d, 6, time.Now().AddDate(0, -20, 0))

	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 90, SyslogInfoDays: 7}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var n int64
	d.db.Model(&models.SyslogSummary{}).Count(&n)
	if n != 1 {
		t.Errorf("summary rows = %d, want 1 — 0 means keep forever", n)
	}
}

// TestSummaryPruneSpansStaticBand pins that pruning covers severity 5 even while
// the aggregation floor is 6. Without this, lowering the floor to 5 and later
// raising it would strand severity-5 summaries at a severity nothing visits —
// forever, in a table that is a plain heap on most deployments so partition drop
// cannot reclaim them either.
func TestSummaryPruneSpansStaticBand(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}, &models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := d.db.Create(&models.SystemSetting{Key: SyslogSummaryRetentionKey, Value: "30"}).Error; err != nil {
		t.Fatalf("set window: %v", err)
	}

	old := time.Now().AddDate(0, 0, -40)
	seedSummary(t, d, 5, old) // below the default aggregation floor of 6
	seedSummary(t, d, 6, old)
	seedSummary(t, d, 7, old)

	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 90, SyslogInfoDays: 7}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var n int64
	d.db.Model(&models.SyslogSummary{}).Count(&n)
	if n != 0 {
		var left []models.SyslogSummary
		d.db.Find(&left)
		t.Errorf("expired summaries left = %d, want 0; pruning must span the static "+
			"band [%d..%d] regardless of the current aggregation floor. left = %+v",
			n, syslogSummaryBandFloor, SyslogSeverityCount-1, left)
	}
}

func TestSyslogSummaryRetentionDays_Default(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := d.SyslogSummaryRetentionDays(); got != syslogSummaryRetentionDefault {
		t.Errorf("default = %d, want %d", got, syslogSummaryRetentionDefault)
	}
	// The default must exceed any plausible raw window, or summaries die young.
	if syslogSummaryRetentionDefault <= 30 {
		t.Errorf("default summary window (%d) must comfortably exceed the raw windows",
			syslogSummaryRetentionDefault)
	}
}
