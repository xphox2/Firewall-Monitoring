package main

import (
	"context"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/serverhealth"
)

// The raw archive's alerts on the server-health tick (archive plan PR 8).
// Synthetic data only.

func openArchiveAlerts(t *testing.T, p *Poller, typ models.AlertType, metric string) int64 {
	t.Helper()
	var n int64
	if err := p.db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND metric_name = ? AND resolved_at IS NULL", typ, metric).
		Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// TestCheckArchiveAlerts: a chunk parked in needs_attention fires
// ARCHIVE_NEEDS_ATTENTION for its table on the tick (through the alert
// engine: device 0, its own metric), and resetting it resolves the alert on
// the next tick. With archiving off and no chunk, the tick does nothing.
func TestCheckArchiveAlerts(t *testing.T) {
	p, db := newTestPoller(t)
	p.alertManager = alerts.NewAlertManager(p.cfg, notifier.NewNotifier(p.cfg), db)

	p.checkArchiveAlerts(nil, false)
	var n int64
	db.Gorm().Model(&models.Alert{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d alerts with archiving off and no chunk", n)
	}

	p.cfg.Archive.FlowsEnabled = true
	hour := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	parked := models.ArchiveChunk{SourceTable: "flow_samples", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: hour, PeriodEnd: hour.Add(time.Hour),
		Month: hour.Format("2006-01"), Status: models.ArchiveChunkNeedsAttention, Mismatches: 3, Error: "read-back sha256 differs"}
	if err := db.Gorm().Create(&parked).Error; err != nil {
		t.Fatal(err)
	}
	p.checkArchiveAlerts(nil, false)
	if got := openArchiveAlerts(t, p, models.AlertTypeArchiveNeedsAttention, "archive_needs_attention_flow_samples"); got != 1 {
		t.Fatalf("needs attention alerts = %d, want 1", got)
	}
	if got := openArchiveAlerts(t, p, models.AlertTypeArchiveNeedsAttention, "archive_needs_attention_syslog_messages"); got != 0 {
		t.Fatalf("syslog_messages alert = %d, want 0", got)
	}

	if _, err := db.ResetArchiveChunk(context.Background(), parked.ID, "fixed", time.Now()); err != nil {
		t.Fatal(err)
	}
	// While part of the status cannot be read, nothing fires or resolves.
	if err := db.Gorm().Exec("ALTER TABLE archive_months RENAME TO archive_months_away").Error; err != nil {
		t.Fatal(err)
	}
	p.checkArchiveAlerts(nil, false)
	if got := openArchiveAlerts(t, p, models.AlertTypeArchiveNeedsAttention, "archive_needs_attention_flow_samples"); got != 1 {
		t.Fatalf("a partly unreadable status resolved the alert: %d open", got)
	}
	if err := db.Gorm().Exec("ALTER TABLE archive_months_away RENAME TO archive_months").Error; err != nil {
		t.Fatal(err)
	}
	p.checkArchiveAlerts(nil, false)
	if got := openArchiveAlerts(t, p, models.AlertTypeArchiveNeedsAttention, "archive_needs_attention_flow_samples"); got != 0 {
		t.Fatalf("needs attention still open after the reset: %d", got)
	}
}

// TestArchiveDiskTrend: the database volume grows when its free space now is
// below the newest sample 1-3 h old; without a probe now or an old sample
// the trend is unknown.
func TestArchiveDiskTrend(t *testing.T) {
	p, db := newTestPoller(t)
	now := time.Now()
	data := func(freeGiB uint64) []alerts.ServerVolume {
		return []alerts.ServerVolume{{Label: "data", Volume: serverhealth.Volume{Path: "/data", FreeBytes: freeGiB << 30}}}
	}
	ctx := context.Background()
	if tr := p.archiveDiskTrend(ctx, data(90), true, now); tr.Known {
		t.Fatalf("no older sample, yet known: %+v", tr)
	}
	old := uint64(100) << 30
	newer := uint64(50) << 30
	for _, m := range []models.ServerMetric{
		{Timestamp: now.Add(-2 * time.Hour), DataDiskFreeBytes: &old},
		{Timestamp: now.Add(-10 * time.Minute), DataDiskFreeBytes: &newer}, // too recent to compare with
	} {
		if err := db.SaveServerMetric(&m); err != nil {
			t.Fatal(err)
		}
	}
	if tr := p.archiveDiskTrend(ctx, data(90), true, now); !tr.Known || !tr.Growing {
		t.Fatalf("100 GiB free 2 h ago, 90 now: %+v", tr)
	}
	if tr := p.archiveDiskTrend(ctx, data(95), true, now); !tr.Known || !tr.Growing {
		t.Fatalf("compared with the 10-minute-old sample: %+v", tr)
	}
	if tr := p.archiveDiskTrend(ctx, data(110), true, now); !tr.Known || tr.Growing {
		t.Fatalf("110 GiB now: %+v", tr)
	}
	if tr := p.archiveDiskTrend(ctx, data(90), false, now); tr.Known {
		t.Fatalf("data volume not measured, yet known: %+v", tr)
	}
}

// TestCheckArchiveAlerts_RetentionHeldThroughFreeSpaceRise: RETENTION_HELD
// fires while the database volume grows, and a later rise of its free space
// (growing → not growing → growing) neither resolves it nor sends a second
// notice: one open row, no recovery companion.
func TestCheckArchiveAlerts_RetentionHeldThroughFreeSpaceRise(t *testing.T) {
	p, db := newTestPoller(t)
	p.alertManager = alerts.NewAlertManager(p.cfg, notifier.NewNotifier(p.cfg), db)
	p.cfg.Archive.FlowsEnabled = true
	if err := db.UpsertSetting(&models.SystemSetting{Key: "retention_held_alert_hours", Value: "2"}); err != nil {
		t.Fatal(err)
	}
	// flow_samples verified through 5 h ago: held 4 h past the 1 h rollup age.
	start := time.Now().UTC().Truncate(time.Hour).Add(-6 * time.Hour)
	for i, c := range []models.ArchiveChunk{
		{SourceTable: "flow_samples", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: start, PeriodEnd: start.Add(time.Hour), Month: start.Format("2006-01"), Status: models.ArchiveChunkVerified},
		{SourceTable: "flow_if_counters", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: start, PeriodEnd: start.Add(time.Hour), Month: start.Format("2006-01"), Status: models.ArchiveChunkVerified},
	} {
		if err := db.Gorm().Create(&c).Error; err != nil {
			t.Fatal(i, err)
		}
	}
	old := uint64(100) << 30
	if err := db.SaveServerMetric(&models.ServerMetric{Timestamp: time.Now().Add(-2 * time.Hour), DataDiskFreeBytes: &old}); err != nil {
		t.Fatal(err)
	}
	data := func(freeGiB uint64) []alerts.ServerVolume {
		return []alerts.ServerVolume{{Label: "data", Volume: serverhealth.Volume{Path: "/data", FreeBytes: freeGiB << 30}}}
	}
	const metric = "retention_held_flow_samples"
	for i, free := range []uint64{90, 110, 90} {
		p.checkArchiveAlerts(data(free), true)
		if got := openArchiveAlerts(t, p, models.AlertTypeRetentionHeld, metric); got != 1 {
			t.Fatalf("step %d (%d GiB free): %d open RETENTION_HELD rows, want 1", i, free, got)
		}
	}
	var rows, companions int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND metric_name = ?", models.AlertTypeRetentionHeld, metric).Count(&rows)
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", models.AlertTypeRetentionHeld+"_RESOLVED").Count(&companions)
	if rows != 1 || companions != 0 {
		t.Fatalf("%d rows and %d recovery companions, want 1 and 0", rows, companions)
	}
}
