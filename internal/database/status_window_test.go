package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func seedStatusSeries(t *testing.T, d *Database, deviceID uint, from, to time.Time, step time.Duration) {
	t.Helper()
	var stamps []time.Time
	for ts := from; !ts.After(to); ts = ts.Add(step) {
		stamps = append(stamps, ts)
	}
	// One row through GORM, the rest cloned from it (cloneRows).
	tmpl := models.SystemStatus{DeviceID: deviceID, Timestamp: stamps[0], CPUUsage: 10, MemoryUsage: 20}
	if err := d.db.Create(&tmpl).Error; err != nil {
		t.Fatalf("seed status: %v", err)
	}
	cloneRows(t, d.db, "system_status", tmpl.ID, []string{"timestamp"}, len(stamps)-1,
		func(i int) []any { return []any{stamps[i+1]} })
}

// A zoom never shows coarser buckets than the preset it was selected from:
// a 20-day window stays hourly (bucketUnitForWindow would give 6-hourly).
func TestGetSystemStatusBucketsWindow_BucketsNeverCoarserThanThePreset(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Hour)
	seedStatusSeries(t, d, 1, now.Add(-21*24*time.Hour), now, 10*time.Minute)
	seedStatusSeries(t, d, 2, now.Add(-3*time.Hour), now, time.Minute)

	cases := []struct {
		name     string
		device   uint
		span     time.Duration
		min, max int
	}{
		{"2h -> minute", 2, 2 * time.Hour, 115, 121},
		{"20h -> 5min", 1, 20 * time.Hour, 115, 121},
		{"20d -> hour (not 6hour)", 1, 20 * 24 * time.Hour, 470, 481},
	}
	for _, tc := range cases {
		b, err := d.GetSystemStatusBucketsWindow(tc.device, now.Add(-tc.span), now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(b) < tc.min || len(b) > tc.max {
			t.Errorf("%s: %d buckets, want %d..%d", tc.name, len(b), tc.min, tc.max)
		}
	}
}

func TestGetSystemStatusBucketsWindow_BoundsAndEmpty(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, ts := range []time.Time{base, base.Add(30 * time.Minute), base.Add(time.Hour), base.Add(90 * time.Minute)} {
		if err := d.db.Create(&models.SystemStatus{DeviceID: 1, Timestamp: ts, CPUUsage: 50}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// (from, to]: the row at from is excluded, the row at to included, and the
	// row after to is excluded.
	b, err := d.GetSystemStatusBucketsWindow(1, base, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(b) != 2 {
		t.Errorf("buckets = %d, want 2 (from exclusive, to inclusive)", len(b))
	}
	if b, _ := d.GetSystemStatusBucketsWindow(1, base.Add(time.Hour), base); len(b) != 0 {
		t.Errorf("an inverted window returned %d buckets", len(b))
	}
}

// The reader clamps a window longer than maxChartWindow itself.
func TestGetSystemStatusBucketsWindow_ClampsLongWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Hour)
	for days := 0; days <= 450; days += 10 {
		if err := d.db.Create(&models.SystemStatus{DeviceID: 1, Timestamp: now.Add(-time.Duration(days) * 24 * time.Hour), CPUUsage: 5}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	b, err := d.GetSystemStatusBucketsWindow(1, now.Add(-500*24*time.Hour), now)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	// Rows every 10 days; the window start is exclusive, so 400 days holds days
	// 0..390 (40 rows) and an unclamped 500 would hold 0..450 (46).
	if len(b) != 40 {
		t.Errorf("a 500-day window returned %d day buckets, want 40 (clamped to 400 days)", len(b))
	}
}

func TestClampChartWindowFrom(t *testing.T) {
	to := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	if got := ClampChartWindowFrom(to.Add(-500*24*time.Hour), to); !got.Equal(to.Add(-maxChartWindow)) {
		t.Errorf("a 500-day window starts at %v, want clamped to %v", got, to.Add(-maxChartWindow))
	}
	short := to.Add(-time.Hour)
	if got := ClampChartWindowFrom(short, to); !got.Equal(short) {
		t.Errorf("a 1-hour window was moved to %v", got)
	}
}
