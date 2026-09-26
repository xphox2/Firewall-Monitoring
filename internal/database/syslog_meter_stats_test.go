package database

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// GetSyslogStats answers windows of syslogMeterMinHours or more, fleet-wide,
// from the ingest meter instead of counting syslog_messages. These seed the
// meter and the raw table with DIFFERENT counts, so every assertion also shows
// which source answered.

// seedMeter writes one meter cell per (hoursAgo, severity, rows).
func seedMeter(t *testing.T, d *Database, now time.Time, cells ...[3]int) {
	t.Helper()
	for _, c := range cells {
		row := models.SyslogIngestHourly{
			Timestamp: now.UTC().Truncate(time.Hour).Add(-time.Duration(c[0]) * time.Hour),
			Severity:  c[1],
			RowCount:  int64(c[2]),
		}
		if err := d.db.Create(&row).Error; err != nil {
			t.Fatalf("seed meter: %v", err)
		}
	}
}

// seedRaw writes n raw rows, bypassing the meter, minutesAgo in the past.
func seedRaw(t *testing.T, d *Database, deviceID uint, minutesAgo, sev, n int) {
	t.Helper()
	rows := make([]models.SyslogMessage, n)
	for i := range rows {
		rows[i] = models.SyslogMessage{DeviceID: deviceID, Timestamp: time.Now().Add(-time.Duration(minutesAgo) * time.Minute), Severity: sev, Message: "raw"}
	}
	if err := d.db.Create(&rows).Error; err != nil {
		t.Fatalf("seed raw: %v", err)
	}
}

func meterTestDB(t *testing.T) *Database {
	t.Helper()
	d := NewDatabaseForTesting(t)
	d.ingest.lastFlush = time.Now() // no save flushes on its own
	return d
}

func sevCount(r *EventStatsResult, name string) int64 {
	for _, k := range r.BySeverity {
		if k.Key == name {
			return k.Count
		}
	}
	return 0
}

func TestSyslogStats_FleetWindowReadsMeterWholeHours(t *testing.T) {
	d := meterTestDB(t)
	now := time.Now()
	// 30h ago is outside a 24h window; 24h ago is the floored first hour and
	// is inside; 0 is the current hour.
	seedMeter(t, d, now, [3]int{30, 5, 1000}, [3]int{24, 5, 7}, [3]int{3, 4, 11}, [3]int{0, 6, 13})
	seedRaw(t, d, 0, 30, 5, 2) // disagrees with the meter on purpose

	r, err := d.GetSyslogStats(24, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 31 {
		t.Fatalf("total = %d, want 31 (meter cells inside the window), not the raw 2", r.Total)
	}
	if sevCount(r, "Notice") != 7 || sevCount(r, "Warning") != 11 || sevCount(r, "Info") != 13 {
		t.Fatalf("by_severity = %+v", r.BySeverity)
	}
	wantFrom := now.Add(-24 * time.Hour).UTC().Truncate(time.Hour)
	if r.WindowFrom == nil || !r.WindowFrom.Equal(wantFrom) {
		t.Fatalf("window_from = %v, want %v", r.WindowFrom, wantFrom)
	}
	if r.Partial {
		t.Fatal("meter history reaches past the window; must not be partial")
	}
	if len(r.OverTime) != 3 || r.OverTime[0].Bucket != wantFrom.Format("2006-01-02 15:00") || r.OverTime[0].Count != 7 {
		t.Fatalf("over_time = %+v", r.OverTime)
	}
	var sum int64
	for _, b := range r.OverTime {
		sum += b.Count
	}
	if sum != r.Total {
		t.Fatalf("chart sums to %d, total is %d — they must come from the same cells", sum, r.Total)
	}
}

func TestSyslogStats_ShortWindowAndDeviceFilterStayExact(t *testing.T) {
	d := meterTestDB(t)
	seedMeter(t, d, time.Now(), [3]int{0, 5, 500}, [3]int{1, 5, 500})
	seedRaw(t, d, 0, 30, 5, 3)
	seedRaw(t, d, 42, 30, 5, 2)

	r, err := d.GetSyslogStats(6, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 5 || r.WindowFrom != nil {
		t.Fatalf("6h: total=%d window_from=%v, want the exact raw 5 with no window_from", r.Total, r.WindowFrom)
	}
	r, err = d.GetSyslogStats(24, 42)
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 2 || r.WindowFrom != nil {
		t.Fatalf("device filter: total=%d window_from=%v, want the exact raw 2", r.Total, r.WindowFrom)
	}
}

func TestSyslogStats_PartialWhenMeterStartsInsideWindow(t *testing.T) {
	d := meterTestDB(t)
	now := time.Now()
	seedMeter(t, d, now, [3]int{5, 5, 9})
	r, err := d.GetSyslogStats(24, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := now.UTC().Truncate(time.Hour).Add(-5 * time.Hour)
	if !r.Partial || r.CoverageFrom == nil || !r.CoverageFrom.Equal(want) || r.Total != 9 {
		t.Fatalf("partial=%v coverage_from=%v total=%d, want true/%v/9", r.Partial, r.CoverageFrom, r.Total, want)
	}
}

func TestSyslogStats_EmptyMeterIsZeroNotPartial(t *testing.T) {
	d := meterTestDB(t)
	r, err := d.GetSyslogStats(24, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 0 || r.Partial || r.WindowFrom == nil {
		t.Fatalf("empty meter: total=%d partial=%v window_from=%v", r.Total, r.Partial, r.WindowFrom)
	}
}

func TestSyslogStats_CountsUnflushedRows(t *testing.T) {
	d := meterTestDB(t)
	if err := d.SaveSyslogMessages(ingestMsgs(5, 4, "live")); err != nil {
		t.Fatal(err)
	}
	if n := len(readIngestRows(t, d)); n != 0 {
		t.Fatalf("setup: %d meter rows persisted, want 0 (still in memory)", n)
	}
	r, err := d.GetSyslogStats(24, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 4 {
		t.Fatalf("total = %d, want 4 from the live buffer", r.Total)
	}
}

// A flush swaps the live map out and releases the lock before its upsert. For
// that whole round-trip (30 s on a stalled database) the cells are in neither
// the live map nor the table; they must still be counted, exactly once.
func TestSyslogStats_InFlightFlushCountedOnce(t *testing.T) {
	d := meterTestDB(t)
	if err := d.SaveSyslogMessages(ingestMsgs(5, 6, "x")); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	d.ingest.beforeUpsert = func() { close(entered); <-release }
	done := make(chan error)
	go func() { done <- d.flushSyslogIngest(false) }()
	<-entered

	r, err := d.GetSyslogStats(24, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 6 {
		t.Fatalf("during the flush: total = %d, want 6 (the in-flight cells)", r.Total)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	d.ingest.beforeUpsert = nil
	if r, _ = d.GetSyslogStats(24, 0); r.Total != 6 {
		t.Fatalf("after the flush: total = %d, want 6 (from the table, not twice)", r.Total)
	}
}

// A flush that commits between the memory snapshot and the table read would
// put the same cells in both; the generation check must re-read.
func TestSyslogStats_FlushBetweenSnapshotAndReadNotDoubled(t *testing.T) {
	d := meterTestDB(t)
	if err := d.SaveSyslogMessages(ingestMsgs(5, 8, "x")); err != nil {
		t.Fatal(err)
	}
	fired := false
	d.ingest.afterSnapshot = func() {
		if !fired {
			fired = true
			if err := d.flushSyslogIngest(false); err != nil {
				t.Errorf("flush: %v", err)
			}
		}
	}
	r, err := d.GetSyslogStats(24, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !fired || r.Total != 8 {
		t.Fatalf("fired=%v total=%d, want 8 — counted once, not from memory AND table", fired, r.Total)
	}
}

// The new fields must not appear on the alerts/traps payloads, which share
// the type.
func TestEventStatsResult_NewFieldsOmittedWhenUnset(t *testing.T) {
	b, err := json.Marshal(&EventStatsResult{Total: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"window_from", "partial", "coverage_from"} {
		if strings.Contains(string(b), k) {
			t.Fatalf("%s leaked into %s", k, b)
		}
	}
}
