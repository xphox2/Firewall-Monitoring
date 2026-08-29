package report

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBucketAlerts_RespectsReportTimezone_AUDIT215 pins the Alert Activity
// timeline to the report timezone. Before the fix bucketAlerts formatted every
// axis label and tooltip with time.Now()/start.Add() and NO .In(loc), so on a
// UTC container a report with report_timezone=America/New_York showed the CPU/Mem
// charts and header in ET but the alert timeline in UTC — a 4-5h mismatch in the
// SAME report.
//
// Bucket INDEXING is timezone-independent (absolute duration), so the same alert
// lands in the same bucket index for any loc; only the RENDERED boundary/label
// differs. That lets us compare the UTC and ET renderings of the identical alert
// set: they must differ by exactly the America/New_York UTC offset. If the fix is
// reverted (loc ignored), both renderings are UTC and IDENTICAL, failing here.
func TestBucketAlerts_RespectsReportTimezone_AUDIT215(t *testing.T) {
	t.Parallel()

	etLoc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}

	// A single alert two hours ago — comfortably inside a 24h hourly-bucket
	// window and away from any bucket boundary, so it indexes identically under
	// both locations.
	at := time.Now().Add(-2 * time.Hour)
	alerts := []models.Alert{{Severity: "critical", Timestamp: at}}

	utc := bucketAlerts(alerts, 24, time.UTC)
	et := bucketAlerts(alerts, 24, etLoc)
	if len(utc) == 0 || len(et) != len(utc) {
		t.Fatalf("bucket count mismatch: utc=%d et=%d", len(utc), len(et))
	}

	// Locate the one populated bucket; it must be the same index in both.
	idx := -1
	for i := range utc {
		if utc[i].Count == 1 {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("no populated bucket found in UTC rendering")
	}
	if et[idx].Count != 1 {
		t.Fatalf("alert landed in different bucket index across locations: et[%d].Count=%d", idx, et[idx].Count)
	}

	if utc[idx].Tooltip == et[idx].Tooltip {
		t.Fatalf("tooltip identical across timezones (%q) — timeline ignores report_timezone (AUDIT-215)", utc[idx].Tooltip)
	}

	// The ET rendering must be the ET wall clock for the SAME instant: extract
	// the "Jan 2, 15:04" boundary each tooltip embeds (time.Parse defaults the
	// zone/year to UTC/0) and confirm the ET one is offset from the UTC one by
	// exactly the America/New_York offset in effect at the alert's real time.
	// (Arithmetic on the parsed wall clock, not a tz conversion, so the year-0
	// LMT offset in the tz database is never consulted.)
	utcT := parseTooltipBoundary(t, utc[idx].Tooltip)
	etT := parseTooltipBoundary(t, et[idx].Tooltip)
	_, offSec := at.In(etLoc).Zone() // e.g. -14400 (EDT) or -18000 (EST)
	want := utcT.Add(time.Duration(offSec) * time.Second).Format("15:04")
	if want != etT.Format("15:04") {
		t.Errorf("ET tooltip time = %s, want %s (UTC %s shifted by %+ds)",
			etT.Format("15:04"), want, utcT.Format("15:04"), offSec)
	}
	if etT.Format("15:04") == utcT.Format("15:04") {
		t.Errorf("ET and UTC tooltips share the same wall-clock time %s — no timezone conversion applied", etT.Format("15:04"))
	}
}

// parseTooltipBoundary extracts the "Jan 2, 15:04" timestamp bucketAlerts embeds
// in an hourly tooltip ("Time: Jan 2, 15:04\nAlerts: N"). The year is absent, so
// we parse without it (year 0) — only the wall-clock HH:MM is compared.
func parseTooltipBoundary(t *testing.T, tip string) time.Time {
	t.Helper()
	line := tip
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimPrefix(line, "Time: ")
	ts, err := time.Parse("Jan 2, 15:04", line)
	if err != nil {
		t.Fatalf("parse tooltip boundary %q: %v", line, err)
	}
	return ts
}

// TestBuildReportModel_AlertTimelineTimezone_AUDIT215 exercises the same fix
// through the public BuildReportModel entry point with report_timezone set, so
// the whole report (header + charts + timeline) shares one timezone.
func TestBuildReportModel_AlertTimelineTimezone_AUDIT215(t *testing.T) {
	t.Parallel()

	if _, err := time.LoadLocation("America/New_York"); err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}

	at := time.Now().Add(-2 * time.Hour)
	devices := []models.Device{{Name: "fw-1", Status: "online"}}
	dd := []*DeviceReportData{{
		AlertCount: 1,
		Alerts:     []models.Alert{{Severity: "critical", Timestamp: at}},
	}}

	etModel := BuildReportModel(devices, dd, "America/New_York", 24, "Daily")
	utcModel := BuildReportModel(devices, dd, "UTC", 24, "Daily")

	idx := -1
	for i := range utcModel.AlertBuckets {
		if utcModel.AlertBuckets[i].Count == 1 {
			idx = i
			break
		}
	}
	if idx < 0 || idx >= len(etModel.AlertBuckets) {
		t.Fatalf("no populated alert bucket (idx=%d, et len=%d)", idx, len(etModel.AlertBuckets))
	}
	if etModel.AlertBuckets[idx].Tooltip == utcModel.AlertBuckets[idx].Tooltip {
		t.Fatalf("report_timezone ignored by alert timeline: tooltip %q identical in ET and UTC (AUDIT-215)",
			utcModel.AlertBuckets[idx].Tooltip)
	}
}
