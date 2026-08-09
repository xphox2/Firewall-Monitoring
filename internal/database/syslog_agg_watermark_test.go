package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The watermark in aggregateSyslogToSummary / promoteSyslogSummaries used to be
// computed with the pass's own predicates attached:
//
//	SELECT COALESCE(MAX(id),0) ... WHERE timestamp < ? AND severity = ?
//
// PostgreSQL rewrites MAX(id) into a backward walk of the primary key that stops
// at the first row passing the filter, and prices it by expected-rows-until-
// first-match. Because the newest ids all fail `timestamp < cutoff`, that walk
// crossed most of the table while the planner still estimated single-digit cost.
// On a 92M-row production table it took >120s against a 30s statement_timeout,
// so every 5-minute cycle aborted and retried and syslog_summaries stayed empty
// forever.
//
// The fix takes an UNFILTERED MAX(id) (0.5ms — the same rewrite stops on the
// first tuple) and keeps the predicates on the SELECT and DELETE, where they
// belong. These tests pin the behaviour that makes that substitution safe: a
// wider bound must not widen what the pass consumes.

// TestAggregateWatermark_UnfilteredBoundDoesNotWidenDelete is the core guard.
// With an unfiltered watermark, ids belonging to OTHER severities and to rows
// NEWER than the cutoff sit below the bound for the first time. If the SELECT or
// the DELETE ever loses a predicate, this test wipes rows it must not touch.
func TestAggregateWatermark_UnfilteredBoundDoesNotWidenDelete(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-2 * time.Hour)
	recent := cutoff.Add(2 * time.Hour)

	// Eligible: severity 6, older than cutoff.
	seed(t, d, 1, 6, old, "eligible")
	// Same severity but NEWER than the cutoff — must survive.
	seed(t, d, 1, 6, recent, "too-new")
	// Older than the cutoff but a DIFFERENT severity — must survive. Created
	// last so its id is the table maximum, i.e. it IS the unfiltered watermark.
	seed(t, d, 1, 5, old, "other-severity")

	ok, err := d.aggregateSyslogToSummary(cutoff, 6, "1h")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !ok {
		t.Fatal("expected work to be done")
	}

	var survivors []models.SyslogMessage
	d.db.Order("message").Find(&survivors)
	if len(survivors) != 2 {
		t.Fatalf("surviving raw rows = %d, want 2; got %+v", len(survivors), messages(survivors))
	}
	got := messages(survivors)
	if got[0] != "other-severity" || got[1] != "too-new" {
		t.Errorf("survivors = %v, want [other-severity too-new] — the unfiltered "+
			"watermark must bound the delete, never define it", got)
	}

	var summaries []models.SyslogSummary
	d.db.Find(&summaries)
	if len(summaries) != 1 {
		t.Errorf("summary rows = %d, want 1 (only the eligible row)", len(summaries))
	}
}

// TestAggregateWatermark_NoEligibleRowsIsANoOp pins the replacement for the old
// `watermark == 0` early-exit. An unfiltered MAX(id) is non-zero whenever the
// table holds ANY row, so without the work probe a severity with nothing to do
// would fall through to the paged scan — and, far worse, a future edit that
// dropped a predicate would have nothing standing between it and a full delete.
func TestAggregateWatermark_NoEligibleRowsIsANoOp(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// Rows exist — so MAX(id) over the table is NOT zero — but none of them are
	// eligible for severity 7.
	seed(t, d, 1, 6, cutoff.Add(-2*time.Hour), "wrong-severity")
	seed(t, d, 1, 7, cutoff.Add(2*time.Hour), "too-new")

	ok, err := d.aggregateSyslogToSummary(cutoff, 7, "1h")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if ok {
		t.Error("aggregate reported work done with no eligible rows")
	}

	var n int64
	d.db.Model(&models.SyslogMessage{}).Count(&n)
	if n != 2 {
		t.Errorf("raw rows = %d, want 2 — a no-work pass must delete nothing", n)
	}
	var summaries int64
	d.db.Model(&models.SyslogSummary{}).Count(&summaries)
	if summaries != 0 {
		t.Errorf("summary rows = %d, want 0", summaries)
	}
}

// TestPromoteWatermark_DoesNotConsumeItsOwnOutput pins the promote path's
// version of the same substitution. The daily rows are inserted inside the same
// transaction as the delete, so with an unfiltered bound taken beforehand they
// sit above it — but the delete's `interval_type = srcInterval` predicate is
// what actually protects them, and that is what this pins.
func TestPromoteWatermark_DoesNotConsumeItsOwnOutput(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-2 * time.Hour)

	for i := 0; i < 3; i++ {
		if err := d.db.Create(&models.SyslogSummary{
			DeviceID: 1, Severity: 6, IntervalType: "1h",
			Timestamp: old, Count: 10, AppName: "app", MessagePattern: "p",
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// A daily row already present and older than the cutoff: a delete that lost
	// its interval_type predicate would take this too.
	if err := d.db.Create(&models.SyslogSummary{
		DeviceID: 1, Severity: 6, IntervalType: "1d",
		Timestamp: old, Count: 99, AppName: "app", MessagePattern: "p",
	}).Error; err != nil {
		t.Fatalf("seed daily: %v", err)
	}

	ok, err := d.promoteSyslogSummaries("1h", "1d", cutoff)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if !ok {
		t.Fatal("expected promote to do work")
	}

	var hourly, daily int64
	d.db.Model(&models.SyslogSummary{}).Where("interval_type = ?", "1h").Count(&hourly)
	d.db.Model(&models.SyslogSummary{}).Where("interval_type = ?", "1d").Count(&daily)
	if hourly != 0 {
		t.Errorf("hourly rows = %d, want 0 (all promoted and consumed)", hourly)
	}
	// The pre-existing daily row plus the one promoted from the three hourlies.
	if daily != 2 {
		t.Errorf("daily rows = %d, want 2 — the promote delete must not reach its "+
			"own output or pre-existing daily rows", daily)
	}
}

func seed(t *testing.T, d *Database, deviceID uint, severity int, ts time.Time, msg string) {
	t.Helper()
	if err := d.db.Create(&models.SyslogMessage{
		DeviceID: deviceID, Severity: severity, AppName: "app",
		Timestamp: ts, Message: msg,
	}).Error; err != nil {
		t.Fatalf("seed %q: %v", msg, err)
	}
}

func messages(rows []models.SyslogMessage) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Message)
	}
	return out
}
