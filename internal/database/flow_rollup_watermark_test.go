package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The flow rollup passes carried the same filtered-MAX(id) watermark that broke
// syslog aggregation, and kept failing in production after that fix shipped:
//
//	flows.go:950: Flow rollup: 5m watermark: ERROR: canceling statement due to
//	statement timeout (SQLSTATE 57014) (rolled back, will retry next cycle)
//
// PostgreSQL rewrites MAX(id) into a backward walk of the primary key that stops
// at the first row passing the filter, priced by expected-rows-until-first-
// match. Under `interval_type = ? AND timestamp < ?` the newest ids all fail the
// timestamp test, so the walk crossed most of the table while the planner still
// estimated 4.48 against a real worst case of 29,536,475 — measured on the live
// flow_rollups table, where it blew the 30s statement_timeout every cycle.
// Unfiltered, the same rewrite stops on the first tuple: 1.3ms.
//
// These tests pin the behaviour that makes the substitution safe: a wider bound
// must not widen what a pass consumes.

// TestFlowRollupWatermark_UnfilteredBoundDoesNotWidenDelete guards the 5m pass.
// With an unfiltered watermark, samples NEWER than the cutoff sit below the
// bound for the first time and must survive.
func TestFlowRollupWatermark_UnfilteredBoundDoesNotWidenDelete(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-2 * time.Hour)
	recent := cutoff.Add(2 * time.Hour)

	seedFlow(t, d, old, 1001, 500)
	// Created last, so its id is the table maximum — it IS the unfiltered
	// watermark, and it must not be rolled up or deleted.
	seedFlow(t, d, recent, 2002, 700)

	if !d.aggregateFlowsToRollup(cutoff, "5m") {
		t.Fatal("expected work to be done")
	}

	var survivors []models.FlowSample
	d.db.Find(&survivors)
	if len(survivors) != 1 {
		t.Fatalf("surviving raw samples = %d, want 1", len(survivors))
	}
	if survivors[0].DstPort != 2002 {
		t.Errorf("survivor dst_port = %d, want 2002 — the unfiltered watermark must "+
			"bound the delete, never define it", survivors[0].DstPort)
	}

	var rollups []models.FlowRollup
	d.db.Where("interval_type = ?", "5m").Find(&rollups)
	if len(rollups) != 1 || rollups[0].BytesSum != 500 {
		t.Errorf("rollups = %+v, want exactly the pre-cutoff sample (500 bytes)", rollups)
	}
}

// TestFlowRollupWatermark_NoEligibleRowsIsANoOp pins the replacement for the
// `watermark == 0` early-exit. An unfiltered MAX(id) is non-zero whenever the
// table holds any row, so without the work probe a pass with nothing to do would
// fall through — and a future edit that dropped a predicate would have nothing
// standing between it and a full delete.
func TestFlowRollupWatermark_NoEligibleRowsIsANoOp(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// Rows exist — MAX(id) is not zero — but none are older than the cutoff.
	seedFlow(t, d, cutoff.Add(time.Hour), 3003, 900)

	if d.aggregateFlowsToRollup(cutoff, "5m") {
		t.Error("reported work done with no eligible samples")
	}

	var n int64
	d.db.Model(&models.FlowSample{}).Count(&n)
	if n != 1 {
		t.Errorf("raw samples = %d, want 1 — a no-work pass must delete nothing", n)
	}
	var rollups int64
	d.db.Model(&models.FlowRollup{}).Count(&rollups)
	if rollups != 0 {
		t.Errorf("rollup rows = %d, want 0", rollups)
	}
}

// TestFlowRollupPromoteWatermark_DoesNotConsumeOtherIntervals guards the promote
// path — the one that was actually timing out on production. It pages over the
// very table it inserts into, so with an unfiltered bound the `interval_type`
// predicate is the only thing protecting other intervals and its own output.
func TestFlowRollupPromoteWatermark_DoesNotConsumeOtherIntervals(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-3 * time.Hour)

	for i := 0; i < 3; i++ {
		seedRollup(t, d, "5m", old, uint16(4000+i), 100)
	}
	// A pre-existing hourly row older than the cutoff: a delete that lost its
	// interval_type predicate would take this too. Created last so it holds the
	// table's maximum id.
	seedRollup(t, d, "1h", old, 5005, 999)

	if !d.aggregateRollupsUp("5m", "1h", cutoff) {
		t.Fatal("expected promote to do work")
	}

	var src, dst int64
	d.db.Model(&models.FlowRollup{}).Where("interval_type = ?", "5m").Count(&src)
	d.db.Model(&models.FlowRollup{}).Where("interval_type = ?", "1h").Count(&dst)
	if src != 0 {
		t.Errorf("5m rows = %d, want 0 (all promoted and consumed)", src)
	}
	// The pre-existing hourly row survives alongside whatever was promoted.
	if dst < 2 {
		t.Errorf("1h rows = %d, want at least 2 — the promote delete must not reach "+
			"its own output or pre-existing rows of another interval", dst)
	}
	var preserved int64
	d.db.Model(&models.FlowRollup{}).Where("interval_type = ? AND bytes_sum = ?", "1h", 999).Count(&preserved)
	if preserved != 1 {
		t.Errorf("pre-existing 1h row survived = %d, want 1", preserved)
	}
}

func seedFlow(t *testing.T, d *Database, ts time.Time, port uint16, bytes uint64) {
	t.Helper()
	if err := d.db.Create(&models.FlowSample{
		Timestamp: ts, DeviceID: 1, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2",
		DstPort: port, Protocol: 6, Bytes: bytes, Packets: 1, SamplingRate: 1,
	}).Error; err != nil {
		t.Fatalf("seed flow %d: %v", port, err)
	}
}

func seedRollup(t *testing.T, d *Database, interval string, ts time.Time, port uint16, bytes uint64) {
	t.Helper()
	if err := d.db.Create(&models.FlowRollup{
		Timestamp: ts, DeviceID: 1, IntervalType: interval,
		SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", DstPort: port, Protocol: 6,
		BytesSum: bytes, PacketsSum: 1, FlowCount: 1, SamplingRateAvg: 1,
	}).Error; err != nil {
		t.Fatalf("seed rollup %s/%d: %v", interval, port, err)
	}
}
