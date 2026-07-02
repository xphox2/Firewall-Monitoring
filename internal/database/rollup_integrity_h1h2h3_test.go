package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestPromoteSyslogSummaries_MultiPage_NoGroupLoss_H3 is the regression for the
// 2026-07-01 audit H3 finding: promoteSyslogSummaries ran an unscoped
// `interval_type = src AND timestamp < cutoff` DELETE inside EACH page's
// transaction, so once page 1 committed it destroyed every still-un-promoted
// hourly group — groups beyond the first page were silently lost, and the raw
// syslog behind them had already been consumed when the hourly summaries were
// created. With the delete moved after the loop (and the whole pass in one
// transaction), every group survives promotion regardless of page count.
func TestPromoteSyslogSummaries_MultiPage_NoGroupLoss_H3(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Force the multi-page path: 2 groups per page, 5 distinct groups.
	// Pre-fix, page 1 would promote 2 groups then delete all 5 groups' source
	// rows; pages 2+ found nothing and 3 groups were destroyed un-promoted.
	orig := syslogPromotePageSize
	syslogPromotePageSize = 2
	defer func() { syslogPromotePageSize = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-3 * time.Hour)
	const groups = 5
	for i := 0; i < groups; i++ {
		if err := d.db.Create(&models.SyslogSummary{
			Timestamp: old, DeviceID: 1, IntervalType: "1h", Severity: 6,
			AppName: fmt.Sprintf("app%d", i), Count: 10, SampleMessage: "info",
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	ok, err := d.promoteSyslogSummaries("1h", "1d", cutoff)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if !ok {
		t.Fatal("expected work to be done")
	}

	var daily []models.SyslogSummary
	d.db.Where("interval_type = ?", "1d").Find(&daily)
	if len(daily) != groups {
		t.Errorf("daily summary rows = %d, want %d (groups beyond page 1 were destroyed un-promoted)", len(daily), groups)
	}
	var totalCounted int64
	for _, s := range daily {
		totalCounted += s.Count
	}
	if totalCounted != groups*10 {
		t.Errorf("summed count = %d, want %d", totalCounted, groups*10)
	}

	var hourlyLeft int64
	d.db.Model(&models.SyslogSummary{}).Where("interval_type = ?", "1h").Count(&hourlyLeft)
	if hourlyLeft != 0 {
		t.Errorf("hourly source rows left = %d, want 0", hourlyLeft)
	}
}

// TestAggregateFlowsToRollup_MultiPage_NoLossOrDoubleCount_H1H2 pins the
// 2026-07-01 audit H1/H2 fixes on the flow rollup path: with more distinct
// groups than one page holds, every group must be rolled up exactly once
// (deterministic ORDER BY pagination over a watermark-scoped immutable source
// set), the byte total must be preserved exactly, and the consumed raw rows
// must all be deleted — in the same transaction as the inserts.
func TestAggregateFlowsToRollup_MultiPage_NoLossOrDoubleCount_H1H2(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	orig := flowRollupPageSize
	flowRollupPageSize = 3
	defer func() { flowRollupPageSize = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-2 * time.Hour)
	const groups = 10
	var wantBytes uint64
	for i := 0; i < groups; i++ {
		// Distinct dst_port per sample → distinct rollup group; 2 samples each.
		for j := 0; j < 2; j++ {
			b := uint64(1000*i + 100 + j)
			wantBytes += b
			if err := d.db.Create(&models.FlowSample{
				Timestamp: old, DeviceID: 1, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2",
				DstPort: uint16(1000 + i), Protocol: 6, Bytes: b, Packets: 1, SamplingRate: 1,
			}).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}

	if !d.aggregateFlowsToRollup(cutoff, "5m") {
		t.Fatal("expected work to be done")
	}

	var rollups []models.FlowRollup
	d.db.Where("interval_type = ?", "5m").Find(&rollups)
	if len(rollups) != groups {
		t.Errorf("rollup rows = %d, want %d (pages overlapped or skipped groups)", len(rollups), groups)
	}
	var gotBytes uint64
	var gotFlows int64
	for _, r := range rollups {
		gotBytes += r.BytesSum
		gotFlows += r.FlowCount
	}
	if gotBytes != wantBytes {
		t.Errorf("rolled-up bytes = %d, want %d (double-counted or lost)", gotBytes, wantBytes)
	}
	if gotFlows != groups*2 {
		t.Errorf("rolled-up flow count = %d, want %d", gotFlows, groups*2)
	}

	var rawLeft int64
	d.db.Model(&models.FlowSample{}).Where("timestamp < ?", cutoff).Count(&rawLeft)
	if rawLeft != 0 {
		t.Errorf("raw flow rows left = %d, want 0", rawLeft)
	}
}

// TestAggregateRollupsUp_MultiPage_NoLossOrDoubleCount_H1H2 pins the same
// guarantees on the rollup-promotion path (which pages over the very table it
// inserts into — the watermark plus the interval_type filter keep the source
// set immutable).
func TestAggregateRollupsUp_MultiPage_NoLossOrDoubleCount_H1H2(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	orig := flowRollupPageSize
	flowRollupPageSize = 3
	defer func() { flowRollupPageSize = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-3 * time.Hour)
	const groups = 10
	var wantBytes uint64
	for i := 0; i < groups; i++ {
		b := uint64(500 * (i + 1))
		wantBytes += b
		if err := d.db.Create(&models.FlowRollup{
			Timestamp: old, DeviceID: 1, IntervalType: "5m", SrcAddr: "10.0.0.1",
			DstAddr: "10.0.0.2", DstPort: uint16(2000 + i), Protocol: 6,
			BytesSum: b, PacketsSum: 1, FlowCount: 1, SamplingRateAvg: 1,
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if !d.aggregateRollupsUp("5m", "1h", cutoff) {
		t.Fatal("expected work to be done")
	}

	var promoted []models.FlowRollup
	d.db.Where("interval_type = ?", "1h").Find(&promoted)
	if len(promoted) != groups {
		t.Errorf("promoted rows = %d, want %d", len(promoted), groups)
	}
	var gotBytes uint64
	for _, r := range promoted {
		gotBytes += r.BytesSum
	}
	if gotBytes != wantBytes {
		t.Errorf("promoted bytes = %d, want %d", gotBytes, wantBytes)
	}

	var srcLeft int64
	d.db.Model(&models.FlowRollup{}).Where("interval_type = ?", "5m").Count(&srcLeft)
	if srcLeft != 0 {
		t.Errorf("source 5m rows left = %d, want 0", srcLeft)
	}
}
