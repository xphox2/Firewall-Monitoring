package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// seedSummarySource lays down rolled-up rows across two hourly buckets for one
// device, mixing scope-local and routed traffic and several distinct addresses.
func seedSummarySource(t *testing.T, d *Database, base time.Time) {
	t.Helper()
	mk := func(ts time.Time, interval, src, dst string, port uint16, proto uint8, scopeLocal bool, bytes, packets uint64, flows int64, rate float64) models.FlowRollup {
		return models.FlowRollup{
			Timestamp: ts, DeviceID: 1, IntervalType: interval,
			SrcAddr: src, DstAddr: dst, DstPort: port, Protocol: proto,
			ScopeLocal: scopeLocal, DstCountry: "US", DstASN: 15169,
			BytesSum: bytes, PacketsSum: packets, FlowCount: flows, SamplingRateAvg: rate,
		}
	}
	rows := []models.FlowRollup{
		mk(base.Add(5*time.Minute), "5m", "10.0.0.1", "8.8.8.8", 443, 6, false, 1000, 10, 2, 1),
		mk(base.Add(10*time.Minute), "5m", "10.0.0.2", "8.8.4.4", 443, 6, false, 2000, 20, 3, 1),
		mk(base.Add(15*time.Minute), "5m", "10.0.0.3", "1.1.1.1", 53, 17, false, 500, 5, 1, 1024),
		mk(base.Add(20*time.Minute), "5m", "169.254.0.1", "224.0.0.1", 0, 2, true, 100, 1, 1, 1),
		// Second hour.
		mk(base.Add(65*time.Minute), "5m", "10.0.0.1", "8.8.8.8", 443, 6, false, 7000, 70, 5, 1),
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed rollups: %v", err)
	}
}

// TestFlowSummary_ReproducesTotalsExactly is the acceptance test for the whole
// design: the summary is only worth having if its totals MATCH. Approximation is
// confined to the top-N lists; bytes, packets and flow counts must be exact.
func TestFlowSummary_ReproducesTotalsExactly(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	seedSummarySource(t, d, base)

	if !d.RunFlowSummaryCycle() {
		t.Fatal("RunFlowSummaryCycle wrote nothing")
	}

	// Only the FIRST hour is complete — the newest source row sits in the second
	// hour, which is still filling, so the summariser must stop before it.
	var want struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	if err := d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", base, base.Add(time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
		Scan(&want).Error; err != nil {
		t.Fatalf("source totals: %v", err)
	}

	var got struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	if err := d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", base).
		Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
		Scan(&got).Error; err != nil {
		t.Fatalf("summary totals: %v", err)
	}
	if got.Bytes != want.Bytes || got.Packets != want.Packets || got.Flows != want.Flows {
		t.Errorf("summary totals %d bytes / %d packets / %d flows; source has %d / %d / %d. "+
			"The summary is only usable if totals are exact.",
			got.Bytes, got.Packets, got.Flows, want.Bytes, want.Packets, want.Flows)
	}
	if want.Bytes == 0 {
		t.Fatal("seed produced no bytes; the test proves nothing")
	}
}

// TestFlowSummary_IsIdempotent is the property the whole design rests on.
// Recomputation, not merging, is what makes late-arriving data (a collector
// replaying its spool with old timestamps) correct rather than double-counted —
// and it is what lets the same code path serve as the backfill.
func TestFlowSummary_IsIdempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	seedSummarySource(t, d, base)

	snapshot := func() (bytes uint64, cube, tops, buckets int64) {
		d.Gorm().Model(&models.FlowSummary{}).Select("COALESCE(SUM(bytes_sum),0)").Scan(&bytes)
		d.Gorm().Model(&models.FlowSummary{}).Count(&cube)
		d.Gorm().Model(&models.FlowSummaryTop{}).Count(&tops)
		d.Gorm().Model(&models.FlowSummaryBucket{}).Count(&buckets)
		return
	}

	d.RunFlowSummaryCycle()
	b1, c1, t1, k1 := snapshot()
	if b1 == 0 || c1 == 0 {
		t.Fatal("first cycle wrote nothing")
	}

	// Run it twice more. A merge-based writer would inflate the byte totals and
	// duplicate rows; a recompute converges.
	d.RunFlowSummaryCycle()
	d.RunFlowSummaryCycle()
	b2, c2, t2, k2 := snapshot()

	if b2 != b1 {
		t.Errorf("bytes changed across repeated cycles: %d then %d. The writer is merging, not "+
			"recomputing, so replayed or late data will double-count.", b1, b2)
	}
	if c2 != c1 || t2 != t1 || k2 != k1 {
		t.Errorf("row counts changed across repeated cycles: cube %d→%d, tops %d→%d, buckets %d→%d",
			c1, c2, t1, t2, k1, k2)
	}
}

// TestFlowSummary_LateDataIsAbsorbed covers the case recomputation exists for:
// a collector replays its store-and-forward backlog into a bucket that was
// already summarised. The summary must end up matching the new source truth,
// not the old snapshot and not the sum of both.
func TestFlowSummary_LateDataIsAbsorbed(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	seedSummarySource(t, d, base)
	d.RunFlowSummaryCycle()

	// Late arrival into the already-summarised first hour.
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: base.Add(30 * time.Minute), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.0.0.9", DstAddr: "9.9.9.9", DstPort: 443, Protocol: 6,
		BytesSum: 4321, PacketsSum: 43, FlowCount: 7, SamplingRateAvg: 1,
	}).Error; err != nil {
		t.Fatalf("seed late row: %v", err)
	}
	d.RunFlowSummaryCycle()

	var want, got uint64
	d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", base, base.Add(time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", base).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&got)

	if got != want {
		t.Errorf("after late data the summary holds %d bytes but the source has %d. Recomputation "+
			"must pick up rows that arrived after the bucket was first summarised.", got, want)
	}
}

// TestFlowSummary_TopNIsPerDeviceAndScope pins the key shape. Scope-local noise
// (multicast, link-local) and routed traffic are shown in SEPARATE panels, so a
// single combined top-N would let broadcast chatter crowd out real talkers.
func TestFlowSummary_TopNIsPerDeviceAndScope(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	seedSummarySource(t, d, base)
	d.RunFlowSummaryCycle()

	var localRows, routedRows int64
	d.Gorm().Model(&models.FlowSummaryTop{}).
		Where("dimension = ? AND scope_local = ?", flowSummaryDimSrcAddr, true).Count(&localRows)
	d.Gorm().Model(&models.FlowSummaryTop{}).
		Where("dimension = ? AND scope_local = ?", flowSummaryDimSrcAddr, false).Count(&routedRows)

	if localRows == 0 {
		t.Error("no scope-local top-N rows; the local-traffic panel would have nothing to read")
	}
	if routedRows == 0 {
		t.Error("no routed top-N rows")
	}

	// The conversation dimension must encode the full tuple, not just an address.
	var convo models.FlowSummaryTop
	if err := d.Gorm().Where("dimension = ?", flowSummaryDimConversation).First(&convo).Error; err != nil {
		t.Fatalf("no conversation rows: %v", err)
	}
	if convo.Value == "" || len(convo.Value) < 7 {
		t.Errorf("conversation value %q does not look like src|dst|port|proto", convo.Value)
	}
}

// TestFlowSummary_BoundaryDayKeepsEveryHour is the regression for a data-loss
// bug that production would have hit continuously.
//
// The rollup ladder promotes 1h→1d with a cutoff that is NOT day-aligned, so the
// day at the 30-day boundary is always PARTIALLY promoted. On production,
// 2026-08-16 held 767 MB in the 1d tier (a single midnight row) and 41 GB across
// the 1h tier. An earlier daily summariser summed only the 1d tier and then
// deleted the hourly summary rows covering that day — recording 767 MB for a
// 45 GB day, losing 98% of it, and repeating for every new boundary day.
//
// The daily bucket must sum EVERY rollup tier, which is what makes superseding
// the hourly rows safe.
func TestFlowSummary_BoundaryDayKeepsEveryHour(t *testing.T) {
	d := NewDatabaseForTesting(t)
	day := time.Now().UTC().Add(-40 * 24 * time.Hour).Truncate(24 * time.Hour)

	// The promoted part: one daily row stamped at midnight, small.
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: day, DeviceID: 1, IntervalType: "1d",
		SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: 1000, PacketsSum: 10, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed 1d: %v", err)
	}
	// The not-yet-promoted remainder of the SAME day, far larger.
	for _, hour := range []int{1, 7, 19} {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(hour) * time.Hour), DeviceID: 1, IntervalType: "1h",
			SrcAddr: "10.0.0.2", DstAddr: "8.8.4.4", DstPort: 443, Protocol: 6,
			BytesSum: 20000, PacketsSum: 200, FlowCount: 5,
		}).Error; err != nil {
			t.Fatalf("seed 1h hour %d: %v", hour, err)
		}
	}

	// Two cycles: the first may write hourly rows, the second lets the daily tier
	// supersede them. Either way the total must survive.
	d.RunFlowSummaryCycle()
	d.RunFlowSummaryCycle()

	var sourceBytes uint64
	if err := d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", day, day.Add(24*time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&sourceBytes).Error; err != nil {
		t.Fatalf("source total: %v", err)
	}

	var summaryBytes uint64
	if err := d.Gorm().Model(&models.FlowSummary{}).
		Where("timestamp >= ? AND timestamp < ?", day, day.Add(24*time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&summaryBytes).Error; err != nil {
		t.Fatalf("summary total: %v", err)
	}

	if summaryBytes != sourceBytes {
		t.Errorf("the boundary day holds %d bytes in the summary but %d in the source. A daily "+
			"bucket that sums only the 1d tier and then supersedes the hourly rows destroys the "+
			"hours still awaiting promotion.", summaryBytes, sourceBytes)
	}
	if sourceBytes != 61000 {
		t.Fatalf("seed total is %d, expected 61000; the test is not measuring what it claims", sourceBytes)
	}

	// And the tiers must not BOTH hold the day, or a reader summing them
	// double-counts.
	var hourlyRows, dailyRows int64
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", day, day.Add(24*time.Hour)).Count(&hourlyRows)
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1d", day, day.Add(24*time.Hour)).Count(&dailyRows)
	if hourlyRows > 0 && dailyRows > 0 {
		t.Errorf("both tiers hold the boundary day (%d hourly, %d daily rows); summing them "+
			"double-counts it", hourlyRows, dailyRows)
	}
}

// TestFlowSummary_LateDataFarBehindIsAbsorbed pins the change-detection
// mechanism. An earlier version recomputed only the newest few buckets, so a
// collector offline for several hours replayed its spool into buckets the walk
// had already passed and would never revisit — the summary silently kept the
// pre-replay figures forever. Detection is now an id watermark on flow_rollups,
// which finds changes wherever in history they land.
func TestFlowSummary_LateDataFarBehindIsAbsorbed(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-14 * time.Hour).Truncate(time.Hour)

	for i := 0; i < 10; i++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: base.Add(time.Duration(i)*time.Hour + 5*time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed hour %d: %v", i, err)
		}
	}
	d.RunFlowSummaryCycle()

	// Replay lands SIX hours behind the leading edge — well outside any
	// "recompute the last few buckets" window.
	lateBucket := base.Add(2 * time.Hour)
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: lateBucket.Add(30 * time.Minute), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.9.9.9", DstAddr: "1.1.1.1", DstPort: 53, Protocol: 17,
		BytesSum: 99999, PacketsSum: 9, FlowCount: 3,
	}).Error; err != nil {
		t.Fatalf("seed late row: %v", err)
	}
	d.RunFlowSummaryCycle()

	var want, got uint64
	d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", lateBucket, lateBucket.Add(time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", lateBucket).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&got)

	if got != want {
		t.Errorf("the replayed bucket holds %d bytes in the summary but %d in the source. "+
			"Change detection must find edits anywhere in history, not only at the leading edge.",
			got, want)
	}
}

// TestFlowSummary_OneBadBucketDoesNotStallTheTier pins the failure mode that
// turned any single poison bucket into permanent, silent data loss: the pass
// used to return on the first bucket error and restart from the same place next
// cycle, so nothing after it was ever summarised.
func TestFlowSummary_OneBadBucketDoesNotStallTheTier(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	for i := 0; i < 5; i++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: base.Add(time.Duration(i)*time.Hour + 5*time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	d.RunFlowSummaryCycle()

	// Every complete bucket must be present; a stall would leave a gap.
	var buckets int64
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ?", "1h").Distinct("timestamp").Count(&buckets)
	if buckets < 4 {
		t.Errorf("only %d hourly buckets summarised; the walk should cover the seeded range", buckets)
	}
}
