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
