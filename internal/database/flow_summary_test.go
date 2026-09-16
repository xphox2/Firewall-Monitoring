package database

import (
	"fmt"
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

	// The day is now held at HOURLY resolution: the daily tier yields any day the
	// finer tiers still have rows in, so the promotion boundary stays hour-stamped
	// and a window cutoff falling inside it truncates the same way the live path
	// does. What must not happen is BOTH tiers holding it.
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

// TestFlowSummary_WatermarkAdvancesWhenNothingIsOwned pins a leak in the change
// detection. The watermark used to advance only when a pass WROTE something,
// but a tier routinely sees rows it does not own — the daily tier sees a stream
// of new 5m rows for today and owns none of them. It then wrote nothing, never
// advanced, and re-scanned an ever-larger id range every cycle forever.
//
// The watermark means "seen up to here", not "wrote something".
func TestFlowSummary_WatermarkAdvancesWhenNothingIsOwned(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	seedSummarySource(t, d, base)
	d.RunFlowSummaryCycle()

	maxID := func() int64 {
		var n int64
		d.Gorm().Model(&models.FlowRollup{}).Select("COALESCE(MAX(id),0)").Scan(&n)
		return n
	}
	after := d.summaryWatermark("1h")
	if after == 0 {
		t.Fatal("watermark never set after the first pass")
	}
	if after != maxID() {
		t.Errorf("watermark is %d but the highest rollup id is %d after a clean pass", after, maxID())
	}

	// A steady-state pass with nothing new must leave the watermark at the
	// ceiling rather than dropping back or stalling.
	d.RunFlowSummaryCycle()
	if got := d.summaryWatermark("1h"); got != maxID() {
		t.Errorf("after a second clean pass the watermark is %d, want %d", got, maxID())
	}

	// The daily tier owns nothing here (no 1d rows at all), so it writes nothing
	// — and must still not be stuck at zero-progress forever.
	if got := d.summaryWatermark("1d"); got != maxID() {
		t.Errorf("the daily tier's watermark is %d, want %d. A tier that owns none of "+
			"what it sees must still record that it has seen it, or its dirty scan grows "+
			"without bound.", got, maxID())
	}
}

// TestFlowSummary_FailedBucketIsRetriedNotSkipped pins the hole that resuming
// from MAX(summary timestamp) created. If a bucket failed while a later one
// succeeded, the max jumped past the failure and the walk resumed beyond the
// gap — leaving a permanent hole in the middle of history that nothing revisited
// and nothing reported. Backfill now resumes from a CONTIGUOUS fill marker.
func TestFlowSummary_FailedBucketIsRetriedNotSkipped(t *testing.T) {
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

	poison := base.Add(2 * time.Hour)
	orig := flowSummaryBucketHook
	// defer, not a trailing statement: a t.Fatal or panic below would otherwise
	// leak the poison hook into every later test in the package.
	defer func() { flowSummaryBucketHook = orig }()
	flowSummaryBucketHook = func(interval string, bucket time.Time) error {
		if interval == "1h" && bucket.Equal(poison) {
			return fmt.Errorf("synthetic bucket failure")
		}
		return nil
	}
	d.RunFlowSummaryCycle()

	// Later buckets must still have been written — one bad bucket must not stall
	// the tier.
	var later int64
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp > ?", "1h", poison).Count(&later)
	if later == 0 {
		t.Error("no buckets after the failing one were written; one bad bucket stalled the tier")
	}
	// And the failing bucket must be absent, not silently half-written.
	var poisoned int64
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", poison).Count(&poisoned)
	if poisoned != 0 {
		t.Errorf("the failing bucket wrote %d rows; its transaction should have rolled back", poisoned)
	}

	// Now let it succeed. The gap must be refilled rather than skipped forever.
	flowSummaryBucketHook = nil
	d.RunFlowSummaryCycle()
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", poison).Count(&poisoned)
	if poisoned == 0 {
		t.Error("the previously-failing bucket was never revisited. Resuming from the newest " +
			"summarised bucket skips past any gap behind it, permanently.")
	}
}

// TestFlowSummary_TierAdvancesPastRowsItDoesNotOwn covers the case the watermark
// fix was actually written for, which no test exercised.
//
// The daily tier detects changes across EVERY tier it sums, so a stream of new
// 5-minute rows for today lands in its dirty list — but it owns only the days
// promotion has begun collapsing, so it writes nothing for them. Keyed on
// "wrote something", its watermark never advanced and its dirty scan re-read an
// ever-larger id range every cycle forever.
func TestFlowSummary_TierAdvancesPastRowsItDoesNotOwn(t *testing.T) {
	d := NewDatabaseForTesting(t)
	oldDay := time.Now().UTC().Add(-45 * 24 * time.Hour).Truncate(24 * time.Hour)

	// Give the daily tier something to own, so it is past the "no source data"
	// branch and genuinely exercising the dirty walk.
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: oldDay, DeviceID: 1, IntervalType: "1d",
		SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: 1000, PacketsSum: 10, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed 1d: %v", err)
	}
	d.RunFlowSummaryCycle()

	maxID := func() int64 {
		var n int64
		d.Gorm().Model(&models.FlowRollup{}).Select("COALESCE(MAX(id),0)").Scan(&n)
		return n
	}
	if got := d.summaryWatermark("1d"); got != maxID() {
		t.Fatalf("daily watermark is %d after the first pass, want %d", got, maxID())
	}

	// Now a stream of rows the daily tier sees but does not own: recent 5m rows,
	// far outside the 1d tier's span.
	recent := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Hour)
	for i := 0; i < 3; i++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: recent.Add(time.Duration(i) * 5 * time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.2", DstAddr: "1.1.1.1", DstPort: 53, Protocol: 17,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed recent 5m: %v", err)
		}
	}
	d.RunFlowSummaryCycle()

	if got := d.summaryWatermark("1d"); got != maxID() {
		t.Errorf("the daily tier's watermark is %d, want %d. It saw rows it does not own and "+
			"wrote nothing; keying the advance on having written something leaves it stuck, and "+
			"its dirty scan then widens every cycle forever.", got, maxID())
	}
}

// TestFlowSummary_LargeDirtyListCompletesInOnePass pins the invariant the whole
// change-detection design now rests on: the dirty walk is never truncated.
//
// Truncating it required a cursor to remember progress, and every attempt to
// make that cursor correct opened a new way to lose data — a bucket re-dirtied
// behind the cursor, a bucket that failed inside a truncated walk, an unpinned
// epoch ceiling. Letting the walk finish removes the mechanism and all three
// bugs with it. If a future change reintroduces a cap here, this fails.
func TestFlowSummary_LargeDirtyListCompletesInOnePass(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Hour)

	seed := func(hour int, bytes uint64, src string) {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: base.Add(time.Duration(hour)*time.Hour + 5*time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: src, DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: bytes, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed hour %d: %v", hour, err)
		}
	}
	const hours = 20
	for h := 0; h < hours; h++ {
		seed(h, 100, "10.0.0.1")
	}
	// Backfill everything first, so the next pass is purely a dirty walk.
	for i := 0; i < 5; i++ {
		d.RunFlowSummaryCycle()
	}

	// Dirty every bucket at once — far more than any per-tier cap would allow.
	for h := 0; h < hours; h++ {
		seed(h, 5000, "10.0.0.9")
	}

	// A tier with a cap that WOULD truncate, to prove the dirty walk ignores it.
	origTiers := flowSummaryTiers
	flowSummaryTiers = []flowSummaryTier{{
		interval:     "1h",
		rangeSources: []string{"5m", "1h"},
		sumSources:   []string{"5m", "1h"},
		width:        time.Hour,
		bucketOf:     func(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) },
		maxPerPass:   2,
	}}
	defer func() { flowSummaryTiers = origTiers }()

	d.RunFlowSummaryCycle() // ONE pass

	for h := 0; h < hours; h++ {
		bucket := base.Add(time.Duration(h) * time.Hour)
		var want, got uint64
		d.Gorm().Model(&models.FlowRollup{}).
			Where("timestamp >= ? AND timestamp < ?", bucket, bucket.Add(time.Hour)).
			Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
		d.Gorm().Model(&models.FlowSummary{}).
			Where("interval_type = ? AND timestamp = ?", "1h", bucket).
			Select("COALESCE(SUM(bytes_sum),0)").Scan(&got)
		if got != want {
			t.Fatalf("after one pass bucket %d holds %d bytes against %d in the source. The dirty "+
				"walk must run to completion; capping it needs a cursor, and every version of that "+
				"cursor lost data.", h, got, want)
		}
	}
}

// --- Invariant guards for the simplified change-detection design -------------
//
// Adversarial review found that three of the four load-bearing invariants below
// survived mutation, i.e. nothing tested them. Removing the dirty cursor deleted
// the tests that had covered two of them as a side effect of covering the
// cursor. These pin the BEHAVIOUR directly, so it survives the next refactor.

func seedSummaryHour(t *testing.T, d *Database, base time.Time, hour int, bytes uint64, src string) {
	t.Helper()
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: base.Add(time.Duration(hour)*time.Hour + 5*time.Minute),
		DeviceID:  1, IntervalType: "5m",
		SrcAddr: src, DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: bytes, PacketsSum: 1, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed hour %d: %v", hour, err)
	}
}

// summaryBucketBytes returns the source and summary byte totals for one hourly
// bucket, which is how every guard below states its failure.
func summaryBucketBytes(d *Database, b time.Time) (want, got uint64) {
	d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", b, b.Add(time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", b).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&got)
	return
}

// TestFlowSummary_DirtyWalkFailureIsRetried covers the ONLY retry path the dirty
// walk has: the watermark being held. FailedBucketIsRetriedNotSkipped exercises
// the backfill's fill-marker retry instead, so before this test, making the
// watermark advance unconditionally passed the whole suite.
func TestFlowSummary_DirtyWalkFailureIsRetried(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 4; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}
	d.RunFlowSummaryCycle()
	if d.summaryWatermark("1h") == 0 {
		t.Fatal("precondition: watermark not set after the first pass")
	}
	for h := 0; h < 4; h++ {
		seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
	}

	poison := base.Add(time.Hour)
	failed := false
	orig := flowSummaryBucketHook
	defer func() { flowSummaryBucketHook = orig }()
	flowSummaryBucketHook = func(iv string, b time.Time) error {
		if !failed && iv == "1h" && b.Equal(poison) {
			failed = true
			return fmt.Errorf("synthetic one-shot failure")
		}
		return nil
	}
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}
	if want, got := summaryBucketBytes(d, poison); got != want {
		t.Errorf("a bucket that failed once in the dirty walk holds %d bytes against %d in the "+
			"source; it was never retried. The watermark must not advance past a walk that did "+
			"not complete.", got, want)
	}
}

// TestFlowSummary_MidPassArrivalIsNotBuried pins why the id ceiling is read
// BEFORE the walk. Rows arriving while a pass runs must belong to the next one;
// reading the ceiling afterwards buries anything that landed in a bucket the
// walk had already passed.
func TestFlowSummary_MidPassArrivalIsNotBuried(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 4; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}
	d.RunFlowSummaryCycle()
	for h := 0; h < 4; h++ {
		seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
	}

	injected := false
	orig := flowSummaryBucketHook
	defer func() { flowSummaryBucketHook = orig }()
	flowSummaryBucketHook = func(iv string, b time.Time) error {
		// While the LAST bucket is being summarised, a replay lands in the FIRST,
		// which the walk has already passed.
		if !injected && iv == "1h" && b.Equal(base.Add(3*time.Hour)) {
			injected = true
			seedSummaryHour(t, d, base, 0, 7777, "10.7.7.7")
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	flowSummaryBucketHook = nil
	d.RunFlowSummaryCycle()

	if want, got := summaryBucketBytes(d, base); got != want {
		t.Errorf("a row that arrived mid-pass into an already-walked bucket left the summary at "+
			"%d bytes against %d in the source. The ceiling must be read before the walk.", got, want)
	}
}

// TestFlowSummary_DirtyWalkIgnoresTheTimeBound pins the other half of "never
// truncated". LargeDirtyListCompletesInOnePass covers the per-tier cap; this
// covers the deadline, which is the path that made a cursor necessary.
func TestFlowSummary_DirtyWalkIgnoresTheTimeBound(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-12 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 6; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}
	d.RunFlowSummaryCycle()
	for h := 0; h < 6; h++ {
		seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
	}

	orig := flowSummaryMaxCycleDuration
	flowSummaryMaxCycleDuration = -time.Hour // already expired
	defer func() { flowSummaryMaxCycleDuration = orig }()
	d.RunFlowSummaryCycle()

	for h := 0; h < 6; h++ {
		bucket := base.Add(time.Duration(h) * time.Hour)
		if want, got := summaryBucketBytes(d, bucket); got != want {
			t.Fatalf("an expired deadline truncated the dirty walk at bucket %d (%d bytes against "+
				"%d). Only the backfill is time-bounded.", h, got, want)
		}
	}
}

// TestFlowSummary_EmptiedSummaryIsRefilled covers the self-heal that a persisted
// fill marker made necessary. MAX(summary timestamp) used to re-backfill on its
// own after a TRUNCATE or a failed migration; a marker does not, so without this
// a cleared table would be a permanent hole.
func TestFlowSummary_EmptiedSummaryIsRefilled(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 4; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}
	d.RunFlowSummaryCycle()
	if d.summaryFillMarker("1h").IsZero() {
		t.Fatal("precondition: no fill marker after the first pass")
	}

	if err := d.Gorm().Where("1 = 1").Delete(&models.FlowSummary{}).Error; err != nil {
		t.Fatalf("empty the summary: %v", err)
	}
	d.RunFlowSummaryCycle()

	var n int64
	d.Gorm().Model(&models.FlowSummary{}).Where("interval_type = ?", "1h").Count(&n)
	if n == 0 {
		t.Error("the summary was emptied under a fill marker and never refilled; the marker " +
			"records progress the table no longer has")
	}
}

// TestFlowSummary_LateDataDuringFirstPassIsNotBuried pins the watermark-zero
// window. Until the first pass sets a watermark the dirty walk does not run at
// all, so a failure during that pass used to leave the watermark at zero — the
// dirty walk stayed disabled while the backfill marched on, and a row replayed
// into an already-filled bucket was neither dirty nor ahead of the fill marker.
// Stale forever.
func TestFlowSummary_LateDataDuringFirstPassIsNotBuried(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-12 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 6; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}

	poison := base.Add(3 * time.Hour)
	failed := false
	orig := flowSummaryBucketHook
	defer func() { flowSummaryBucketHook = orig }()
	flowSummaryBucketHook = func(iv string, b time.Time) error {
		if !failed && iv == "1h" && b.Equal(poison) {
			failed = true
			return fmt.Errorf("synthetic failure on the first pass")
		}
		return nil
	}
	d.RunFlowSummaryCycle() // backfills, one bucket fails

	// A replay into a bucket the first pass already filled.
	seedSummaryHour(t, d, base, 1, 9999, "10.9.9.9")
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}

	if want, got := summaryBucketBytes(d, base.Add(time.Hour)); got != want {
		t.Errorf("a row replayed into an already-filled bucket during the first-pass window left "+
			"the summary at %d bytes against %d in the source.", got, want)
	}
}

// TestFlowSummary_YieldedDayIsRebuiltHourly pins the ownership TRANSITION, which
// production exposed and the steady-state boundary test does not reach.
//
// A day summarised as daily, then handed to the hourly tier (because the finer
// rollup tiers turn out to hold part of it), has to be rebuilt there AND its
// stale daily row removed. Neither happened: the hourly tier's fill marker sat
// weeks ahead so it never backfilled the day it had just acquired, and nothing
// superseded the daily row the yield was meant to replace. The day stayed
// represented only by a midnight-stamped row — exactly what yielding exists to
// avoid, since a window cutoff falling inside that day then drops all of it.
func TestFlowSummary_YieldedDayIsRebuiltHourly(t *testing.T) {
	d := NewDatabaseForTesting(t)
	day := time.Now().UTC().Add(-40 * 24 * time.Hour).Truncate(24 * time.Hour)

	// A fully-promoted day: only the 1d tier holds it, so the daily tier owns it.
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: day, DeviceID: 1, IntervalType: "1d",
		SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: 1000, PacketsSum: 10, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed 1d: %v", err)
	}
	// Recent traffic as well, so the HOURLY tier builds a fill marker far ahead of
	// the old day. Without this the marker is zero and its backfill would start at
	// ownedFrom anyway — which is what made an earlier version of this test pass
	// with the reset removed.
	recent := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 3; h++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: recent.Add(time.Duration(h)*time.Hour + 5*time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.3", DstAddr: "1.1.1.1", DstPort: 53, Protocol: 17,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed recent: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		d.RunFlowSummaryCycle()
	}
	if d.summaryFillMarker("1h").Before(recent) {
		t.Fatalf("precondition: hourly fill marker is %v, expected to be at or past %v",
			d.summaryFillMarker("1h"), recent)
	}
	var dailyRows int64
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1d", day).Count(&dailyRows)
	if dailyRows == 0 {
		t.Fatal("precondition: the day was not summarised as daily")
	}

	// Now the finer tier turns out to hold part of that same day — the shape a
	// real promotion boundary always has. The daily tier must yield it.
	for _, hour := range []int{6, 14} {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(hour) * time.Hour), DeviceID: 1, IntervalType: "1h",
			SrcAddr: "10.0.0.2", DstAddr: "8.8.4.4", DstPort: 443, Protocol: 6,
			BytesSum: 50000, PacketsSum: 500, FlowCount: 9,
		}).Error; err != nil {
			t.Fatalf("seed 1h hour %d: %v", hour, err)
		}
	}
	for i := 0; i < 5; i++ {
		d.RunFlowSummaryCycle()
	}

	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1d", day).Count(&dailyRows)
	if dailyRows != 0 {
		t.Errorf("the yielded day still has %d daily summary row(s); the hourly tier now holds it "+
			"and leaving both double-counts on read", dailyRows)
	}

	var hourlyRows int64
	d.Gorm().Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", day, day.Add(24*time.Hour)).
		Count(&hourlyRows)
	if hourlyRows == 0 {
		t.Error("the yielded day was never rebuilt at hourly resolution; the fill marker sits ahead " +
			"of the newly acquired span and must be reset when ownership moves down")
	}

	// And the day's traffic must all still be there.
	var want, got uint64
	d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", day, day.Add(24*time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
	d.Gorm().Model(&models.FlowSummary{}).
		Where("timestamp >= ? AND timestamp < ?", day, day.Add(24*time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&got)
	if got != want {
		t.Errorf("after the yield the day holds %d bytes in the summary against %d in the source",
			got, want)
	}
	if want != 101000 {
		t.Fatalf("the day's seed total is %d, expected 101000; the test is not measuring what it claims", want)
	}
}
