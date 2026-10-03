package database

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// Regressions for the flow summary's retention and ownership handling
// (v0.11.282). Each test here fails with its fix reverted:
//
//   - TestCleanupOldData_FlowSummaryKeptForeverAtZero: the `days <= 0` guard in
//     CleanupOldData's generic loop.
//   - TestFlowSummary_RetentionShorterThanRollupsDoesNotRewalk: the retention
//     clamp on ownedFrom (summaryRetentionFloor) and the read path's coverage
//     check (summaryCoversCutoff).
//   - TestFlowSummary_EmptyBucketsDoNotCountTowardTheCap: counting only WRITTEN
//     buckets against maxPerPass.
//   - TestFlowSummary_LateRowBelowTheFloorDoesNotResetTheMarker: walking only
//     the acquired span instead of resetting the fill marker.
//   - TestFlowSummary_PromotionDuringTheCycleIsNotDoubleCounted: deriving the
//     hourly floor inside the hourly pass.

func setFlowSummaryRetention(t *testing.T, d *Database, value string) {
	t.Helper()
	if err := d.UpsertSetting(&models.SystemSetting{
		Key: FlowSummaryRetentionKey, Value: value, Category: "retention", Type: "number",
	}); err != nil {
		t.Fatalf("set %s=%q: %v", FlowSummaryRetentionKey, value, err)
	}
}

func seedDailyRollup(t *testing.T, d *Database, day time.Time, bytes uint64) {
	t.Helper()
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: day, DeviceID: 1, IntervalType: "1d",
		SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: bytes, PacketsSum: 10, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed 1d %s: %v", day.Format(time.RFC3339), err)
	}
}

func seedRecentRollups(t *testing.T, d *Database) (recent time.Time) {
	t.Helper()
	recent = time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Hour)
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
	return recent
}

func cyclesUntilComplete(t *testing.T, d *Database, limit int) {
	t.Helper()
	for i := 0; i < limit; i++ {
		d.RunFlowSummaryCycle()
		if d.summaryBackfillComplete() {
			return
		}
	}
	t.Fatalf("summary backfill not complete after %d cycles", limit)
}

func summaryBytesBetween(d *Database, interval string, from, to time.Time) uint64 {
	var n uint64
	q := d.Gorm().Model(&models.FlowSummary{}).Where("timestamp >= ? AND timestamp < ?", from, to)
	if interval != "" {
		q = q.Where("interval_type = ?", interval)
	}
	q.Select("COALESCE(SUM(bytes_sum),0)").Scan(&n)
	return n
}

func rollupBytesBetween(d *Database, from, to time.Time) uint64 {
	var n uint64
	d.Gorm().Model(&models.FlowRollup{}).Where("timestamp >= ? AND timestamp < ?", from, to).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&n)
	return n
}

// TestCleanupOldData_FlowSummaryKeptForeverAtZero: flow_summary_retention_days
// = 0 is documented (and validated by the settings handler) as "keep forever".
// The generic cleanup loop computed a cutoff of now-0d from it and deleted the
// entire summary every night.
func TestCleanupOldData_FlowSummaryKeptForeverAtZero(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seed := func() {
		for _, m := range []interface{}{
			&models.FlowSummary{Timestamp: time.Now().AddDate(0, 0, -400), IntervalType: "1d", DeviceID: 1, BytesSum: 1, FlowCount: 1},
			&models.FlowSummaryTop{Timestamp: time.Now().AddDate(0, 0, -400), IntervalType: "1d", DeviceID: 1, Dimension: flowSummaryDimSrcAddr, Value: "10.0.0.1", BytesSum: 1, FlowCount: 1},
			&models.FlowSummaryBucket{Timestamp: time.Now().AddDate(0, 0, -400), IntervalType: "1d", DeviceID: 1, DistinctSrc: 1, DistinctDst: 1},
		} {
			if err := d.Gorm().Create(m).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	count := func(name string, m interface{}) int64 {
		t.Helper()
		var n int64
		if err := d.Gorm().Model(m).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		return n
	}
	ret := config.RetentionConfig{DefaultDays: 90, FlowRollupDays: 365}

	setFlowSummaryRetention(t, d, "0")
	seed()
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	for name, m := range map[string]interface{}{
		"flow_summaries": &models.FlowSummary{}, "flow_summary_tops": &models.FlowSummaryTop{}, "flow_summary_buckets": &models.FlowSummaryBucket{},
	} {
		if n := count(name, m); n != 1 {
			t.Errorf("%s rows after cleanup with retention 0 = %d, want 1: 0 means keep forever, "+
				"not a cutoff of now", name, n)
		}
	}

	// And the window still prunes when it is set: this is what proves the
	// setting is being read at all.
	setFlowSummaryRetention(t, d, "30")
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n := count("flow_summaries", &models.FlowSummary{}); n != 0 {
		t.Errorf("flow_summaries rows after cleanup with retention 30 = %d, want 0", n)
	}
}

// TestFlowSummary_RetentionShorterThanRollupsDoesNotRewalk: the settings
// handler allows a summary window shorter than the rollups'. The summariser
// used to build every day the rollups held, cleanup pruned the summary back to
// its window, and the next pass saw a tier that had "acquired" every pruned
// day, reset its fill marker and rebuilt all of it (~15 h on production) with
// the read path off — every single night.
func TestFlowSummary_RetentionShorterThanRollupsDoesNotRewalk(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// 45 days, not 30: the live path reads the 1d rollup tier only for windows
	// wider than its promotion age (30 days), and the comparison below needs a
	// window inside the retention that both paths answer from the same rows.
	setFlowSummaryRetention(t, d, "45")
	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	for days := 90; days >= 3; days-- {
		seedDailyRollup(t, d, today.AddDate(0, 0, -days), 1000)
	}
	seedRecentRollups(t, d)
	retained := now.AddDate(0, 0, -45)

	cyclesUntilComplete(t, d, 80)
	oldestBuilt := func() time.Time {
		ts, ok, err := aggregateTimestamp(d.Gorm().Model(&models.FlowSummary{}), "MIN(timestamp)")
		if err != nil || !ok {
			t.Fatalf("oldest summary bucket: ok=%v err=%v", ok, err)
		}
		return ts
	}
	if got := oldestBuilt(); got.Before(retained) {
		t.Fatalf("the summariser built a bucket at %s, below the 45-day retention cutoff %s; "+
			"it must not build what cleanup is about to delete", got.Format(time.RFC3339), retained.Format(time.RFC3339))
	}

	ret := config.RetentionConfig{DefaultDays: 90, FlowRollupDays: 365}
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	markerBefore := d.summaryFillMarker("1d")
	if markerBefore.IsZero() {
		t.Fatal("precondition: the daily tier has no fill marker")
	}
	for i := 0; i < 3; i++ {
		d.RunFlowSummaryCycle()
		if m := d.summaryFillMarker("1d"); m.Before(markerBefore) {
			t.Fatalf("cycle %d after cleanup: the daily fill marker dropped from %s to %s; the summary "+
				"was pruned to its own window, nothing new was acquired", i+1, markerBefore.Format(time.RFC3339), m.Format(time.RFC3339))
		}
		if !d.summaryBackfillComplete() {
			t.Fatalf("cycle %d after cleanup: the read path switched off", i+1)
		}
		if got := oldestBuilt(); got.Before(retained) {
			t.Fatalf("cycle %d after cleanup: a bucket at %s was rebuilt below the retention cutoff", i+1, got.Format(time.RFC3339))
		}
	}

	// A window the summary does not reach must be served by the live path, and
	// agree with it. A window inside the retention is served from the summary.
	for _, hours := range []int{40 * 24, 90 * 24} {
		summary, live := statsBothWays(t, d, hours, FlowStatsFilter{})
		if summary.TotalBytes != live.TotalBytes {
			t.Errorf("%dh window: TotalBytes %d via summary, %d via live; the summary holds only the "+
				"retention window and must not answer a wider request", hours, summary.TotalBytes, live.TotalBytes)
		}
	}
	if !d.summaryCoversCutoff(now.AddDate(0, 0, -40)) {
		t.Error("a 40-day window inside a 45-day retention is reported uncovered")
	}
	if d.summaryCoversCutoff(now.AddDate(0, 0, -90)) {
		t.Error("a 90-day window on a 45-day retention is reported covered")
	}
}

// TestFlowSummary_EmptyBucketsDoNotCountTowardTheCap: the daily tier's cap of
// two buckets per cycle counted buckets VISITED, so a quiet stretch of days
// (one existence probe each) was crawled at the same pace as the expensive
// ones.
func TestFlowSummary_EmptyBucketsDoNotCountTowardTheCap(t *testing.T) {
	d := NewDatabaseForTesting(t)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	seedDailyRollup(t, d, today.AddDate(0, 0, -10), 1000)
	seedDailyRollup(t, d, today.AddDate(0, 0, -3), 2000)

	d.RunFlowSummaryCycle()

	if got, want := d.summaryFillMarker("1d"), today.AddDate(0, 0, -3); !got.Equal(want) {
		t.Errorf("daily fill marker after one cycle = %s, want %s: six empty days between the two "+
			"real ones were counted against the per-cycle cap", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	if !d.summaryBackfillComplete() {
		t.Error("two real days did not backfill in a single cycle")
	}
}

// TestFlowSummary_LateRowBelowTheFloorDoesNotResetTheMarker: a replayed row
// stamped inside a day the daily tier owns pulls the hourly floor down to that
// day. The hourly tier then owns buckets older than anything it has built; it
// used to reset its fill marker and rebuild every owned hour from there, with
// the read path off. Only the newly acquired span needs walking.
func TestFlowSummary_LateRowBelowTheFloorDoesNotResetTheMarker(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t.Cleanup(func() { flowSummaryBucketHook = nil })
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for days := 12; days >= 3; days-- {
		seedDailyRollup(t, d, today.AddDate(0, 0, -days), 1000)
	}
	recent := seedRecentRollups(t, d)
	cyclesUntilComplete(t, d, 20)
	markerBefore := d.summaryFillMarker("1h")
	if markerBefore.Before(recent) {
		t.Fatalf("precondition: hourly fill marker %s is below the recent data at %s", markerBefore, recent)
	}

	// Late data into a daily-owned day.
	lateDay := today.AddDate(0, 0, -8)
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: lateDay.Add(14*time.Hour + 5*time.Minute), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.0.0.9", DstAddr: "9.9.9.9", DstPort: 443, Protocol: 6,
		BytesSum: 777, PacketsSum: 7, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed late row: %v", err)
	}
	// One bucket of the acquired day fails once, so a walk that RESTARTED from
	// the day's midnight could not reach the old marker in this cycle and would
	// persist a lower one.
	failed := false
	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval == "1h" && b.Equal(lateDay.Add(time.Hour)) && !failed {
			failed = true
			return errors.New("synthetic one-shot failure")
		}
		return nil
	}
	d.RunFlowSummaryCycle()

	if m := d.summaryFillMarker("1h"); m.Before(markerBefore) {
		t.Errorf("the hourly fill marker dropped from %s to %s on acquiring one day below the floor; "+
			"only the acquired span needs backfilling", markerBefore.Format(time.RFC3339), m.Format(time.RFC3339))
	}
	if !d.summaryBackfillComplete() {
		t.Error("the read path switched off while one acquired day was backfilled")
	}

	flowSummaryBucketHook = nil
	for i := 0; i < 3; i++ {
		d.RunFlowSummaryCycle()
	}
	// The acquired day is complete at hourly resolution, including the 1d row
	// stamped at its midnight, and its stale daily row is gone.
	dayEnd := lateDay.Add(24 * time.Hour)
	if got, want := summaryBytesBetween(d, "", lateDay, dayEnd), rollupBytesBetween(d, lateDay, dayEnd); got != want {
		t.Errorf("acquired day holds %d bytes in the summary against %d in the source", got, want)
	}
	if n := summaryBytesBetween(d, "1d", lateDay, dayEnd); n != 0 {
		t.Errorf("the acquired day still has a daily summary row (%d bytes) beside its hourly rows", n)
	}
	// Every day of the acquired range is held by exactly one tier and adds up.
	for day := lateDay; day.Before(today.AddDate(0, 0, -2)); day = day.AddDate(0, 0, 1) {
		if got, want := summaryBytesBetween(d, "", day, day.AddDate(0, 0, 1)), rollupBytesBetween(d, day, day.AddDate(0, 0, 1)); got != want {
			t.Errorf("day %s holds %d bytes in the summary against %d in the source", day.Format("2006-01-02"), got, want)
		}
	}
	// And the whole history still adds up.
	if got, want := summaryBytesBetween(d, "", lateDay.AddDate(0, 0, -10), today.AddDate(0, 0, -2)), rollupBytesBetween(d, lateDay.AddDate(0, 0, -10), today.AddDate(0, 0, -2)); got != want {
		t.Errorf("history holds %d bytes in the summary against %d in the source", got, want)
	}
	if !d.summaryBackfillComplete() {
		t.Error("the read path is off after the acquired day was backfilled")
	}
}

// TestFlowSummary_PromotionDuringTheCycleIsNotDoubleCounted: the summariser
// and the rollup ladder hold different advisory locks, so a 1h→1d promotion
// can commit while a cycle runs. With the hourly floor probed once at the start
// of the cycle, a day promoted during the daily pass was still "owned" by the
// hourly pass, whose dirty walk then put the new 1d row — the whole day — into
// the day's midnight bucket beside the hourly buckets already holding it.
func TestFlowSummary_PromotionDuringTheCycleIsNotDoubleCounted(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t.Cleanup(func() { flowSummaryBucketHook = nil })
	today := time.Now().UTC().Truncate(24 * time.Hour)
	promoted := today.AddDate(0, 0, -4) // fully promoted already
	boundary := today.AddDate(0, 0, -3) // still at hourly resolution
	seedDailyRollup(t, d, promoted, 1000)
	var dayBytes uint64
	for _, h := range []int{3, 9, 15} {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: boundary.Add(time.Duration(h) * time.Hour), DeviceID: 1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 500, PacketsSum: 5, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed 1h: %v", err)
		}
		dayBytes += 500
	}
	seedRecentRollups(t, d)
	cyclesUntilComplete(t, d, 20)
	if got := summaryBytesBetween(d, "1h", boundary, boundary.Add(24*time.Hour)); got != dayBytes {
		t.Fatalf("precondition: the boundary day holds %d bytes at hourly resolution, want %d", got, dayBytes)
	}

	// Late data into the promoted day makes the daily pass run a bucket this
	// cycle; the ladder "commits" the boundary day's promotion from inside it,
	// i.e. after the cycle started and before the hourly pass runs.
	seedDailyRollup(t, d, promoted, 10)
	promotedOnce := false
	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval != "1d" || promotedOnce {
			return nil
		}
		promotedOnce = true
		seedDailyRollup(t, d, boundary, dayBytes)
		return d.Gorm().Where("interval_type = ? AND timestamp >= ? AND timestamp < ?",
			"1h", boundary, boundary.Add(24*time.Hour)).Delete(&models.FlowRollup{}).Error
	}
	d.RunFlowSummaryCycle()
	if !promotedOnce {
		t.Fatal("precondition: the promotion was not injected during the daily pass")
	}
	for i := 1; i <= 3; i++ {
		got, want := summaryBytesBetween(d, "", boundary, boundary.Add(24*time.Hour)), rollupBytesBetween(d, boundary, boundary.Add(24*time.Hour))
		if got != want {
			t.Errorf("cycle %d: the promoted day holds %d bytes in the summary against %d in the source; "+
				"a floor probed before the promotion let the hourly tier add the 1d row beside its own rows", i, got, want)
		}
		d.RunFlowSummaryCycle()
	}
}

// runTwoLateDaysScenario is the reviewer's reproduction of the hole the
// MIN(timestamp) resume point left: late 5m rows land in TWO fully promoted
// days in one cycle. The hourly floor drops to the older day; the dirty walk
// writes the two late buckets, each of which supersedes its day's daily row;
// a span resumed from MIN(summary timestamp) then started at the older late
// bucket and never rebuilt the newer day's midnight bucket — its whole 1d
// row — above the new minimum and below the fill marker, with the read path
// on. Shared by the SQLite test and the PostgreSQL integration test.
func runTwoLateDaysScenario(t *testing.T, d *Database) {
	t.Helper()
	origDur := flowSummaryMaxCycleDuration
	t.Cleanup(func() { flowSummaryMaxCycleDuration = origDur })
	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	for days := 60; days >= 3; days-- {
		seedDailyRollup(t, d, today.AddDate(0, 0, -days), 1000)
	}
	seedRecentRollups(t, d)
	cyclesUntilComplete(t, d, 60)
	window := 38 * 24
	if s, l := statsBothWays(t, d, window, FlowStatsFilter{}); s.TotalBytes != l.TotalBytes {
		t.Fatalf("precondition: summary %d vs live %d", s.TotalBytes, l.TotalBytes)
	}

	dayA, dayB := today.AddDate(0, 0, -35), today.AddDate(0, 0, -33)
	for _, late := range []time.Time{dayA.Add(14*time.Hour + 5*time.Minute), dayB.Add(10*time.Hour + 5*time.Minute)} {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: late, DeviceID: 1, IntervalType: "5m",
			SrcAddr: "10.0.0.9", DstAddr: "9.9.9.9", DstPort: 443, Protocol: 6,
			BytesSum: 7, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed late row: %v", err)
		}
	}
	dayTotals := func(label string) {
		t.Helper()
		for _, day := range []time.Time{dayA, dayB} {
			got, want := summaryBytesBetween(d, "", day, day.AddDate(0, 0, 1)), rollupBytesBetween(d, day, day.AddDate(0, 0, 1))
			if got != want {
				t.Errorf("%s: day %s holds %d bytes in the summary against %d in the source", label, day.Format("2006-01-02"), got, want)
			}
		}
	}
	// A cycle with no time for the backfill walks: the dirty walk still writes
	// the two late buckets (and supersedes their days' daily rows), so the
	// acquired span is now half-built and the read path must know it.
	flowSummaryMaxCycleDuration = 0
	d.RunFlowSummaryCycle()
	if !d.summaryBackfillComplete() {
		t.Error("cycle 1: the top of the summary is intact; summaryBackfillComplete must stay true")
	}
	cutoff := now.Add(-time.Duration(window) * time.Hour)
	if d.summaryCoversCutoff(cutoff) {
		t.Errorf("cycle 1: a %dh window is reported covered while the hourly tier's acquired span is unwalked", window)
	}
	if s, l := statsBothWays(t, d, window, FlowStatsFilter{}); s.TotalBytes != l.TotalBytes {
		t.Errorf("cycle 1: %dh window: %d via summary, %d via live; the read path served a half-built span", window, s.TotalBytes, l.TotalBytes)
	}

	flowSummaryMaxCycleDuration = origDur
	for i := 2; i <= 6; i++ {
		d.RunFlowSummaryCycle()
		if d.summaryCoversCutoff(cutoff) {
			dayTotals(fmt.Sprintf("cycle %d", i))
			if s, l := statsBothWays(t, d, window, FlowStatsFilter{}); s.TotalBytes != l.TotalBytes {
				t.Errorf("cycle %d: %dh window: %d via summary, %d via live", i, window, s.TotalBytes, l.TotalBytes)
			}
		}
	}
	if !d.summaryBackfillComplete() || !d.summaryCoversCutoff(cutoff) {
		t.Fatalf("after 6 cycles the %dh window is still not served from the summary (complete=%v covered=%v)",
			window, d.summaryBackfillComplete(), d.summaryCoversCutoff(cutoff))
	}
	dayTotals("final")
	if n := summaryBytesBetween(d, "1h", dayB, dayB.Add(time.Hour)); n != 1000 {
		t.Errorf("day B's midnight hourly bucket holds %d bytes, want its 1d row's 1000", n)
	}
	for _, day := range []time.Time{dayA, dayB} {
		if n := summaryBytesBetween(d, "1d", day, day.AddDate(0, 0, 1)); n != 0 {
			t.Errorf("day %s still has a daily summary row beside its hourly rows", day.Format("2006-01-02"))
		}
	}
}

func TestFlowSummary_TwoLateDaysBelowTheFloorAreRebuilt(t *testing.T) {
	runTwoLateDaysScenario(t, NewDatabaseForTesting(t))
}

// TestFlowSummary_SpanWalkContinuesPastAFailedBucket: a bucket that fails
// permanently inside an acquired span holds the low marker (so it is retried
// and the span stays flagged) but must not wall off everything older.
func TestFlowSummary_SpanWalkContinuesPastAFailedBucket(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t.Cleanup(func() { flowSummaryBucketHook = nil })
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for days := 12; days >= 3; days-- {
		seedDailyRollup(t, d, today.AddDate(0, 0, -days), 1000)
	}
	seedRecentRollups(t, d)
	cyclesUntilComplete(t, d, 20)

	lateDay := today.AddDate(0, 0, -8)
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: lateDay.Add(14*time.Hour + 5*time.Minute), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.0.0.9", DstAddr: "9.9.9.9", DstPort: 443, Protocol: 6,
		BytesSum: 777, PacketsSum: 7, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed late row: %v", err)
	}
	poison := lateDay.Add(5 * time.Hour)
	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval == "1h" && b.Equal(poison) {
			return errors.New("synthetic permanent failure")
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	if n := summaryBytesBetween(d, "1h", lateDay, lateDay.Add(time.Hour)); n != 1000 {
		t.Errorf("the acquired day's midnight bucket holds %d bytes, want 1000; a failing bucket above it stopped the span walk", n)
	}
	if from := d.summaryFillFromMarker("1h"); !from.After(poison) {
		t.Errorf("low marker is %s; it must stay above the failing bucket %s so the bucket is retried", from, poison)
	}
	if !d.summaryAcquiring("1h") {
		t.Error("the span is still open at the failing bucket but the tier is not flagged as acquiring")
	}
	if d.summaryCoversCutoff(time.Now().UTC().AddDate(0, 0, -10)) {
		t.Error("a window reaching into the open span is reported covered")
	}
}
