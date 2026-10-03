package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// Regressions for the flow summary's retention and ownership handling
// (v0.11.284). Each test here fails with its fix reverted:
//
//   - TestCleanupOldData_FlowSummaryKeptForeverAtZero: the `days <= 0` guard in
//     CleanupOldData's generic loop.
//   - TestFlowSummary_RetentionShorterThanRollupsDoesNotRewalk: the retention
//     clamp on ownedFrom (summaryRetentionFloor) and the read path's retention
//     gate (summaryRetentionCovers).
//   - TestFlowSummary_EmptyBucketsDoNotCountTowardTheCap: counting only WRITTEN
//     buckets against maxPerPass.
//   - TestFlowSummary_PromotionDuringTheCycleIsNotDoubleCounted: deriving the
//     hourly floor inside the hourly pass, in one snapshot.
//   - The late-data scenarios (TestFlowSummary_TwoLateDays..., ..._LateRowInThe
//     FloorBucket..., ..._LateDailyRowOlderThanHistory...) pin the invariant
//     that whenever the read path is on, the summary agrees with the live
//     path — at hook time mid-pass, after a crash mid-pass, and across cycles.

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
	if !d.summaryRetentionCovers(40 * 24) {
		t.Error("a 40-day window inside a 45-day retention is reported uncovered")
	}
	if !d.summaryRetentionCovers(45 * 24) {
		t.Error("a 45-day window on a 45-day retention is reported uncovered")
	}
	if d.summaryRetentionCovers(90 * 24) {
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

// assertSummaryAgrees pins the invariant every late-data scenario below is
// about: whenever the read path is ON (the backfill is complete and the window
// is inside the retention), the summary answers exactly what the live path
// answers, for every window. When the read path is off nothing is asserted —
// a slow right answer is the design's fallback.
func assertSummaryAgrees(t *testing.T, d *Database, label string, windows ...int) {
	t.Helper()
	if !d.summaryBackfillComplete() {
		return
	}
	for _, hours := range windows {
		if !d.summaryRetentionCovers(hours) {
			continue
		}
		s, l := statsBothWays(t, d, hours, FlowStatsFilter{})
		if s.TotalBytes != l.TotalBytes || s.TotalFlows != l.TotalFlows {
			t.Errorf("%s: %dh window: %d bytes / %d flows via summary, %d / %d via live, with the read path on",
				label, hours, s.TotalBytes, s.TotalFlows, l.TotalBytes, l.TotalFlows)
		}
	}
}

// Windows wider than the 1h→1d promotion age (30 days): below it the live
// path does not read the 1d tier at all, and this seed is 1d rows only.
// 33 days puts the cutoff inside day B, so both paths truncate mid-day.
var lateScenarioWindows = []int{33 * 24, 38 * 24, 59 * 24}

// seedPromotedHistory lays down 58 fully promoted days and a few recent hours,
// and builds the summary over them.
func seedPromotedHistory(t *testing.T, d *Database) (today time.Time) {
	t.Helper()
	today = time.Now().UTC().Truncate(24 * time.Hour)
	for days := 60; days >= 3; days-- {
		seedDailyRollup(t, d, today.AddDate(0, 0, -days), 1000)
	}
	seedRecentRollups(t, d)
	cyclesUntilComplete(t, d, 60)
	assertSummaryAgrees(t, d, "precondition", lateScenarioWindows...)
	return today
}

func seedLate5m(t *testing.T, d *Database, at time.Time) {
	t.Helper()
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: at, DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.0.0.9", DstAddr: "9.9.9.9", DstPort: 443, Protocol: 6,
		BytesSum: 7, PacketsSum: 1, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed late row at %s: %v", at.Format(time.RFC3339), err)
	}
}

// runTwoLateDaysScenario: late 5m rows land in TWO fully promoted days in one
// cycle. The hourly floor drops to the older day; the dirty walk writes the
// two late buckets, each of which supersedes its day's daily row. The tier
// must have reset its fill marker ON DISK before that first write, so that at
// no point — mid-pass, after a crash, or across cycles — does a reader with
// the read path on see the newer day without its midnight bucket (its whole
// 1d row). Shared by the SQLite test and the PostgreSQL integration test.
func runTwoLateDaysScenario(t *testing.T, d *Database) {
	t.Helper()
	t.Cleanup(func() { flowSummaryBucketHook = nil })
	today := seedPromotedHistory(t, d)
	dayA, dayB := today.AddDate(0, 0, -35), today.AddDate(0, 0, -33)
	seedLate5m(t, d, dayA.Add(14*time.Hour+5*time.Minute))
	seedLate5m(t, d, dayB.Add(10*time.Hour+5*time.Minute))

	// Mid-pass: at the first dirty write the marker must already be reset on
	// disk; at the second, day A's daily row is gone and the read path must be
	// off (or agree, which it cannot).
	visited := 0
	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval != "1h" {
			return nil
		}
		if b.Equal(dayA.Add(14*time.Hour)) || b.Equal(dayB.Add(10*time.Hour)) {
			visited++
			if d.summaryBackfillComplete() {
				t.Errorf("hook at %s: the read path is still on while the pass writes into the acquired span", b.Format(time.RFC3339))
			}
			assertSummaryAgrees(t, d, "hook at "+b.Format(time.RFC3339), lateScenarioWindows...)
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	if visited < 2 {
		t.Fatalf("precondition: the pass visited the two late buckets %d time(s)", visited)
	}
	flowSummaryBucketHook = nil
	assertSummaryAgrees(t, d, "cycle 1", lateScenarioWindows...)
	for i := 2; i <= 8; i++ {
		d.RunFlowSummaryCycle()
		assertSummaryAgrees(t, d, fmt.Sprintf("cycle %d", i), lateScenarioWindows...)
	}
	if !d.summaryBackfillComplete() {
		t.Fatal("after 8 cycles the summary is still not complete")
	}
	for _, day := range []time.Time{dayA, dayB} {
		if got, want := summaryBytesBetween(d, "", day, day.AddDate(0, 0, 1)), rollupBytesBetween(d, day, day.AddDate(0, 0, 1)); got != want {
			t.Errorf("day %s holds %d bytes in the summary against %d in the source", day.Format("2006-01-02"), got, want)
		}
		if n := summaryBytesBetween(d, "1d", day, day.AddDate(0, 0, 1)); n != 0 {
			t.Errorf("day %s still has a daily summary row beside its hourly rows", day.Format("2006-01-02"))
		}
	}
}

func TestFlowSummary_TwoLateDaysBelowTheFloorAreRebuilt(t *testing.T) {
	runTwoLateDaysScenario(t, NewDatabaseForTesting(t))
}

// TestFlowSummary_TwoLateDaysCrashMidDirtyWalk: the pass dies after its first
// write into the acquired span and before any end-of-pass bookkeeping. The
// reset persisted before that write keeps the read path off until a later
// pass has rebuilt the range.
func TestFlowSummary_TwoLateDaysCrashMidDirtyWalk(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t.Cleanup(func() { flowSummaryBucketHook = nil })
	today := seedPromotedHistory(t, d)
	dayA, dayB := today.AddDate(0, 0, -35), today.AddDate(0, 0, -33)
	seedLate5m(t, d, dayA.Add(14*time.Hour+5*time.Minute))
	seedLate5m(t, d, dayB.Add(10*time.Hour+5*time.Minute))

	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval == "1h" && b.Equal(dayB.Add(10*time.Hour)) {
			panic("synthetic crash after the first write into the acquired span")
		}
		return nil
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("precondition: the injected crash did not fire")
			}
		}()
		d.RunFlowSummaryCycle()
	}()
	flowSummaryBucketHook = nil
	if n := summaryBytesBetween(d, "1d", dayA, dayA.AddDate(0, 0, 1)); n != 0 {
		t.Fatalf("precondition: day A's daily row (%d bytes) was not superseded by the crashed pass", n)
	}
	if d.summaryBackfillComplete() {
		t.Error("after a crash mid-pass the read path is on over a half-rebuilt range")
	}
	assertSummaryAgrees(t, d, "after the crash", lateScenarioWindows...)
	for i := 1; i <= 8; i++ {
		d.RunFlowSummaryCycle()
		assertSummaryAgrees(t, d, fmt.Sprintf("recovery cycle %d", i), lateScenarioWindows...)
	}
	if !d.summaryBackfillComplete() {
		t.Fatal("the summary did not complete after the crash")
	}
	assertSummaryAgrees(t, d, "recovered", lateScenarioWindows...)
}

// TestFlowSummary_LateRowInTheFloorBucketPlusAnotherDay: the older late row
// lands in the very bucket the tier's range now starts at, so after the dirty
// walk the summary's oldest bucket EQUALS ownedFrom and an oldest-bucket probe
// taken after it sees no ownership drop at all — while the other late day's
// daily row is gone and its midnight bucket unbuilt. The drop has to be
// decided before the dirty walk.
func TestFlowSummary_LateRowInTheFloorBucketPlusAnotherDay(t *testing.T) {
	d := NewDatabaseForTesting(t)
	today := seedPromotedHistory(t, d)
	dayA, dayB := today.AddDate(0, 0, -35), today.AddDate(0, 0, -33)
	seedLate5m(t, d, dayA.Add(5*time.Minute))
	seedLate5m(t, d, dayB.Add(10*time.Hour+5*time.Minute))
	for i := 1; i <= 8; i++ {
		d.RunFlowSummaryCycle()
		assertSummaryAgrees(t, d, fmt.Sprintf("cycle %d", i), lateScenarioWindows...)
	}
	if !d.summaryBackfillComplete() {
		t.Fatal("after 8 cycles the summary is still not complete")
	}
	if got, want := summaryBytesBetween(d, "", dayB, dayB.AddDate(0, 0, 1)), rollupBytesBetween(d, dayB, dayB.AddDate(0, 0, 1)); got != want {
		t.Errorf("day B holds %d bytes in the summary against %d in the source", got, want)
	}
}

// TestFlowSummary_LateDailyRowOlderThanHistoryNeedsNoRewalk: a late 1d row
// older than every other moves the daily tier's range down by one day, but
// that day's rows are all new — the dirty walk builds it, nothing else is
// affected, and a full re-walk of 58 days (with the read path off for all of
// it) would be pure cost. The invariant holds throughout either way.
func TestFlowSummary_LateDailyRowOlderThanHistoryNeedsNoRewalk(t *testing.T) {
	d := NewDatabaseForTesting(t)
	today := seedPromotedHistory(t, d)
	marker := d.summaryFillMarker("1d")
	seedDailyRollup(t, d, today.AddDate(0, 0, -61), 500)
	d.RunFlowSummaryCycle()
	assertSummaryAgrees(t, d, "cycle 1", append(lateScenarioWindows, 62*24)...)
	if got := d.summaryFillMarker("1d"); got.Before(marker) {
		t.Errorf("daily fill marker dropped from %s to %s for a day the dirty walk built on its own", marker.Format(time.RFC3339), got.Format(time.RFC3339))
	}
	if !d.summaryBackfillComplete() {
		t.Error("the read path went off for a late 1d row the dirty walk built on its own")
	}
	if n := summaryBytesBetween(d, "1d", today.AddDate(0, 0, -61), today.AddDate(0, 0, -60)); n != 500 {
		t.Errorf("the late day holds %d bytes in the summary, want 500", n)
	}
	d.RunFlowSummaryCycle()
	assertSummaryAgrees(t, d, "cycle 2", append(lateScenarioWindows, 62*24)...)
}
