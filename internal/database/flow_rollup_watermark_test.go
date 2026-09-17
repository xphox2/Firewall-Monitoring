package database

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

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

// TestAggregateRollupsUp_EmitsEachBucketOnce pins the fix for duplicate-key
// inflation in the rollup ladder.
//
// walkAggregationWindows clamps its final window at the cutoff, so an
// un-truncated cutoff SPLITS the destination bucket it lands in: the slice below
// the cutoff promotes now, the rest on a later cycle, each writing a separate row
// with an identical group key. With a 5-minute ticker that recurs every cycle
// forever. Measured on production for one day of the 1h tier: 2,416,851 rows for
// 2,085,373 distinct keys, a multiplicity of 1.159 — roughly 16% of the table.
//
// Promotion now truncates its cutoff to the destination bucket width, so a
// straddled bucket waits for the next cycle rather than being split.
func TestAggregateRollupsUp_EmitsEachBucketOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// One hour's worth of 5m rows, all sharing a group key so any split shows up
	// as two rows where there should be one.
	hour := time.Now().Add(-50 * time.Hour).UTC().Truncate(time.Hour)
	for m := 0; m < 60; m += 5 {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: hour.Add(time.Duration(m) * time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed +%dm: %v", m, err)
		}
	}

	// Promote with a cutoff deliberately landing MID-HOUR, which is what a
	// wall-clock cutoff does on almost every real cycle.
	d.aggregateRollupsUp("5m", "1h", hour.Add(32*time.Minute))
	// And again with the cutoff past the hour, as a later cycle would.
	d.aggregateRollupsUp("5m", "1h", hour.Add(3*time.Hour))

	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "1h").Find(&rows).Error; err != nil {
		t.Fatalf("read 1h tier: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("the hour produced %d rows in the 1h tier, want 1. A cutoff landing mid-bucket "+
			"must defer that bucket, not split it into one row per promotion pass.", len(rows))
	}

	// And nothing may be lost or double-counted by the deferral.
	var total uint64
	for _, r := range rows {
		total += r.BytesSum
	}
	var remaining uint64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "5m").
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&remaining)
	if total+remaining != 1200 {
		t.Errorf("promoted %d bytes plus %d still in the 5m tier = %d, want 1200 seeded",
			total, remaining, total+remaining)
	}
}

// TestAggregateFlowsToRollup_EmitsEach5mBucketOnce is the raw→5m sibling of
// TestAggregateRollupsUp_EmitsEachBucketOnce. Every promotion step truncates, so
// every promotion step needs the guard; this is the one that runs most often.
func TestAggregateFlowsToRollup_EmitsEach5mBucketOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// One 5-minute bucket's worth of samples, one per minute, all sharing a
	// group key so a split shows up as two rows where there should be one.
	bucket := time.Now().Add(-3 * time.Hour).UTC().Truncate(5 * time.Minute)
	for m := 0; m < 5; m++ {
		seedFlow(t, d, bucket.Add(time.Duration(m)*time.Minute), 443, 100)
	}

	// A cutoff landing mid-bucket — what a wall-clock cutoff does on most cycles.
	d.aggregateFlowsToRollup(bucket.Add(3*time.Minute), "5m")
	var early int64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "5m").Count(&early)
	if early != 0 {
		t.Errorf("a cutoff inside the bucket produced %d 5m rows, want 0 — the bucket "+
			"must be deferred whole, not split across two passes", early)
	}

	// A later cycle, cutoff past the bucket.
	d.aggregateFlowsToRollup(bucket.Add(time.Hour), "5m")
	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "5m").Find(&rows).Error; err != nil {
		t.Fatalf("read 5m tier: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the bucket produced %d rows in the 5m tier, want 1", len(rows))
	}
	if rows[0].BytesSum != 500 {
		t.Errorf("promoted %d bytes, want the 500 seeded", rows[0].BytesSum)
	}
	var leftover int64
	d.Gorm().Model(&models.FlowSample{}).Count(&leftover)
	if leftover != 0 {
		t.Errorf("%d raw samples survived a promotion that consumed their bucket", leftover)
	}
}

// TestAggregateRollupsUp_EmitsEachDayOnce covers the 1h→1d step, which is the
// one the truncation was measured on and the only one whose window is walked in
// sub-ranges. A day-destination window must be 24h wide (a split day bucket is
// the duplication being fixed), which made its SELECT and DELETE the largest
// statements the ladder issues — 14.7s and 3.3M rows against a 30s
// statement_timeout. The window is therefore scanned an hour at a time and the
// partial aggregates merged in Go, so this asserts the merge produces ONE row
// per day carrying every sub-range's bytes.
func TestAggregateRollupsUp_EmitsEachDayOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	day := time.Now().Add(-40 * 24 * time.Hour).UTC().Truncate(24 * time.Hour)
	for h := 0; h < 24; h++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(h) * time.Hour),
			DeviceID:  1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 2, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed +%dh: %v", h, err)
		}
	}

	// Cutoff mid-day: the day must be deferred whole, not split.
	d.aggregateRollupsUp("1h", "1d", day.Add(13*time.Hour))
	var early int64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "1d").Count(&early)
	if early != 0 {
		t.Errorf("a cutoff inside the day produced %d 1d rows, want 0", early)
	}

	// A later cycle, cutoff past the day.
	d.aggregateRollupsUp("1h", "1d", day.Add(48*time.Hour))
	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "1d").Find(&rows).Error; err != nil {
		t.Fatalf("read 1d tier: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the day produced %d rows in the 1d tier, want 1 — 24 hourly sub-range "+
			"scans must merge by group key, not emit a row each", len(rows))
	}
	if rows[0].BytesSum != 2400 || rows[0].PacketsSum != 48 || rows[0].FlowCount != 24 {
		t.Errorf("daily row = %d bytes / %d packets / %d flows, want 2400 / 48 / 24 — "+
			"the sub-range merge dropped measures", rows[0].BytesSum, rows[0].PacketsSum, rows[0].FlowCount)
	}
	var leftover int64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "1h").Count(&leftover)
	if leftover != 0 {
		t.Errorf("%d hourly rows survived the promotion that consumed their day", leftover)
	}
}

// TestAggregateRollupsUp_MergesSamplingRateByFlowCount pins the subtlest part of
// the sub-range merge. sampling_rate_avg is a flow-count-weighted mean, so
// folding two partial aggregates cannot simply average them or keep the first —
// it has to re-weight, and it has to do so BEFORE the running flow count moves
// underneath it.
func TestAggregateRollupsUp_MergesSamplingRateByFlowCount(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Hour h carries flow_count h+1 at sampling rate h+1, so the day's weighted
	// mean is sum(k^2)/sum(k) over k=1..24 = 4900/300.
	day := time.Now().Add(-40 * 24 * time.Hour).UTC().Truncate(24 * time.Hour)
	for h := 0; h < 24; h++ {
		k := float64(h + 1)
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(h) * time.Hour),
			DeviceID:  1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: int64(h + 1), SamplingRateAvg: k,
		}).Error; err != nil {
			t.Fatalf("seed +%dh: %v", h, err)
		}
	}

	d.aggregateRollupsUp("1h", "1d", day.Add(48*time.Hour))

	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "1d").Find(&rows).Error; err != nil {
		t.Fatalf("read 1d tier: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("1d rows = %d, want 1", len(rows))
	}
	const want = 4900.0 / 300.0
	if got := rows[0].SamplingRateAvg; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("merged sampling_rate_avg = %v, want %v (flow-count-weighted). A plain "+
			"average gives 12.5 and keeping the first sub-range gives 1.", got, want)
	}
	if rows[0].FlowCount != 300 {
		t.Errorf("merged flow_count = %d, want 300", rows[0].FlowCount)
	}
}

// TestTruncateToBucket_KeepsCallersZone pins the zone half of the truncation.
//
// The boundary has to be computed in UTC — that is where both engines bucket —
// but the result becomes a `timestamp < ?` bound, and SQLite compares timestamps
// as rendered text INCLUDING the offset. A UTC-rendered bound sorted against
// locally-rendered rows by its digits, so the promotion simply did not see them.
func TestTruncateToBucket_KeepsCallersZone(t *testing.T) {
	zone := time.FixedZone("test+12", 12*3600)
	// 2026-06-02 03:30 UTC, which is 2026-06-02 15:30 in +12.
	at := time.Date(2026, 6, 2, 3, 30, 0, 0, time.UTC).In(zone)

	for _, tc := range []struct {
		unit string
		want time.Time
	}{
		{"5min", time.Date(2026, 6, 2, 3, 30, 0, 0, time.UTC)},
		{"hour", time.Date(2026, 6, 2, 3, 0, 0, 0, time.UTC)},
		{"day", time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)},
	} {
		got := truncateToBucket(at, tc.unit)
		if !got.Equal(tc.want) {
			t.Errorf("%s: boundary = %s, want %s (the UTC bucket start, which is what "+
				"both engines group by)", tc.unit, got.UTC(), tc.want)
		}
		if got.Location() != zone {
			t.Errorf("%s: zone = %s, want the caller's %s — the result is a SQL bound and "+
				"SQLite compares the rendered offset", tc.unit, got.Location(), zone)
		}
	}
}

// TestAggregateRollupsUp_PromotesRowsStampedOutsideUTC walks the day path with
// rows and a cutoff that both carry a non-UTC offset, which is what production
// does — RunFlowRollupCycle's cutoff is time.Now(), in the process zone. It uses
// an explicit fixed zone rather than the host's, so it exercises that regardless
// of TZ and guards in a UTC CI too.
//
// It is NOT the guard for the caller-zone rule in truncateToBucket: the window
// walk re-derives its bounds from real row timestamps, so a mis-zoned cutoff
// usually cannot reach the aggregate here. TestTruncateToBucket_KeepsCallersZone
// pins that contract directly, and TestFlowRollup_GroupsByFlowSource /
// _GroupsByFirewallEvent catch it behaviourally east of Greenwich.
func TestAggregateRollupsUp_PromotesRowsStampedOutsideUTC(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	zone := time.FixedZone("test+12", 12*3600)
	day := time.Now().Add(-40 * 24 * time.Hour).UTC().Truncate(24 * time.Hour)
	for h := 0; h < 24; h++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(h) * time.Hour).In(zone),
			DeviceID:  1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed +%dh: %v", h, err)
		}
	}

	// The cutoff sits exactly on the day boundary. That matters: a cutoff well
	// past the day would still sort above every row even when rendered in the
	// wrong zone, and the test would pass with the bug in place. On the boundary
	// a 12-hour rendering error crosses half the rows.
	d.aggregateRollupsUp("1h", "1d", day.Add(24*time.Hour).In(zone))

	var promoted uint64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "1d").
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&promoted)
	if promoted != 2400 {
		t.Errorf("promoted %d of 2400 seeded bytes — a day whose rows and cutoff are "+
			"stamped outside UTC must promote whole.", promoted)
	}
}

// TestAggregateRollupsUp_ScansTheDayInSubRanges pins that a whole-day window is
// not one enormous statement pair.
//
// A day-destination window must be 24h wide, which made its SELECT and DELETE
// the largest statements the ladder issues — measured on production at 14.7s and
// 3.3M rows, against a 30s statement_timeout. Blowing it there is a PERMANENT
// stall, since the window rolls back and the next tick reissues the identical
// statement. The merge that makes sub-ranging possible is covered by
// TestAggregateRollupsUp_MergesSamplingRateByFlowCount; this covers the split
// itself, which is otherwise invisible in the results.
func TestAggregateRollupsUp_ScansTheDayInSubRanges(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	day := time.Now().Add(-40 * 24 * time.Hour).UTC().Truncate(24 * time.Hour)
	for h := 0; h < 24; h++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(h) * time.Hour),
			DeviceID:  1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed +%dh: %v", h, err)
		}
	}

	// Scan() into a plain slice runs through GORM's Row processor, not Query.
	var aggregates int
	if err := d.Gorm().Callback().Row().After("gorm:row").
		Register("test:count_promote_scans", func(tx *gorm.DB) {
			if sql := tx.Statement.SQL.String(); strings.Contains(sql, "GROUP BY") &&
				strings.Contains(sql, "flow_rollups") {
				aggregates++
			}
		}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	defer func() { _ = d.Gorm().Callback().Row().Remove("test:count_promote_scans") }()

	d.aggregateRollupsUp("1h", "1d", day.Add(48*time.Hour))

	// Exactly one statement per source bucket. `< 2` would have accepted a
	// 12-hour step, which is two ~7s statements on a production day — still far
	// too close to the 30s cancel to be the property this pins.
	if aggregates != 24 {
		t.Errorf("the whole day was aggregated in %d statement(s), want 24 — one per hourly "+
			"source bucket. A single statement over a production day measures 14.7s against "+
			"a 30s statement_timeout, and exceeding it stalls the ladder for good.",
			aggregates)
	}
}

// TestRollupAccumulator_KeyCoversEveryGroupedColumn guards the one thing nothing
// else can: that `rollupKey` and the SQL `flowRollupGroupKey` stay in step.
//
// The accumulator folds sub-range aggregates by a Go struct key. If a column is
// added to the GROUP BY but not to that struct, two genuinely distinct groups
// collapse into one and their measures are summed together — silent corruption
// on the daily tier only, invisible until someone diffs row counts against the
// source. The compiler cannot catch it because both sides are independently
// valid.
func TestRollupAccumulator_KeyCoversEveryGroupedColumn(t *testing.T) {
	// flowRollupGroupKey is a comma-separated column list.
	grouped := 0
	for _, c := range strings.Split(flowRollupGroupKey, ",") {
		if strings.TrimSpace(c) != "" {
			grouped++
		}
	}
	fields := reflect.TypeOf(rollupKey{}).NumField()
	if fields != grouped {
		t.Errorf("rollupKey has %d fields but flowRollupGroupKey groups by %d columns (%q). "+
			"The sub-range merge folds by rollupKey, so a grouped column missing from the "+
			"struct silently merges distinct groups and sums their measures together.",
			fields, grouped, flowRollupGroupKey)
	}
}

// TestAggregateRollupsUp_MergesDisjointKeysAcrossSubRanges exercises the
// accumulator's INSERT branch, which every other test misses: they all seed a
// single group key, so only the merge branch runs and an off-by-one in the index
// bookkeeping would pass the whole suite.
//
// Here each hour carries a key the neighbouring hours do not, plus one shared
// key present in every hour — so the day must fold to (distinct keys + 1) rows
// with each one's measures intact.
func TestAggregateRollupsUp_MergesDisjointKeysAcrossSubRanges(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	day := time.Now().Add(-40 * 24 * time.Hour).UTC().Truncate(24 * time.Hour)
	const hours = 24
	// Hours 0 and 7 are left EMPTY, which covers two more paths for free: the
	// skip-the-delete branch for a sub-range with no source rows, and — because
	// hour 0 is one of them — the accumulator adopting its first batch on a
	// LATER sub-range than the first.
	empty := map[int]bool{0: true, 7: true}
	seeded := 0
	for h := 0; h < hours; h++ {
		if empty[h] {
			continue
		}
		seeded++
		ts := day.Add(time.Duration(h) * time.Hour)
		// Unique to this hour — lands in exactly one sub-range.
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: ts, DeviceID: 1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: uint16(1000 + h), Protocol: 6,
			BytesSum: 7, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed unique +%dh: %v", h, err)
		}
		// Present in every seeded hour, so it arrives in whichever batch the
		// accumulator adopts whole and is indexed in bulk.
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: ts, DeviceID: 1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 5, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed shared +%dh: %v", h, err)
		}
		// Absent from the first seeded hour, so it is first seen in a LATER
		// sub-range and therefore indexed by the append branch, then merged in
		// every sub-range after that. This is the only path that dereferences an
		// index the append branch wrote — without it an off-by-one there is
		// never observed.
		if h > 1 {
			if err := d.Gorm().Create(&models.FlowRollup{
				Timestamp: ts, DeviceID: 1, IntervalType: "1h",
				SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 8443, Protocol: 6,
				BytesSum: 3, PacketsSum: 1, FlowCount: 1,
			}).Error; err != nil {
				t.Fatalf("seed late-shared +%dh: %v", h, err)
			}
		}
	}

	d.aggregateRollupsUp("1h", "1d", day.Add(48*time.Hour))

	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "1d").Find(&rows).Error; err != nil {
		t.Fatalf("read 1d tier: %v", err)
	}
	if len(rows) != seeded+2 {
		t.Fatalf("1d tier holds %d rows, want %d (one per hour-unique port, plus the key in "+
			"every seeded hour and the one that starts later). A wrong index into the "+
			"accumulator collapses or duplicates keys.", len(rows), seeded+2)
	}

	var shared, lateShared *models.FlowRollup
	uniques := 0
	for i := range rows {
		switch {
		case rows[i].DstPort == 443:
			shared = &rows[i]
		case rows[i].DstPort == 8443:
			lateShared = &rows[i]
		case rows[i].DstPort >= 1000 && rows[i].DstPort < 1000+hours:
			if empty[int(rows[i].DstPort)-1000] {
				t.Errorf("port %d came from an hour that was never seeded", rows[i].DstPort)
			}
			uniques++
			if rows[i].BytesSum != 7 || rows[i].FlowCount != 1 {
				t.Errorf("port %d carries %d bytes / %d flows, want 7 / 1 — a key seen in one "+
					"sub-range must pass through untouched", rows[i].DstPort,
					rows[i].BytesSum, rows[i].FlowCount)
			}
		default:
			t.Errorf("unexpected dst_port %d in the daily tier", rows[i].DstPort)
		}
	}
	if uniques != seeded {
		t.Errorf("found %d hour-unique keys, want %d", uniques, seeded)
	}
	if shared == nil {
		t.Fatal("the key shared by every hour is missing from the daily tier")
	}
	if shared.BytesSum != uint64(5*seeded) || shared.FlowCount != int64(seeded) {
		t.Errorf("the shared key carries %d bytes / %d flows, want %d / %d",
			shared.BytesSum, shared.FlowCount, 5*seeded, seeded)
	}
	if lateShared == nil {
		t.Fatal("the key first seen in the second sub-range is missing from the daily tier")
	}
	// Seeded for every hour above 1 that is not in `empty`.
	lateHours := 0
	for h := 2; h < hours; h++ {
		if !empty[h] {
			lateHours++
		}
	}
	if lateShared.BytesSum != uint64(3*lateHours) || lateShared.FlowCount != int64(lateHours) {
		t.Errorf("the key first appearing in a later sub-range carries %d bytes / %d flows, "+
			"want %d / %d — the index the append branch wrote points at the wrong row",
			lateShared.BytesSum, lateShared.FlowCount, 3*lateHours, lateHours)
	}
}

// TestFlowRollupRetentionFloor_KeepsClearOfTheLadder pins that retention cannot
// be configured to delete a tier the ladder has not finished with.
//
// The flow_rollups cutoff applies to EVERY interval_type, so a window shorter
// than the ladder's reach reaps hourly rows before their daily row is written —
// silent loss, no error. Deferring straddled buckets widened the exposure from
// one ticker interval to a full day, which is what turned this from a comment
// into a guard.
func TestFlowRollupRetentionFloor_KeepsClearOfTheLadder(t *testing.T) {
	ladderDays := int(flowPromote1hTo1dAge / (24 * time.Hour))

	if got := flowRollupRetentionFloor(365); got != 365 {
		t.Errorf("the default of 365 days was altered to %d; the floor must only raise a "+
			"window that is genuinely too short", got)
	}
	if got := flowRollupRetentionFloor(ladderDays); got <= ladderDays {
		t.Errorf("a window equal to the promotion age (%d days) stayed at %d — retention "+
			"would race the 1h→1d promotion it is supposed to outlive", ladderDays, got)
	}
	if got := flowRollupRetentionFloor(0); got != 0 {
		t.Errorf("flowRollupRetentionFloor(0) = %d, want 0 — zero means the caller's own "+
			"default applies and must pass through untouched", got)
	}
}
