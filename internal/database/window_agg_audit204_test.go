package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// AUDIT-204 (2026-08-27 audit): the aggregation passes used to page their
// GROUP BY with LIMIT/OFFSET, which forced the FULL backlog to be aggregated
// per page — so once a real backlog accumulated, the first page blew the 30s
// statement_timeout and the cycle wedged forever while cleanup deleted
// never-summarised rows. The passes now walk bounded time windows, each
// committing its own insert+delete transaction. These tests pin the two
// properties that rewrite exists to provide:
//   - a backlog spanning many windows aggregates COMPLETELY, even when the
//     window is far smaller than the backlog (and smaller than a bucket);
//   - a failure in a LATER window keeps every EARLIER window's commit
//     (forward progress) and leaves the failed/unreached raw rows intact.

// poisonAfterDialect wraps the real dialect, replacing the bucket value with
// an unparseable constant for every bucket at or after a boundary (compared in
// the dialect's own normalized bucket space, so the comparison is portable
// text-chronological). Windows before the boundary aggregate normally; the
// window that first crosses it fails at insert time and rolls back.
type poisonAfterDialect struct {
	Dialect
	after string // boundary in the wrapped dialect's bucket format
}

func (p poisonAfterDialect) TimeBucket(unit, column string) string {
	real := p.Dialect.TimeBucket(unit, column)
	return fmt.Sprintf("CASE WHEN %s >= '%s' THEN 'garbage' ELSE %s END", real, p.after, real)
}

// TestSyslogAggregation_MultiWindowBacklog_AUDIT204 walks a backlog spanning
// several shrunk windows — including windows SMALLER than the hourly bucket,
// so one bucket straddles multiple windows — and requires complete, exact
// aggregation: summed counts preserved per hour bucket and every consumed raw
// row deleted. (Straddled buckets may legally produce multiple summary rows;
// readers and the promotion tier merge them by SUM, which is what the
// per-bucket sum assertion exercises.)
func TestSyslogAggregation_MultiWindowBacklog_AUDIT204(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	orig := syslogAggWindow
	syslogAggWindow = 15 * time.Minute
	defer func() { syslogAggWindow = orig }()

	base := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	cutoff := base.Add(6 * time.Hour)
	// Hour 10:00 — four rows across four 15-minute windows, one group.
	for _, min := range []int{0, 15, 30, 45} {
		seed(t, d, 1, 6, base.Add(time.Duration(min)*time.Minute), "hour10")
	}
	// Hour 12:00 — two rows, a separate bucket two hours (8 windows) later.
	seed(t, d, 1, 6, base.Add(2*time.Hour), "hour12")
	seed(t, d, 1, 6, base.Add(2*time.Hour+5*time.Minute), "hour12")

	ok, err := d.aggregateSyslogToSummary(cutoff, 6, "1h")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !ok {
		t.Fatal("expected work to be done")
	}

	var raw int64
	d.db.Model(&models.SyslogMessage{}).Count(&raw)
	if raw != 0 {
		t.Errorf("raw rows left = %d, want 0 — the window walk must consume the whole backlog", raw)
	}

	// Per-bucket integrity: SUM(count) per hour must match the seeds exactly,
	// however many windows (and summary rows) the bucket spanned.
	var perBucket []struct {
		Timestamp time.Time
		Total     int64
	}
	if err := d.db.Model(&models.SyslogSummary{}).
		Select("timestamp, SUM(count) as total").
		Group("timestamp").Order("timestamp").
		Scan(&perBucket).Error; err != nil {
		t.Fatalf("sum summaries: %v", err)
	}
	want := map[string]int64{
		base.Format("2006-01-02 15:04"):                    4,
		base.Add(2 * time.Hour).Format("2006-01-02 15:04"): 2,
	}
	if len(perBucket) != len(want) {
		t.Fatalf("distinct summary buckets = %d, want %d: %+v", len(perBucket), len(want), perBucket)
	}
	for _, b := range perBucket {
		key := b.Timestamp.UTC().Format("2006-01-02 15:04")
		if want[key] != b.Total {
			t.Errorf("bucket %s summed count = %d, want %d (lost or double-counted across windows)", key, b.Total, want[key])
		}
	}
}

// TestSyslogAggregation_LaterWindowFailureKeepsEarlierProgress_AUDIT204 pins
// forward progress — the property the old all-or-nothing transaction lacked: a
// failure induced in a later window must leave the earlier windows' summaries
// committed and their raw rows deleted, while the failed and never-reached
// windows' raw rows survive untouched for the next cycle.
func TestSyslogAggregation_LaterWindowFailureKeepsEarlierProgress_AUDIT204(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	orig := syslogAggWindow
	syslogAggWindow = time.Hour
	defer func() { syslogAggWindow = orig }()

	base := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	cutoff := base.Add(6 * time.Hour)
	seed(t, d, 1, 6, base.Add(15*time.Minute), "w1a")
	seed(t, d, 1, 6, base.Add(20*time.Minute), "w1b")
	seed(t, d, 1, 6, base.Add(time.Hour+15*time.Minute), "w2")
	seed(t, d, 1, 6, base.Add(2*time.Hour+15*time.Minute), "w3")

	// Buckets at or after 11:00 become unparseable → the second window fails.
	d.dialect = poisonAfterDialect{
		Dialect: d.dialect,
		after:   base.Add(time.Hour).Format("2006-01-02 15:04"),
	}

	done, err := d.aggregateSyslogToSummary(cutoff, 6, "1h")
	if err == nil {
		t.Fatal("expected the poisoned later window to fail the pass")
	}
	if !done {
		t.Error("done = false, want true — the first window's work WAS committed")
	}

	// Window 1 committed: its summary exists and its raw rows are gone.
	var sum int64
	d.db.Model(&models.SyslogSummary{}).Select("COALESCE(SUM(count), 0)").Scan(&sum)
	if sum != 2 {
		t.Errorf("committed summary count = %d, want 2 (the first window's two rows)", sum)
	}
	var survivors []models.SyslogMessage
	d.db.Order("message").Find(&survivors)
	got := messages(survivors)
	if len(got) != 2 || got[0] != "w2" || got[1] != "w3" {
		t.Errorf("surviving raw rows = %v, want [w2 w3] — earlier windows consumed, "+
			"failed and unreached windows preserved", got)
	}
}

// TestFlowRollup_LaterWindowFailureKeepsEarlierProgress_AUDIT204 is the
// flow-side twin: earlier windows' rollups commit and their raw samples are
// consumed; the failed and never-reached windows' samples survive.
func TestFlowRollup_LaterWindowFailureKeepsEarlierProgress_AUDIT204(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	orig := flowRollupWindow
	flowRollupWindow = time.Hour
	defer func() { flowRollupWindow = orig }()

	base := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	cutoff := base.Add(6 * time.Hour)
	seedFlow(t, d, base.Add(15*time.Minute), 1001, 500)
	seedFlow(t, d, base.Add(20*time.Minute), 1001, 300)
	seedFlow(t, d, base.Add(time.Hour+15*time.Minute), 2002, 700)
	seedFlow(t, d, base.Add(2*time.Hour+15*time.Minute), 3003, 900)

	// 5-minute buckets at or after 11:00 become unparseable → window 2 fails.
	d.dialect = poisonAfterDialect{
		Dialect: d.dialect,
		after:   base.Add(time.Hour).Format("2006-01-02 15:04"),
	}

	if !d.aggregateFlowsToRollup(cutoff, "5m") {
		t.Error("want true — the first window's work WAS committed before the failure")
	}

	var bytes int64
	d.db.Model(&models.FlowRollup{}).Select("COALESCE(SUM(bytes_sum), 0)").Scan(&bytes)
	if bytes != 800 {
		t.Errorf("committed rollup bytes = %d, want 800 (the first window's two samples)", bytes)
	}
	var survivors []models.FlowSample
	d.db.Order("dst_port").Find(&survivors)
	if len(survivors) != 2 || survivors[0].DstPort != 2002 || survivors[1].DstPort != 3003 {
		ports := make([]uint16, 0, len(survivors))
		for _, s := range survivors {
			ports = append(ports, s.DstPort)
		}
		t.Errorf("surviving sample ports = %v, want [2002 3003] — earlier windows consumed, "+
			"failed and unreached windows preserved", ports)
	}
}

// TestWalkAggregationWindows_JumpsEmptyRanges_AUDIT204Review pins the review
// fix on the window walk: cost must be proportional to NON-EMPTY windows, not
// to the time span. Pre-fix, a single pathologically ancient row (the
// collector's generic BSD syslog parser emits year-0 timestamps) made the walk
// crawl one transaction per empty window across millennia. The walker now
// probes the next eligible row after every window and jumps there, so this
// fixture — one ancient row and one recent row ~2000 years apart at a 1-hour
// window (~17.8M windows pre-fix) — must complete in exactly two aggregate
// calls and two probes.
func TestWalkAggregationWindows_JumpsEmptyRanges_AUDIT204Review(t *testing.T) {
	d := NewDatabaseForTesting(t)

	ancient := time.Date(0, 8, 28, 20, 31, 12, 0, time.UTC) // the BSD-parser shape
	recent := time.Date(2026, 5, 31, 10, 5, 0, 0, time.UTC)
	cutoff := recent.Add(time.Hour)

	var aggCalls, probes int
	total, err := walkAggregationWindows(d.db, time.Hour, ancient, cutoff,
		func(after time.Time) (time.Time, bool, error) {
			probes++
			if probes > 10 {
				t.Fatalf("nextEligible called %d times — the walk is crawling, not jumping", probes)
			}
			if !recent.Before(after) {
				return recent, true, nil
			}
			return time.Time{}, false, nil
		},
		func(tx *gorm.DB, winStart, winEnd time.Time) (int, error) {
			aggCalls++
			if aggCalls > 10 {
				return 0, fmt.Errorf("aggregate called %d times — empty-window crawl", aggCalls)
			}
			return 1, nil
		})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// Exactly two populated windows: the ancient row's and the recent row's.
	if aggCalls != 2 {
		t.Fatalf("aggregate windows = %d, want exactly 2 (ancient + recent)", aggCalls)
	}
	if probes != 2 {
		t.Fatalf("nextEligible probes = %d, want exactly 2 (jump + exhausted)", probes)
	}
	if total != 2 {
		t.Fatalf("total groups = %d, want 2", total)
	}
}
