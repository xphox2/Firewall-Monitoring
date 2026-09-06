//go:build integration

// Per-severity volume estimation against real Postgres catalog statistics.
//
// These are integration tests rather than unit tests because the whole feature
// IS the catalog: pg_stats, pg_class.reltuples and pg_inherits have no SQLite
// equivalent, so a mock would only assert that the mock was written to match
// the code. Both bugs these pin were found by comparing rendered figures to
// seeded data, and neither is reachable without a real planner.

package database

import (
	"testing"

	"firewall-mon/internal/config"
)

// The three shapes syslog_messages is actually deployed in. The estimate has to
// be right in all of them, and each broke differently:
//
//   - plainHeap is production today.
//   - partitionedLeafOnly is EVERY fresh install as autovacuum actually leaves
//     it. PostgreSQL never analyzes a partitioned parent automatically, so the
//     parent's pg_stats stays empty forever and a parent-only query reports
//     nothing at all — for the table the operator most needs to see.
//   - partitionedBothAnalyzed is what a manual ANALYZE produces, and is the
//     shape that hid the bug above during development while introducing its
//     own: an explicit ANALYZE on the parent populates the parent's reltuples
//     with the whole total, so summing parent AND children double-counts.
const (
	plainHeap = iota
	partitionedLeafOnly
	partitionedBothAnalyzed
)

// seedSyslogVolume builds syslog_messages in the requested shape with a
// deliberately lopsided distribution: production is ~97% one severity, and the
// severities an operator most wants to protect are ~0.01% of rows. An estimator
// that looks fine on a uniform distribution can still be useless on this one.
func seedSyslogVolume(t *testing.T, d *Database, shape int) map[int]int64 {
	t.Helper()
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if err := d.db.Exec(q, args...).Error; err != nil {
			t.Fatalf("exec %.60s: %v", q, err)
		}
	}
	exec(`DROP TABLE IF EXISTS syslog_messages CASCADE`)

	if shape == plainHeap {
		exec(`CREATE TABLE syslog_messages (
			id bigserial, severity int, message text, "timestamp" timestamptz)`)
	} else {
		exec(`CREATE TABLE syslog_messages (
			id bigserial, severity int, message text, "timestamp" timestamptz)
			PARTITION BY RANGE ("timestamp")`)
		exec(`CREATE TABLE syslog_messages_2026_07 PARTITION OF syslog_messages
			FOR VALUES FROM ('2026-07-01') TO ('2026-08-01')`)
	}

	exec(`INSERT INTO syslog_messages (severity, message, "timestamp")
		SELECT CASE WHEN g % 1000 < 970 THEN 5
		            WHEN g % 1000 < 995 THEN 4
		            WHEN g % 1000 < 999 THEN 6
		            ELSE 3 END,
		       'seeded', '2026-07-15'::timestamptz
		FROM generate_series(1, 20000) g`)

	switch shape {
	case plainHeap:
		exec(`ANALYZE syslog_messages`)
	case partitionedLeafOnly:
		// Only the leaf — exactly what autovacuum does, and nothing more.
		exec(`ANALYZE syslog_messages_2026_07`)
	case partitionedBothAnalyzed:
		exec(`ANALYZE syslog_messages_2026_07`)
		exec(`ANALYZE syslog_messages`)
	}

	return map[int]int64{3: 20, 4: 500, 5: 19400, 6: 80}
}

func TestSyslogVolume_EstimatesAreRightInEveryTableShape(t *testing.T) {
	shapes := []struct {
		name  string
		shape int
	}{
		{"plain heap (production)", plainHeap},
		{"partitioned, leaf analyzed only (every fresh install)", partitionedLeafOnly},
		{"partitioned, parent also analyzed", partitionedBothAnalyzed},
	}

	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			d := newPGForTest(t) // skips if TEST_PG_DSN is unset
			want := seedSyslogVolume(t, d, tc.shape)

			total, freqs, ok := d.syslogSeverityStats()

			if !ok {
				t.Fatalf("no statistics resolved. On the leaf-only shape this is the real "+
					"defect: autovacuum never analyzes a partitioned parent, so reading the "+
					"parent's pg_stats alone yields nothing and every severity renders as "+
					"untracked — on the shape every new install has. (shape=%s)", tc.name)
			}

			// The row total must count the rows once. Summing the parent AND its
			// partitions reported 20,000 rows as 40,000, because an explicit
			// ANALYZE on a partitioned parent populates the parent's reltuples
			// with the whole total as well.
			if total != 20000 {
				t.Errorf("total rows = %d, want 20000 (a doubled value means parent and "+
					"partitions are both being summed)", total)
			}

			for sev, wantRows := range want {
				gotRows := int64(freqs[sev] * float64(total))
				// Statistics are an estimate; hold them to the right order of
				// magnitude rather than to the exact count.
				lo, hi := float64(wantRows)*0.5, float64(wantRows)*1.5
				if float64(gotRows) < lo || float64(gotRows) > hi {
					t.Errorf("severity %d estimated %d rows, want ~%d (%.0f-%.0f)",
						sev, gotRows, wantRows, lo, hi)
				}
			}

			// The dominant severity has to dominate: the entire point of the
			// display is showing which severity is drowning the operator.
			if freqs[5] < 0.9 {
				t.Errorf("severity 5 freq = %.4f, want ~0.97 — the estimate fails to "+
					"identify the severity holding almost the whole table", freqs[5])
			}
			// And the rare ones must not read as absent. Reporting zero for the
			// severities an operator most wants to protect is what makes a
			// sampling approach unusable here, and is worse than saying nothing.
			for _, sev := range []int{3, 6} {
				if freqs[sev] <= 0 {
					t.Errorf("severity %d estimated at zero rows; it holds %d. A hard zero "+
						"on a rare-but-present severity invites shortening its window", sev, want[sev])
				}
			}
		})
	}
}

// The row width backs the byte estimate and reads pg_stats too, so it has the
// same parent-has-no-statistics blind spot.
func TestSyslogVolume_RowWidthResolvesWithoutParentStats(t *testing.T) {
	d := newPGForTest(t)
	seedSyslogVolume(t, d, partitionedLeafOnly)

	if w := d.syslogAvgRowWidth(); w <= 0 {
		t.Errorf("avg row width = %d on a partitioned table with only the leaf analyzed; "+
			"every size estimate silently becomes 0 bytes", w)
	}
}

// The whole reason this reads the catalog instead of counting: a GROUP BY over
// 68M rows would risk the 30-second statement timeout on every load of the
// Settings page — the exact failure class the retention work exists to remove.
func TestSyslogVolume_DoesNotScanTheTable(t *testing.T) {
	d := newPGForTest(t)
	seedSyslogVolume(t, d, plainHeap)

	var before, after int64
	read := func(dst *int64) {
		if err := d.db.Raw(`SELECT COALESCE(seq_tup_read, 0) FROM pg_stat_user_tables
			WHERE relname = 'syslog_messages'`).Scan(dst).Error; err != nil {
			t.Fatalf("read seq_tup_read: %v", err)
		}
	}
	// Statistics are collected asynchronously; force what's pending to land.
	if err := d.db.Exec(`SELECT pg_stat_force_next_flush()`).Error; err != nil {
		t.Skipf("pg_stat_force_next_flush unavailable (PG < 15): %v", err)
	}
	read(&before)

	// The whole report, not its two original helpers: v0.11.236 added the
	// on-disk footprint, database size, server_metrics and syslog_ingest_hourly
	// reads, and every one of them has to stay under this guarantee.
	d.SyslogVolume(config.RetentionConfig{SyslogCriticalDays: 30, SyslogInfoDays: 7})

	if err := d.db.Exec(`SELECT pg_stat_force_next_flush()`).Error; err != nil {
		t.Fatalf("flush: %v", err)
	}
	read(&after)

	if after > before {
		t.Errorf("volume estimation read %d tuples from syslog_messages; it must touch only "+
			"the catalog. A per-load scan of this table is what times out at 68M rows",
			after-before)
	}
}

// SyslogVolume must present a rare-but-present severity as untracked rather
// than as a confident zero, and must not invent a distribution before any
// ANALYZE has run.
func TestSyslogVolume_NeverAnalyzedReportsUnavailableNotZero(t *testing.T) {
	d := newPGForTest(t)
	if err := d.db.Exec(`DROP TABLE IF EXISTS syslog_messages CASCADE`).Error; err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := d.db.Exec(`CREATE TABLE syslog_messages (
		id bigserial, severity int, message text, "timestamp" timestamptz)`).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	// Rows exist but nothing has analyzed them yet.
	if err := d.db.Exec(`INSERT INTO syslog_messages (severity, message, "timestamp")
		SELECT 5, 'x', now() FROM generate_series(1, 100) g`).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}

	rep := d.SyslogVolume(config.RetentionConfig{SyslogCriticalDays: 30, SyslogInfoDays: 7})
	if rep.StatsAvailable {
		t.Error("StatsAvailable is true before any ANALYZE — the page would present an " +
			"invented distribution as fact")
	}
	for _, s := range rep.Severities {
		if s.Tracked {
			t.Errorf("severity %d reported as tracked with no statistics collected", s.Severity)
		}
		if s.EstRows != 0 {
			t.Errorf("severity %d reports %d rows with no statistics", s.Severity, s.EstRows)
		}
	}
	if got := len(rep.Severities); got != SyslogSeverityCount {
		t.Errorf("reported %d severities, want %d — every severity needs a row even when "+
			"its volume is unknown, or it cannot be configured", got, SyslogSeverityCount)
	}
}

// The projection multiplies a row rate by the table's TRUE on-disk cost per row
// (heap + indexes + TOAST), which the planner's avg_width understates by ~25%
// on production. It must resolve in every shape the table is deployed in,
// including the leaf-only-analyzed one every fresh install has.
func TestSyslogVolume_DiskFootprintResolvesInEveryTableShape(t *testing.T) {
	shapes := []struct {
		name  string
		shape int
	}{
		{"plain heap (production)", plainHeap},
		{"partitioned, leaf analyzed only (every fresh install)", partitionedLeafOnly},
		{"partitioned, parent also analyzed", partitionedBothAnalyzed},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			d := newPGForTest(t)
			seedSyslogVolume(t, d, tc.shape)

			width, tableBytes, measured := d.syslogDiskFootprint()
			if !measured {
				t.Fatalf("width not measured (width=%d, bytes=%d) — the projection would fall back to "+
					"the received size and understate the on-disk cost", width, tableBytes)
			}
			if width <= 0 || tableBytes <= 0 {
				t.Errorf("width=%d tableBytes=%d, want both > 0", width, tableBytes)
			}
			// 20,000 seeded rows; a partition-double-count would halve the width
			// and a parent-only read would zero the bytes.
			if width < 20 || width > 2000 {
				t.Errorf("width=%d bytes/row is not a plausible per-row cost for the seeded rows", width)
			}
			rep := d.SyslogVolume(config.RetentionConfig{SyslogCriticalDays: 30, SyslogInfoDays: 7})
			if rep.DiskBytesPerRow != width || rep.CurrentSyslogBytes != tableBytes || !rep.DiskWidthMeasured {
				t.Errorf("report carries width=%d bytes=%d measured=%v, want %d/%d/true",
					rep.DiskBytesPerRow, rep.CurrentSyslogBytes, rep.DiskWidthMeasured, width, tableBytes)
			}
			if rep.DatabaseBytes < rep.CurrentSyslogBytes {
				t.Errorf("DatabaseBytes=%d < CurrentSyslogBytes=%d", rep.DatabaseBytes, rep.CurrentSyslogBytes)
			}
		})
	}
}

// Never analyzed: the footprint's bytes are known but its per-row cost is not
// (reltuples = -1), and the report must say so rather than divide by a sentinel.
func TestSyslogVolume_DiskWidthUnmeasuredBeforeAnalyze(t *testing.T) {
	d := newPGForTest(t)
	if err := d.db.Exec(`DROP TABLE IF EXISTS syslog_messages CASCADE`).Error; err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := d.db.Exec(`CREATE TABLE syslog_messages (
		id bigserial, severity int, message text, "timestamp" timestamptz)`).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.db.Exec(`INSERT INTO syslog_messages (severity, message, "timestamp")
		SELECT 5, 'x', now() FROM generate_series(1, 100) g`).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	width, tableBytes, measured := d.syslogDiskFootprint()
	if measured || width != 0 {
		t.Errorf("width=%d measured=%v before any ANALYZE, want 0/false", width, measured)
	}
	if tableBytes <= 0 {
		t.Errorf("tableBytes=%d, want the relation's size even when the width is unknown", tableBytes)
	}
}
