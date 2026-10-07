//go:build integration

package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// TestArchiveStatusReads_PG: the status card's reads (every 15 s per open
// tab) cost what they return, not what the archive has accumulated. Seeded
// with five years of manifest: a syslog chunk per day and a flow chunk per
// hour (~45 000 chunks) with three objects each (~135 000), all verified but
// the last few; every statement is EXPLAINed exactly as the code builds it
// and must read archive_chunks and archive_objects by index — no Seq Scan
// costing more than zero, no Sort of the verified chunks — and ANALYZE
// confirms it touches a few dozen buffers, not the tables' pages.
func TestArchiveStatusReads_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	ctx := context.Background()
	start := time.Date(2021, 10, 1, 0, 0, 0, 0, time.UTC)
	days := 5 * 365
	for _, q := range []string{
		// Daily syslog chunks, verified but the last three (one failed, one
		// pending, one superseded attempt record).
		fmt.Sprintf(`INSERT INTO archive_chunks (table_name, seq, id_lo, id_hi, period_start, period_end, month, cut_at, status, row_count,
			attempts, mismatches, verify_failures, error, runner_id, started_at, verified_at, created_at, updated_at)
			SELECT 'syslog_messages', g, g*1000, (g+1)*1000, ts, ts + interval '1 day', to_char(ts, 'YYYY-MM'), ts + interval '1 day',
				CASE WHEN g = %[1]d-1 THEN 'pending' WHEN g = %[1]d-2 THEN 'failed' WHEN g = %[1]d-3 THEN 'superseded' ELSE 'verified' END,
				1000, 1, 0, 0, '', 'fw-example-01', ts + interval '26 hours',
				CASE WHEN g < %[1]d-3 THEN ts + interval '26 hours 5 minutes' END, ts, ts
			FROM (SELECT g, ?::timestamptz + g * interval '1 day' AS ts FROM generate_series(0, %[1]d-1) AS g) s`, days),
		// Hourly flow chunks.
		fmt.Sprintf(`INSERT INTO archive_chunks (table_name, seq, id_lo, id_hi, period_start, period_end, month, cut_at, status, row_count,
			attempts, mismatches, verify_failures, error, runner_id, started_at, verified_at, created_at, updated_at)
			SELECT 'flow_samples', g, g*100, (g+1)*100, ts, ts + interval '1 hour', to_char(ts, 'YYYY-MM'), ts + interval '1 hour',
				CASE WHEN g = %[1]d-1 THEN 'pending' ELSE 'verified' END, 100, 1, 0, 0, '', 'fw-example-01',
				ts + interval '70 minutes', CASE WHEN g < %[1]d-1 THEN ts + interval '71 minutes' END, ts, ts
			FROM (SELECT g, ?::timestamptz + g * interval '1 hour' AS ts FROM generate_series(0, %[1]d-1) AS g) s`, days*24),
		// Three objects per chunk.
		`INSERT INTO archive_objects (chunk_id, stream, object_key, schema_version, compression, row_count, raw_bytes, object_bytes,
			status, min_id, max_id, part_count, created_at, updated_at)
			SELECT c.id, CASE WHEN c.table_name = 'syslog_messages' THEN 'syslog' WHEN k = 0 THEN 'sflow' ELSE 'netflow' END,
				'fwmon-test/' || c.id || '/' || k, 1, 'gzip', 300, 40000, 9000,
				CASE WHEN c.status = 'verified' THEN 'verified' ELSE 'pending' END, c.id_lo, c.id_hi, 1, c.created_at, c.created_at
			FROM archive_chunks c, generate_series(0, 2) AS k`,
	} {
		var err error
		if strings.Contains(q, "?::timestamptz") {
			err = d.db.Exec(q, start).Error
		} else {
			err = d.db.Exec(q).Error
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := d.db.Exec("VACUUM ANALYZE archive_chunks").Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Exec("VACUUM ANALYZE archive_objects").Error; err != nil {
		t.Fatal(err)
	}
	var chunks, objects int64
	d.db.Model(&models.ArchiveChunk{}).Count(&chunks)
	d.db.Model(&models.ArchiveObject{}).Count(&objects)
	t.Logf("seeded %d chunks, %d objects (archive_chunks %d pages, archive_objects %d pages)", chunks, objects,
		heapPages(t, d, "archive_chunks"), heapPages(t, d, "archive_objects"))

	lastMonths := []string{"2026-09"} // the months not sealed, as the status asks
	lastMonth := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		label  string
		stmt   func(tx *gorm.DB) *gorm.DB
		noSort bool
	}{
		{"month chunks", func(tx *gorm.DB) *gorm.DB {
			return archiveMonthChunksQuery(tx, export.TableFlows, lastMonth).Pluck("id", &[]uint{})
		}, false},
		{"backlog", func(tx *gorm.DB) *gorm.DB { return archiveBacklogQuery(tx).Scan(&[]map[string]any{}) }, false},
		{"oldest open", func(tx *gorm.DB) *gorm.DB {
			return archiveOldestOpenQuery(tx, export.TableSyslog).Pluck("period_start", &[]time.Time{})
		}, false},
		{"recent syslog", func(tx *gorm.DB) *gorm.DB {
			return archiveRecentQuery(tx, export.TableSyslog, 10).Find(&[]models.ArchiveChunk{})
		}, true},
		{"recent flows", func(tx *gorm.DB) *gorm.DB {
			return archiveRecentQuery(tx, export.TableFlows, 10).Find(&[]models.ArchiveChunk{})
		}, true},
		{"totals", func(tx *gorm.DB) *gorm.DB {
			var ids []uint
			if err := archiveMonthChunksQuery(d.db, export.TableFlows, lastMonth).Pluck("id", &ids).Error; err != nil || len(ids) < 600 {
				t.Fatalf("the month's flow chunks: %d, %v", len(ids), err)
			}
			lo, hi := ids[0], ids[0]
			for _, id := range ids {
				lo, hi = min(lo, id), max(hi, id)
			}
			return archiveTotalsQuery(tx, export.StreamSFlow, lo, hi).Scan(&[]map[string]any{})
		}, false},
	} {
		stmt := tc.stmt(dryRun(d)).Statement
		plan := archiveStatusPlan(t, d, tc.label, stmt, tc.noSort)
		bufs := explainBuffers(t, d, tc.label, stmt.SQL.String(), stmt.Vars...)
		t.Logf("%s: %d buffers\n%s", tc.label, bufs, plan)
		if bufs > 200 {
			t.Errorf("%s touches %d buffers: it grows with the archive", tc.label, bufs)
		}
	}

	// What the reads return on this archive.
	b, err := d.ArchiveBacklogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s := b[export.TableSyslog]; s.Chunks != 2 || s.OldestPeriod == nil || !s.OldestPeriod.Equal(start.AddDate(0, 0, days-2)) {
		t.Fatalf("syslog backlog %+v, want the failed and the pending chunk (not the superseded one)", s)
	}
	recent, err := d.RecentArchiveChunks(ctx, export.TableFlows, 10)
	if err != nil || len(recent) != 10 || recent[0].Chunk.Seq != int64(days*24-2) || recent[0].Objects != 3 {
		t.Fatalf("recent flows %v: %+v", err, recent)
	}
	tot, err := d.ArchiveVerifiedTotals(ctx, export.TableFlows, export.StreamSFlow, lastMonths)
	if err != nil || len(tot) != 1 || tot[0].Rows == 0 {
		t.Fatalf("totals %v: %+v", err, tot)
	}
	for _, r := range []struct {
		name string
		f    func() error
	}{
		{"backlog", func() error { _, err := d.ArchiveBacklogs(ctx); return err }},
		{"recent syslog", func() error { _, err := d.RecentArchiveChunks(ctx, export.TableSyslog, 10); return err }},
		{"totals syslog", func() error {
			_, err := d.ArchiveVerifiedTotals(ctx, export.TableSyslog, export.StreamSyslog, lastMonths)
			return err
		}},
		{"totals sflow", func() error {
			_, err := d.ArchiveVerifiedTotals(ctx, export.TableFlows, export.StreamSFlow, lastMonths)
			return err
		}},
		// The status's older reads, for the log only (not part of this change).
		{"(older) status counts", func() error { _, err := d.ArchiveChunkStatusCounts(ctx); return err }},
		{"(older) chunk months", func() error { _, err := d.ArchiveChunkMonths(ctx, export.TableFlows); return err }},
		{"(older) table progress", func() error { _, err := d.ArchiveTableProgress(ctx, export.TableFlows); return err }},
		{"(older) table times", func() error { _, err := d.ArchiveTableTimes(ctx, export.TableFlows); return err }},
	} {
		began := time.Now()
		if err := r.f(); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s read in %v", r.name, time.Since(began))
	}
}

// archiveStatusPlan EXPLAINs stmt and fails on a Seq Scan costing more than
// zero, and — noSort — on a Sort (the newest chunks must come off the index
// in order). It returns the plan as text.
func archiveStatusPlan(t *testing.T, d *Database, label string, stmt *gorm.Statement, noSort bool) string {
	t.Helper()
	var raw string
	if err := d.pgxPool.QueryRow(context.Background(), "EXPLAIN (FORMAT JSON) "+stmt.SQL.String(), stmt.Vars...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN %s: %v\n%s", label, err, stmt.SQL.String())
	}
	var top []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &top); err != nil || len(top) != 1 {
		t.Fatalf("EXPLAIN %s JSON: %v", label, err)
	}
	var b strings.Builder
	var walk func(n planNode, depth int)
	walk = func(n planNode, depth int) {
		fmt.Fprintf(&b, "%s%s %s %s (cost %.2f)\n", strings.Repeat("  ", depth), n.Type, n.Relation, n.Index, n.TotalCost)
		if n.Type == "Seq Scan" && n.TotalCost > 0 {
			t.Errorf("EXPLAIN %s: Seq Scan on %s costing %.2f — the status must read the manifest by index", label, n.Relation, n.TotalCost)
		}
		if noSort && (n.Type == "Sort" || n.Type == "Incremental Sort") {
			t.Errorf("EXPLAIN %s: %s — the newest chunks must come off the index in order", label, n.Type)
		}
		for _, c := range n.Plans {
			walk(c, depth+1)
		}
	}
	walk(top[0].Plan, 0)
	return b.String()
}
