//go:build integration

// The raw archive's planner and export reads (archive plan PR 3) on a real
// PostgreSQL, in both table shapes: the plain heap production has
// (syslog_messages is ~161 GB, never partitioned) and the partitioned parent
// of a fresh install (monthly leaves plus a DEFAULT child, primary key
// (id, timestamp)). Seeded at production density: the plan of a keyset page,
// a cut probe, a range count and max(id) is only meaningful when the table
// is much larger than the range read. Synthetic data only (RFC 5737,
// fw-example-NN).
package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
)

// archivePlanBuffers EXPLAINs a statement exactly as the code sends it: it
// fails on any Seq Scan costing more than zero (assertBackfillPlan; an empty
// future leaf's zero-cost scan is free — the lesson), requires a primary-key
// index in the plan, and then runs it under EXPLAIN (ANALYZE, BUFFERS) and
// returns the shared buffers it touched. Buffers, not the planner's total
// cost: on a partitioned table the key is (id, timestamp), and PostgreSQL
// discounts a multi-column index's correlation, so the estimate of an id
// range there is several times what the scan reads.
func archivePlanBuffers(t *testing.T, d *Database, label string, stmt *gorm.Statement) int64 {
	t.Helper()
	plan := assertBackfillPlan(t, d, label, stmt)
	if !strings.Contains(plan, "_pkey") {
		t.Errorf("%s: the plan does not read a primary key:\n%s", label, plan)
	}
	return explainBuffers(t, d, label, stmt.SQL.String(), stmt.Vars...)
}

func explainBuffers(t *testing.T, d *Database, label, sql string, vars ...interface{}) int64 {
	t.Helper()
	var raw string
	if err := d.pgxPool.QueryRow(context.Background(), "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+sql, vars...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN ANALYZE %s: %v", label, err)
	}
	var top []struct {
		Plan struct {
			Hit  int64 `json:"Shared Hit Blocks"`
			Read int64 `json:"Shared Read Blocks"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &top); err != nil || len(top) != 1 {
		t.Fatalf("EXPLAIN ANALYZE %s JSON: %v", label, err)
	}
	return top[0].Plan.Hit + top[0].Plan.Read
}

// heapPages is the table's heap size in pages (every leaf when partitioned).
func heapPages(t *testing.T, d *Database, table string) int64 {
	t.Helper()
	var n int64
	if err := d.db.Raw(`SELECT COALESCE(sum(relpages), 0) FROM pg_class WHERE relname = ?
		OR oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = ?::regclass)`, table, table).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatalf("%s has no pages: seed and VACUUM ANALYZE it first", table)
	}
	return n
}

func dryRun(d *Database) *gorm.DB { return d.db.Session(&gorm.Session{DryRun: true}) }

// archiveFastSettle stands in a writer statement_timeout for the test (the
// integration DSN runs without one, which the archive refuses) and shrinks the
// settle window to timeout + margin.
func archiveFastSettle(t *testing.T, timeout, margin time.Duration) {
	t.Helper()
	ot, of, om := archiveWriterStatementTimeout, archiveSettleFloor, archiveSettleMargin
	archiveWriterStatementTimeout = func(context.Context, *Database) (time.Duration, error) { return timeout, nil }
	archiveSettleFloor, archiveSettleMargin = 0, margin
	t.Cleanup(func() { archiveWriterStatementTimeout, archiveSettleFloor, archiveSettleMargin = ot, of, om })
}

// waitSettled polls ArchiveChunkSettled until it clears (or fails the test).
func waitSettled(t *testing.T, d *Database, c *models.ArchiveChunk, within time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := d.ArchiveChunkSettled(context.Background(), c)
		if err == nil {
			return time.Now()
		}
		var un *ArchiveUnsettledError
		if !errors.As(err, &un) || time.Now().After(deadline) {
			t.Fatalf("chunk %d not settled: %v", c.Seq, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// archiveSeedSyslog inserts n rows whose created_at runs evenly from base over
// span (ids rise with created_at), message times 30 s earlier.
func archiveSeedSyslog(t *testing.T, d *Database, base time.Time, span time.Duration, n int) {
	t.Helper()
	step := float64(span.Microseconds()) / float64(n)
	if err := d.db.Exec(`INSERT INTO syslog_messages ("timestamp", device_id, probe_id, hostname, app_name, process_id,
			message_id, structured_data, message, priority, facility, severity, source_ip, created_at, format)
		SELECT c - interval '30 seconds', 1 + g % 3, 1, 'fw-example-0' || (1 + g % 3), 'traffic', '-', '0000000013', '',
			'date=2026-10-04 devname="fw-example-0' || (1 + g % 3) || '" srcip=192.0.2.' || (g % 250) ||
			' dstip=198.51.100.7 dstport=443 action="accept" user="alice" sentbyte=' || g, 189, 23, 5, '203.0.113.4', c,
			CASE WHEN g % 2 = 0 THEN 1 END
		FROM (SELECT g, ?::timestamptz + make_interval(secs => g * ?::float8 / 1e6) AS c FROM generate_series(0, ?::int - 1) g) s`,
		base, step, n).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Exec("VACUUM ANALYZE syslog_messages").Error; err != nil {
		t.Fatal(err)
	}
}

// TestArchiveSyslog_PG plans every due day of a 30-day syslog_messages in both
// shapes, checks each cut against created_at, EXPLAINs the page, probe, count
// and max(id) statements at density, and exports one day: the content hash
// is the same in both shapes and on a re-export.
func TestArchiveSyslog_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	archiveFastSettle(t, 100*time.Millisecond, 100*time.Millisecond)
	if !pgIsPartitioned(t, d, "syslog_messages") {
		t.Fatal("syslog_messages is not partitioned on the fresh-install path")
	}
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const days, perDay = 30, 15000
	now := time.Now().UTC().Truncate(time.Second)
	base := archivePeriodStart(now, 24*time.Hour).AddDate(0, 0, -days)
	hashes := map[string]string{}

	for _, shape := range []string{"partitioned (fresh install)", "plain heap (production)"} {
		t.Run(shape, func(t *testing.T) {
			if strings.HasPrefix(shape, "plain") {
				if err := d.db.Exec(`DROP TABLE syslog_messages CASCADE`).Error; err != nil {
					t.Fatal(err)
				}
				if err := d.db.Migrator().CreateTable(&models.SyslogMessage{}); err != nil {
					t.Fatal(err)
				}
				if pgIsPartitioned(t, d, "syslog_messages") {
					t.Fatal("the recreated syslog_messages is partitioned")
				}
			}
			if err := d.db.Exec("DELETE FROM archive_chunks").Error; err != nil {
				t.Fatal(err)
			}
			archiveSeedSyslog(t, d, base, days*24*time.Hour, days*perDay)

			start := time.Now()
			chunks := planAll(t, d, export.TableSyslog, now)
			t.Logf("%s: planned %d daily chunks in %s", shape, len(chunks), time.Since(start))
			if len(chunks) < days-1 {
				t.Fatalf("%d chunks over %d days", len(chunks), days)
			}
			prev := int64(0)
			for _, c := range chunks {
				var r struct {
					N     int64
					MaxID *int64
				}
				if err := d.db.Raw(`SELECT count(*) AS n, max(id) AS max_id FROM syslog_messages WHERE created_at >= ? AND created_at < ?`,
					c.PeriodStart, c.PeriodEnd).Scan(&r).Error; err != nil {
					t.Fatal(err)
				}
				var inRange int64
				d.db.Raw(`SELECT count(*) FROM syslog_messages WHERE id > ? AND id <= ?`, c.IDLo, c.IDHi).Scan(&inRange)
				if c.IDLo != prev || inRange != r.N || (r.MaxID != nil && *r.MaxID != c.IDHi) || c.Month != export.MonthOf(c.PeriodStart) {
					t.Fatalf("chunk %d [%s): (%d, %d] holds %d rows; the day has %d (max id %v); previous ended at %d",
						c.Seq, c.PeriodStart.Format(time.DateOnly), c.IDLo, c.IDHi, inRange, r.N, r.MaxID, prev)
				}
				prev = c.IDHi
			}

			// Plans at density, for a chunk in the middle of the table.
			mid := chunks[len(chunks)/2]
			pages := heapPages(t, d, "syslog_messages")
			bufs := map[string]int64{
				"page":  archivePlanBuffers(t, d, shape+" page", archivePageQuery(dryRun(d), export.TableSyslog, mid.IDLo+perDay/3, mid.IDHi, archivePageSize).Find(&[]models.SyslogMessage{}).Statement),
				"probe": archivePlanBuffers(t, d, shape+" probe", archiveSyslogProbeQuery(dryRun(d), mid.IDLo+perDay/2).Find(&[]archiveRowProbe{}).Statement),
				"count": archivePlanBuffers(t, d, shape+" count", archiveCountQuery(dryRun(d), export.TableSyslog, mid.IDLo, mid.IDHi).Find(&[]int64{}).Statement),
				"max":   explainBuffers(t, d, "max", "SELECT COALESCE(max(id), 0) AS max_id, clock_timestamp() AS taken_at FROM syslog_messages"),
			}
			// A 5 000-row page is ~200 heap pages; a probe and max(id) a few
			// index descents; the day's count an index-only range. None may
			// come near the table (here ~15 000 pages; production ~20 M).
			limits := map[string]int64{"page": pages / 20, "probe": 40, "count": pages / 50, "max": 40}
			for k, n := range bufs {
				t.Logf("%s: %s read %d buffers (table %d pages)", shape, k, n, pages)
				if n > limits[k] {
					t.Errorf("%s: the %s statement read %d buffers, limit %d (table %d pages)", shape, k, n, limits[k], pages)
				}
			}

			// Export the middle day twice; the page size must not matter.
			waitSettled(t, d, &mid, 10*time.Second)
			exp := func(page int) *export.ChunkResult {
				res, err := d.ExportArchiveChunk(ctx, &mid, export.SyslogSchemaV2, ArchiveReadOptions{PageSize: page}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
				if err != nil {
					t.Fatal(err)
				}
				return res
			}
			start = time.Now()
			a := exp(archivePageSize)
			t.Logf("%s: exported %d rows in %s", shape, a.Rows, time.Since(start))
			b := exp(1777)
			if a.Rows != mid.IDHi-mid.IDLo || len(a.Objects) != 3 {
				t.Fatalf("exported %d rows in %d objects, range holds %d", a.Rows, len(a.Objects), mid.IDHi-mid.IDLo)
			}
			var sum strings.Builder
			for i := range a.Objects {
				if a.Objects[i].Sha256Content != b.Objects[i].Sha256Content || a.Objects[i].Sha256Object != b.Objects[i].Sha256Object {
					t.Fatalf("re-export of object %d is not byte-identical", i)
				}
				sum.WriteString(a.Objects[i].Sha256Content)
			}
			hashes[shape] = sum.String()
			if chk, err := d.CheckArchiveChunkCount(ctx, &mid, a); err != nil || !chk.Verifiable() {
				t.Fatalf("count check %+v %v", chk, err)
			}
		})
	}
	if len(hashes) != 2 || hashes["partitioned (fresh install)"] != hashes["plain heap (production)"] {
		t.Fatalf("the same rows exported differently from the two shapes: %v", hashes)
	}
}

// archiveSeedFlows inserts n flow_samples rows (flow_source g % 4) sampled at ts.
func archiveSeedFlows(t *testing.T, d *Database, ts time.Time, n int) {
	t.Helper()
	if err := d.db.Exec(`INSERT INTO flow_samples ("timestamp", device_id, probe_id, sampler_address, src_addr, dst_addr,
			src_port, dst_port, protocol, bytes, packets, flow_source, created_at)
		SELECT ?::timestamptz, 1 + g % 3, 1, '192.0.2.1', '192.0.2.' || (g % 250), '198.51.100.' || (g % 200),
			1024 + g % 60000, 443, 6, 1500, 1, g % 4, now()
		FROM generate_series(0, ? - 1) g`, ts, n).Error; err != nil {
		t.Fatal(err)
	}
}

// TestArchiveFlows_PG: hourly flow chunks at production density (~160k
// rows an hour) in both shapes, cut at id marks, split into sflow and netflow
// by flow_source; the page and max(id) plans read the primary key. Then the
// counters: daily marks and a plain-table page plan.
func TestArchiveFlows_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	archiveFastSettle(t, 100*time.Millisecond, 100*time.Millisecond)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const perHour = 160000
	h0 := archivePeriodStart(time.Now(), time.Hour).Add(-3 * time.Hour)

	for _, shape := range []string{"partitioned (fresh install)", "plain heap"} {
		t.Run(shape, func(t *testing.T) {
			if strings.HasPrefix(shape, "plain") {
				if err := d.db.Exec(`DROP TABLE flow_samples CASCADE`).Error; err != nil {
					t.Fatal(err)
				}
				if err := d.db.Migrator().CreateTable(&models.FlowSample{}); err != nil {
					t.Fatal(err)
				}
			} else if !pgIsPartitioned(t, d, "flow_samples") {
				t.Fatal("flow_samples is not partitioned on the fresh-install path")
			}
			if err := d.db.Exec("DELETE FROM archive_chunks; DELETE FROM archive_id_marks").Error; err != nil {
				t.Fatal(err)
			}
			// The worker's ticks, with the hour's rows arriving between them.
			for i := 0; i < 3; i++ {
				archiveSeedFlows(t, d, h0.Add(time.Duration(i)*time.Hour+30*time.Minute), perHour)
				if _, err := d.TakeArchiveIDMarks(ctx, export.TableFlows, h0.Add(time.Duration(i+1)*time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.db.Exec("VACUUM ANALYZE flow_samples").Error; err != nil {
				t.Fatal(err)
			}
			chunks := planAll(t, d, export.TableFlows, h0.Add(3*time.Hour+10*time.Minute))
			if len(chunks) != 3 {
				t.Fatalf("%d flow chunks, want 3", len(chunks))
			}
			for _, c := range chunks {
				if c.IDHi-c.IDLo != perHour || c.MarkLateByMs == nil {
					t.Fatalf("chunk %d (%d, %d] late %v: want %d rows", c.Seq, c.IDLo, c.IDHi, c.MarkLateByMs, perHour)
				}
			}
			mid := chunks[1]
			pages := heapPages(t, d, "flow_samples")
			page := archivePlanBuffers(t, d, shape+" flow page", archivePageQuery(dryRun(d), export.TableFlows, mid.IDLo+perHour/2, mid.IDHi, archivePageSize).Find(&[]models.FlowSample{}).Statement)
			maxb := explainBuffers(t, d, "flow max", "SELECT COALESCE(max(id), 0) AS max_id, clock_timestamp() AS taken_at FROM flow_samples")
			t.Logf("%s: page read %d buffers, max(id) %d (table %d pages)", shape, page, maxb, pages)
			if page > pages/20 || maxb > 40 {
				t.Errorf("%s: page %d / max %d buffers over the limit (table %d pages)", shape, page, maxb, pages)
			}
			waitSettled(t, d, &mid, 10*time.Second)
			start := time.Now()
			res, err := d.ExportArchiveChunk(ctx, &mid, export.FlowSchemaV1, ArchiveReadOptions{}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: exported one hour (%d rows) in %s: %d / %d bytes", shape, res.Rows, time.Since(start), res.Objects[0].ObjectBytes, res.Objects[1].ObjectBytes)
			if res.Rows != perHour || len(res.Objects) != 2 || res.Objects[0].ID.Stream != export.StreamNetFlow ||
				res.Objects[0].Rows != perHour*3/4 || res.Objects[1].Rows != perHour/4 {
				t.Fatalf("flow export: %d rows, objects %+v", res.Rows, res.Objects)
			}
		})
	}

	t.Run("counters", func(t *testing.T) {
		if err := d.db.Exec(`INSERT INTO flow_if_counters ("timestamp", device_id, probe_id, sampler_address, if_index, if_speed, in_octets, out_octets, created_at)
			SELECT now() - make_interval(secs => g), 1 + g % 3, 1, '192.0.2.1', g % 48, 1000000000, g * 1000, g * 900, now()
			FROM generate_series(0, 199999) g`).Error; err != nil {
			t.Fatal(err)
		}
		day := archivePeriodStart(time.Now(), 24*time.Hour)
		if _, err := d.TakeArchiveIDMarks(ctx, export.TableCounters, day); err != nil {
			t.Fatal(err)
		}
		if err := d.db.Exec("VACUUM ANALYZE flow_if_counters").Error; err != nil {
			t.Fatal(err)
		}
		chunks := planAll(t, d, export.TableCounters, day.Add(3*time.Hour))
		if len(chunks) != 1 || chunks[0].IDHi != 200000 {
			t.Fatalf("counter chunks %+v", chunks)
		}
		pages := heapPages(t, d, "flow_if_counters")
		page := archivePlanBuffers(t, d, "counter page", archivePageQuery(dryRun(d), export.TableCounters, 100000, 200000, archivePageSize).Find(&[]models.FlowInterfaceCounter{}).Statement)
		if page > pages/20 {
			t.Errorf("counter page read %d buffers (table %d pages)", page, pages)
		}
	})
}

// TestArchiveSettleGuard_PG: the export of a chunk waits for every WRITING
// transaction that may hold rows in its range — one that inserted a row
// before the cut and is still open — and for nothing else: a long read-only
// REPEATABLE READ transaction (what pg_dump holds for hours) opened before
// everything never blocks. Syslog, and a flow chunk cut at a mark taken while
// the writer was open.
func TestArchiveSettleGuard_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	archiveFastSettle(t, 200*time.Millisecond, 100*time.Millisecond)
	ctx := context.Background()
	now := time.Now().UTC()

	// The pg_dump-like reader, open across the whole test.
	rconn, err := d.pgxPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rconn.Release()
	rtx, err := rconn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rtx.Rollback(ctx) }()
	var seen int64
	if err := rtx.QueryRow(ctx, `SELECT count(*) FROM syslog_messages`).Scan(&seen); err != nil {
		t.Fatal(err)
	}

	// The writer: one syslog row and one flow row, uncommitted.
	wconn, err := d.pgxPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer wconn.Release()
	wtx, err := wconn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wtx.Rollback(ctx) }()
	var heldID, heldFlow int64
	if err := wtx.QueryRow(ctx, `INSERT INTO syslog_messages ("timestamp", device_id, message, severity, created_at)
		VALUES (now(), 1, 'held srcip=192.0.2.9', 5, now()) RETURNING id`).Scan(&heldID); err != nil {
		t.Fatal(err)
	}
	if err := wtx.QueryRow(ctx, `INSERT INTO flow_samples ("timestamp", device_id, src_addr, dst_addr, flow_source, created_at)
		VALUES (now(), 1, '192.0.2.9', '198.51.100.9', 1, now()) RETURNING id`).Scan(&heldFlow); err != nil {
		t.Fatal(err)
	}
	// A younger writer (its xid after the first one's), open too: the holder
	// named must be the OLDEST.
	yconn, err := d.pgxPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer yconn.Release()
	ytx, err := yconn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ytx.Rollback(ctx) }()
	if _, err := ytx.Exec(ctx, `INSERT INTO system_settings (key, value, type) VALUES ('archive_test_younger_writer', '1', 'string')`); err != nil {
		t.Fatal(err)
	}
	// Later rows commit first, with higher ids.
	archiveSeedSyslog(t, d, now.Add(-time.Second), time.Second, 50)
	archiveSeedFlows(t, d, now, 10)

	tomorrow := archivePeriodStart(now, 24*time.Hour).Add(27 * time.Hour)
	sys, err := d.PlanNextArchiveChunk(ctx, export.TableSyslog, tomorrow, 0)
	if err != nil || sys == nil || heldID > sys.IDHi || sys.GuardXmax != nil {
		t.Fatalf("syslog plan with a writer open = %+v, %v: want a chunk covering id %d, guard not yet taken", sys, err, heldID)
	}
	hour := archivePeriodStart(now, time.Hour)
	for _, b := range []time.Time{hour, hour.Add(time.Hour)} {
		if _, err := d.TakeArchiveIDMarks(ctx, export.TableFlows, b); err != nil {
			t.Fatal(err)
		}
	}
	flow, err := d.PlanNextArchiveChunk(ctx, export.TableFlows, hour.Add(2*time.Hour), 0)
	if err != nil || flow == nil || heldFlow > flow.IDHi {
		t.Fatalf("flow plan = %+v, %v: want a chunk covering id %d", flow, err, heldFlow)
	}

	exportOf := func(c *models.ArchiveChunk, schema int) (*export.ChunkResult, error) {
		return d.ExportArchiveChunk(ctx, c, schema, ArchiveReadOptions{}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
	}
	var un *ArchiveUnsettledError
	// Inside the settle window: refused without a guard.
	if _, err := exportOf(sys, export.SyslogSchemaV2); !errors.As(err, &un) || un.SettleLeft <= 0 {
		t.Fatalf("export inside the settle window = %v, want SettleLeft", err)
	}
	time.Sleep(400 * time.Millisecond)
	for _, c := range []struct {
		c      *models.ArchiveChunk
		schema int
	}{{sys, export.SyslogSchemaV2}, {flow, export.FlowSchemaV1}} {
		_, err := exportOf(c.c, c.schema)
		if !errors.As(err, &un) || un.SettleLeft > 0 || un.Xmin >= un.GuardXmax || c.c.GuardXmax == nil {
			t.Fatalf("%s export with the writer open = %v, want ArchiveUnsettledError on the writer", c.c.SourceTable, err)
		}
		if un.Holder == nil || un.Holder.PID != int64(wconn.Conn().PgConn().PID()) || un.Holder.State != "idle in transaction" {
			t.Fatalf("%s: holder %+v, want the writer's pid %d idle in transaction", c.c.SourceTable, un.Holder, wconn.Conn().PgConn().PID())
		}
	}
	t.Logf("unsettled: %v", un)

	if err := wtx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ytx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// The reader is still open: it must not block.
	for _, c := range []struct {
		c      *models.ArchiveChunk
		schema int
	}{{sys, export.SyslogSchemaV2}, {flow, export.FlowSchemaV1}} {
		res, err := exportOf(c.c, c.schema)
		if err != nil {
			t.Fatalf("%s export after the commit, with a read-only transaction open: %v", c.c.SourceTable, err)
		}
		if chk, _ := d.CheckArchiveChunkCount(ctx, c.c, res); !chk.Verifiable() {
			t.Fatalf("%s: %+v", c.c.SourceTable, chk)
		}
	}
	if err := rtx.QueryRow(ctx, `SELECT count(*) FROM syslog_messages`).Scan(&seen); err != nil || seen != 0 {
		t.Fatalf("the reader's snapshot moved (%d, %v): it was not the long transaction this test needs", seen, err)
	}
}

// TestArchiveSettle_StalledCopy_PG: a pgx-style COPY into flow_samples that has
// reserved ids (nextval, between two of the sequence's WAL logs) but stalls
// before its first flush has no transaction id yet — a guard snapshot taken then would not wait for it. The chunk cut at
// a mark taken during the stall must not settle until statement_timeout (+
// margin) after the cut, by which time the COPY has an xid, failed or
// committed; here it commits after 1.5 s (longer than the old 1 s settle) and
// the export holds its rows.
func TestArchiveSettle_StalledCopy_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	const stmtTimeout = 2 * time.Second
	archiveFastSettle(t, stmtTimeout, 500*time.Millisecond)
	ctx := context.Background()
	now := time.Now().UTC()

	conn, err := d.pgxPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, fmt.Sprintf("SET statement_timeout = '%dms'", stmtTimeout.Milliseconds())); err != nil {
		t.Fatal(err)
	}
	// nextval WAL-logs (and so takes an xid) once per 32 values; one call in
	// its own transaction first leaves the next 31 unlogged, which is the
	// common case the COPY below hits: ids reserved, no xid.
	if err := d.db.Exec(`SELECT nextval(pg_get_serial_sequence('flow_samples', 'id'))`).Error; err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	copyDone := make(chan error, 1)
	go func() {
		_, err := conn.Conn().PgConn().CopyFrom(ctx, pr, `COPY flow_samples ("timestamp", device_id, src_addr, dst_addr, flow_source, created_at) FROM STDIN`)
		copyDone <- err
	}()
	ts := now.Format(time.RFC3339Nano)
	for i := 0; i < 5; i++ {
		if _, err := fmt.Fprintf(pw, "%s\t1\t192.0.2.%d\t198.51.100.7\t0\t%s\n", ts, 10+i, ts); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond) // the server has parsed the rows: ids reserved, no xid
	var st struct {
		Xid   *string
		Query string
	}
	if err := d.db.Raw(`SELECT backend_xid::text AS xid, query FROM pg_stat_activity WHERE pid = ?`, conn.Conn().PgConn().PID()).Scan(&st).Error; err != nil ||
		st.Xid != nil || !strings.HasPrefix(st.Query, "COPY") {
		t.Fatalf("the stalled COPY: %+v (%v): want it running without an xid — the fixture does not reproduce the gap", st, err)
	}
	archiveSeedFlows(t, d, now, 10) // committed, higher ids
	hour := archivePeriodStart(now, time.Hour)
	for _, b := range []time.Time{hour, hour.Add(time.Hour)} {
		if _, err := d.TakeArchiveIDMarks(ctx, export.TableFlows, b); err != nil {
			t.Fatal(err)
		}
	}
	chunk, err := d.PlanNextArchiveChunk(ctx, export.TableFlows, hour.Add(2*time.Hour), 0)
	if err != nil || chunk == nil {
		t.Fatalf("plan: %+v %v", chunk, err)
	}
	cut := time.Now()
	// The COPY finishes 1.5 s after the cut, inside its statement_timeout.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = pw.Close()
	}()
	settled := waitSettled(t, d, chunk, 10*time.Second)
	if err := <-copyDone; err != nil {
		t.Fatalf("COPY: %v", err)
	}
	t.Logf("settled %s after the cut", settled.Sub(cut).Round(10*time.Millisecond))
	res, err := d.ExportArchiveChunk(ctx, chunk, export.FlowSchemaV1, ArchiveReadOptions{}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	chk, err := d.CheckArchiveChunkCount(ctx, chunk, res)
	if err != nil || !chk.Verifiable() || res.Rows != 15 {
		t.Fatalf("export of %d rows; table now %+v (%v): the stalled COPY's rows were missed", res.Rows, chk, err)
	}
}

// TestArchiveSettle_StatementTimeout_PG: the settle window comes from the
// session's statement_timeout (the DSN's): max(1 min, timeout + 5 s); none
// (0) refuses planning and exports.
func TestArchiveSettle_StatementTimeout_PG(t *testing.T) {
	d := NewIntegrationDB(t) // the integration DSN sets no statement_timeout
	ctx := context.Background()
	if _, err := d.PlanNextArchiveChunk(ctx, export.TableSyslog, time.Now(), 0); !errors.Is(err, ErrArchiveNoStatementTimeout) {
		t.Fatalf("plan with statement_timeout 0 = %v", err)
	}
	if err := d.ArchiveChunkSettled(ctx, &models.ArchiveChunk{CutAt: time.Now().Add(-time.Hour)}); !errors.Is(err, ErrArchiveNoStatementTimeout) {
		t.Fatalf("settle with statement_timeout 0 = %v", err)
	}
	for _, c := range []struct{ timeout, want time.Duration }{{30 * time.Second, time.Minute}, {90 * time.Second, 95 * time.Second}} {
		cfg := integrationCfgFromDSN(t, os.Getenv("TEST_PG_DSN"))
		cfg.Database.StatementTimeout = c.timeout
		d2, err := Connect(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := d2.archiveSettle(ctx)
		_ = d2.Close()
		if err != nil || got != c.want {
			t.Fatalf("statement_timeout %s: settle %s (%v), want %s", c.timeout, got, err, c.want)
		}
	}
}
