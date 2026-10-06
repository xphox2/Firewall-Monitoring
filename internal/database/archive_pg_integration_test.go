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
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

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
			if n, v, err := d.CheckArchiveChunkCount(ctx, &mid, a.Rows); err != nil || v != ArchiveCountMatch {
				t.Fatalf("count check %d %s %v", n, v, err)
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

// TestArchiveLateCommitGuard_PG: while another session of the same role holds
// a transaction that inserted a row into the range, the cut is refused (its
// xact_start is visible: one role for every component); once it commits the
// cut is taken and the export holds the row. Same for a flow chunk cut at a
// mark taken while the transaction was open.
func TestArchiveLateCommitGuard_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()

	conn, err := d.pgxPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var heldID int64
	if err := tx.QueryRow(ctx, `INSERT INTO syslog_messages ("timestamp", device_id, message, severity, created_at)
		VALUES (now(), 1, 'held srcip=192.0.2.9', 5, now()) RETURNING id`).Scan(&heldID); err != nil {
		t.Fatal(err)
	}
	// Later rows commit first, with higher ids.
	archiveSeedSyslog(t, d, now.Add(-time.Second), time.Second, 50)

	tomorrow := archivePeriodStart(now, 24*time.Hour).Add(27 * time.Hour)
	_, err = d.PlanNextArchiveChunk(ctx, export.TableSyslog, tomorrow, 0)
	var lc *ArchiveLateCommitError
	if !errors.As(err, &lc) || lc.Open < 1 || lc.Oldest == nil || lc.Hidden != 0 {
		t.Fatalf("plan with a held transaction = %v (%+v), want ArchiveLateCommitError with the open transaction visible", err, lc)
	}
	var n int64
	d.db.Model(&models.ArchiveChunk{}).Count(&n)
	if n != 0 {
		t.Fatal("a chunk was recorded while the guard refused")
	}

	// The flow side: a mark taken while a flow insert is open.
	var heldFlow int64
	if err := tx.QueryRow(ctx, `INSERT INTO flow_samples ("timestamp", device_id, src_addr, dst_addr, flow_source, created_at)
		VALUES (now(), 1, '192.0.2.9', '198.51.100.9', 1, now()) RETURNING id`).Scan(&heldFlow); err != nil {
		t.Fatal(err)
	}
	archiveSeedFlows(t, d, now, 10)
	hour := archivePeriodStart(now, time.Hour)
	if _, err := d.TakeArchiveIDMarks(ctx, export.TableFlows, hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.TakeArchiveIDMarks(ctx, export.TableFlows, hour.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PlanNextArchiveChunk(ctx, export.TableFlows, hour.Add(2*time.Hour), 0); !errors.As(err, &lc) {
		t.Fatalf("flow plan with a held transaction = %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		table string
		held  int64
	}{{export.TableSyslog, heldID}, {export.TableFlows, heldFlow}} {
		var chunks []models.ArchiveChunk
		at := tomorrow
		if c.table == export.TableFlows {
			at = hour.Add(2 * time.Hour)
		}
		chunks = planAll(t, d, c.table, at)
		found := false
		for i := range chunks {
			if c.held <= chunks[i].IDLo || c.held > chunks[i].IDHi {
				continue
			}
			res, err := d.ExportArchiveChunk(ctx, &chunks[i], map[string]int{export.TableSyslog: export.SyslogSchemaV2, export.TableFlows: export.FlowSchemaV1}[c.table],
				ArchiveReadOptions{}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
			if err != nil {
				t.Fatal(err)
			}
			if got, v, _ := d.CheckArchiveChunkCount(ctx, &chunks[i], res.Rows); v != ArchiveCountMatch {
				t.Fatalf("%s: export of %d rows vs %d in the table (%s)", c.table, res.Rows, got, v)
			}
			found = true
		}
		if !found {
			t.Fatalf("%s: the committed row %d is in no chunk: %+v", c.table, c.held, chunks)
		}
	}
}
