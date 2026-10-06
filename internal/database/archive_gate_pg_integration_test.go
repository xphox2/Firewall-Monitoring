//go:build integration

// The archive's verified-id retention gate (archive plan PR 5) on a real
// PostgreSQL, in both shapes of the raw tables: the plain heap production
// runs (syslog_messages ~161 GB, flow_samples) and the partitioned parent of a
// fresh install (monthly leaves, a DEFAULT child). Seeded at density, so the
// plans of the gated statements are the plans production gets: the added
// `id <= V` must not turn a retention batch, an aggregation probe or the
// rollup into a sequential scan. Synthetic data only (RFC 5737,
// fw-example-NN).
package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// gatePGVerified replaces table's chunks with one verified chunk (0, v],
// with the row count and latest timestamp a verification records.
func gatePGVerified(t *testing.T, d *Database, table string, v int64) {
	t.Helper()
	if err := d.db.Exec("DELETE FROM archive_chunks WHERE table_name = ?", table).Error; err != nil {
		t.Fatal(err)
	}
	var r struct {
		N     int64
		MaxTs *time.Time
	}
	if err := d.db.Raw(fmt.Sprintf(`SELECT count(*) AS n, max("timestamp") AS max_ts FROM %s WHERE id <= ?`, table), v).Scan(&r).Error; err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := d.db.Create(&models.ArchiveChunk{SourceTable: table, Seq: 1, IDLo: 0, IDHi: v, PeriodStart: start,
		PeriodEnd: start.Add(24 * time.Hour), Month: "2026-01", Status: models.ArchiveChunkVerified, RowCount: r.N, MaxTs: r.MaxTs}).Error; err != nil {
		t.Fatal(err)
	}
}

func gatePGCount(t *testing.T, d *Database, q string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := d.db.Raw(q, args...).Scan(&n).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// gatePGLeaves lists the monthly leaves of table (not the DEFAULT child).
func gatePGLeaves(t *testing.T, d *Database, table string) map[string]bool {
	t.Helper()
	var names []string
	if err := d.db.Raw(`SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = ?::regclass AND c.relname <> ?`, table, table+"_default").Scan(&names).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

// gatePGMonthLeaf creates table's leaf for the UTC month starting at m (with
// the leaf index plan EnsurePartitions gives its own leaves) unless it exists.
func gatePGMonthLeaf(t *testing.T, d *Database, table string, m time.Time) string {
	t.Helper()
	name := fmt.Sprintf("%s_%s", table, m.Format("200601"))
	if gatePGLeaves(t, d, table)[name] {
		return name
	}
	if err := d.db.Exec(fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`, name, table,
		m.Format("2006-01-02 15:04:05-07"), m.AddDate(0, 1, 0).Format("2006-01-02 15:04:05-07"))).Error; err != nil {
		t.Fatal(err)
	}
	plan, err := partitionIndexPlan(partitionDef{table, "timestamp"})
	if err != nil {
		t.Fatal(err)
	}
	d.ensureLeafIndexes(name, plan)
	return name
}

// gatePGSeedSyslog inserts n rows evenly from `from` to `to` (ids rise with
// the timestamp), every sixth one severity 6, the rest severity 5.
func gatePGSeedSyslog(t *testing.T, d *Database, from, to time.Time, n int) {
	t.Helper()
	step := float64(to.Sub(from).Microseconds()) / float64(n)
	if err := d.db.Exec(`INSERT INTO syslog_messages ("timestamp", device_id, probe_id, hostname, app_name, process_id,
			message_id, structured_data, message, priority, facility, severity, source_ip, created_at)
		SELECT c, 1 + g % 3, 1, 'fw-example-0' || (1 + g % 3), 'traffic', '-', '0000000013', '',
			'devname="fw-example-0' || (1 + g % 3) || '" srcip=192.0.2.' || (g % 250) || ' dstip=198.51.100.7 action="accept" user="alice"',
			189, 23, CASE WHEN g % 6 = 0 THEN 6 ELSE 5 END, '203.0.113.4', c + interval '30 seconds'
		FROM (SELECT g, ?::timestamptz + make_interval(secs => g * ?::float8 / 1e6) AS c FROM generate_series(0, ?::int - 1) g) s`,
		from, step, n).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Exec("VACUUM ANALYZE syslog_messages").Error; err != nil {
		t.Fatal(err)
	}
}

// gatePlan EXPLAINs a statement as the code sends it — failing on any Seq
// Scan that costs more than zero (assertBackfillPlan) — and returns the
// shared buffers it reads under EXPLAIN (ANALYZE, BUFFERS).
func gatePlan(t *testing.T, d *Database, label, sql string, vars ...interface{}) int64 {
	t.Helper()
	st := &gorm.Statement{Vars: vars}
	st.SQL.WriteString(sql)
	assertBackfillPlan(t, d, label, st)
	return explainBuffers(t, d, label, sql, vars...)
}

// TestArchiveGate_Syslog_PG: 130 days of syslog_messages (650 000 rows) in
// both shapes, V in the middle of an expired month. The aggregation and the
// daily retention pass delete exactly the rows at or below V; the partitioned
// shape drops the expired leaf wholly below V, keeps the one V cuts, and the
// DEFAULT child's rows are row-deleted. Then V covers everything and the next
// pass takes the rest. On the way, the gated statements' plans at density.
func TestArchiveGate_Syslog_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true, Flows: true}
	ret := config.RetentionConfig{DefaultDays: 30, SyslogCriticalDays: 30, SyslogInfoDays: 7, FlowDays: 30}
	now := time.Now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	for _, shape := range []string{"partitioned (fresh install)", "plain heap (production)"} {
		t.Run(shape, func(t *testing.T) {
			partitioned := !strings.HasPrefix(shape, "plain")
			if !partitioned {
				if err := d.db.Exec(`DROP TABLE syslog_messages CASCADE`).Error; err != nil {
					t.Fatal(err)
				}
				if err := d.db.Migrator().CreateTable(&models.SyslogMessage{}); err != nil {
					t.Fatal(err)
				}
			} else if !pgIsPartitioned(t, d, "syslog_messages") {
				t.Fatal("syslog_messages is not partitioned on the fresh-install path")
			}
			// Months M-4 .. M-1 get leaves; anything older lands in the
			// DEFAULT child. M-4 and M-3 always end before now - 30 days.
			var older, cut string
			if partitioned {
				for k := 4; k >= 1; k-- {
					name := gatePGMonthLeaf(t, d, "syslog_messages", month.AddDate(0, -k, 0))
					switch k {
					case 4:
						older = name
					case 3:
						cut = name
					}
				}
			}
			gatePGSeedSyslog(t, d, now.AddDate(0, 0, -130), now, 650000)
			total := gatePGCount(t, d, "SELECT count(*) FROM syslog_messages")

			// V: the middle of month M-3 (older than every retention cutoff).
			m3 := month.AddDate(0, -3, 0)
			var v int64
			if err := d.db.Raw(`SELECT max(id) FROM syslog_messages WHERE "timestamp" < ?`, m3.AddDate(0, 0, 15)).Scan(&v).Error; err != nil || v == 0 {
				t.Fatalf("V: %d %v", v, err)
			}
			gatePGVerified(t, d, export.TableSyslog, v)
			above := gatePGCount(t, d, "SELECT count(*) FROM syslog_messages WHERE id > ?", v)
			if partitioned && (gatePGCount(t, d, "SELECT count(*) FROM syslog_messages_default") == 0 ||
				gatePGCount(t, d, fmt.Sprintf("SELECT count(*) FROM %s", older)) == 0) {
				t.Fatal("the fixture must put rows in the DEFAULT child and in month M-4")
			}

			// Plans at density, gated exactly as the code builds them.
			g := d.archiveGate(ctx, export.TableSyslog)
			if !g.on || g.v != v {
				t.Fatalf("gate %+v, want on with V %d", g, v)
			}
			cutoff := now.AddDate(0, 0, -30)
			where, args := g.andID("severity IN ?", []interface{}{[]int{0, 1, 2, 3, 4, 5}})
			gated := retentionBatchQuery(dryRun(d), &models.SyslogMessage{}, "timestamp", "timestamp", cutoff, where, args, cleanupDeleteBatchSize).
				Find(&[]int64{}).Statement
			ungated := retentionBatchQuery(dryRun(d), &models.SyslogMessage{}, "timestamp", "timestamp", cutoff, "severity IN ?",
				[]interface{}{[]int{0, 1, 2, 3, 4, 5}}, cleanupDeleteBatchSize).Find(&[]int64{}).Statement
			bGated := gatePlan(t, d, shape+" retention batch (gated)", gated.SQL.String(), gated.Vars...)
			bUngated := gatePlan(t, d, shape+" retention batch (ungated)", ungated.SQL.String(), ungated.Vars...)
			aggStart := `SELECT MIN(timestamp) FROM "syslog_messages" WHERE severity = $1 AND timestamp < $2 AND id <= $3`
			aggCutoff := g.capCutoff(now.AddDate(0, 0, -7))
			if !aggCutoff.Before(now.AddDate(0, 0, -30)) {
				t.Fatalf("aggregation cutoff %s not capped below V's latest timestamp", aggCutoff)
			}
			bAgg := gatePlan(t, d, shape+" aggregation start (gated)", aggStart, 6, aggCutoff, v)
			t.Logf("%s: heap %d pages; first retention batch %d buffers gated / %d ungated; aggregation start %d",
				shape, heapPages(t, d, "syslog_messages"), bGated, bUngated, bAgg)
			if bGated > 2*bUngated+100 {
				t.Errorf("the gated retention batch reads %d buffers against %d ungated", bGated, bUngated)
			}

			// The rollup tick (aggregation) and the daily pass, gated.
			if err := d.RunSyslogAggregationCycle(ret); err != nil {
				t.Fatal(err)
			}
			if err := d.CleanupOldData(ret); err != nil {
				t.Fatal(err)
			}
			if n := gatePGCount(t, d, "SELECT count(*) FROM syslog_messages WHERE id > ?", v); n != above {
				t.Fatalf("%d rows above V left, want all %d", n, above)
			}
			if n := gatePGCount(t, d, "SELECT count(*) FROM syslog_messages WHERE id <= ?", v); n != 0 {
				t.Fatalf("%d rows at or below V left, want 0 (all are past every window)", n)
			}
			if partitioned {
				leaves := gatePGLeaves(t, d, "syslog_messages")
				if leaves[older] || !leaves[cut] {
					t.Fatalf("leaves after the gated pass: %v; want %s dropped (max id <= V) and %s kept (V cuts it)", leaves, older, cut)
				}
			}
			// Held state: every row still past the cutoff is above V. The
			// statements now walk the held rows to find nothing; their plans
			// must still be index scans.
			heldRows := gatePGCount(t, d, `SELECT count(*) FROM syslog_messages WHERE "timestamp" < ?`, cutoff)
			bHeld := gatePlan(t, d, shape+" retention batch (held)", gated.SQL.String(), gated.Vars...)
			bAggHeld := gatePlan(t, d, shape+" aggregation start (held)", aggStart, 6, aggCutoff, v)
			t.Logf("%s: held %d rows past the cutoff; final retention batch %d buffers, aggregation start %d", shape, heldRows, bHeld, bAggHeld)
			// Without the verified-time bound both walked every held row
			// (~9 000 and ~13 000 buffers here, half the heap; the
			// partitioned retention batch did so once per batch).
			if pages := heapPages(t, d, "syslog_messages"); bHeld > pages/10 || bAggHeld > pages/10 {
				t.Errorf("held state: retention batch %d / aggregation start %d buffers on a %d-page heap: the held rows are walked", bHeld, bAggHeld, pages)
			}

			// The archive catches up.
			var maxID int64
			d.db.Raw("SELECT max(id) FROM syslog_messages").Scan(&maxID)
			gatePGVerified(t, d, export.TableSyslog, maxID)
			if err := d.RunSyslogAggregationCycle(ret); err != nil {
				t.Fatal(err)
			}
			if err := d.CleanupOldData(ret); err != nil {
				t.Fatal(err)
			}
			if n := gatePGCount(t, d, `SELECT count(*) FROM syslog_messages WHERE ("timestamp" < ? AND severity <= 5) OR ("timestamp" < ? AND severity >= 6)`,
				now.AddDate(0, 0, -30).Add(-time.Minute), now.AddDate(0, 0, -7).Add(-time.Minute)); n != 0 {
				t.Fatalf("%d expired rows left after the archive caught up", n)
			}
			if partitioned && gatePGLeaves(t, d, "syslog_messages")[cut] {
				t.Fatalf("%s still attached after V passed it", cut)
			}
			t.Logf("%s: %d rows seeded, %d left", shape, total, gatePGCount(t, d, "SELECT count(*) FROM syslog_messages"))
		})
	}
}

// TestArchiveGate_DropRecheckedUnderLock_PG: a row above V that lands in an
// expired leaf after the unlocked check (a collector replaying old
// timestamps) is caught by the check under the DROP's lock: nothing is
// dropped.
func TestArchiveGate_DropRecheckedUnderLock_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -4, 0)
	leaf := gatePGMonthLeaf(t, d, "syslog_messages", m)
	gatePGSeedSyslog(t, d, m.Add(time.Hour), m.Add(48*time.Hour), 1000)
	var v int64
	d.db.Raw("SELECT max(id) FROM syslog_messages").Scan(&v)
	// After the check, before the DROP: a replayed row with an old timestamp.
	gatePGSeedSyslog(t, d, m.Add(72*time.Hour), m.Add(73*time.Hour), 1)
	if err := d.dropArchivedPartition("syslog_messages", leaf, v); !errors.Is(err, errArchivePartitionHeld) {
		t.Fatalf("drop with a row above V in the leaf: %v, want errArchivePartitionHeld", err)
	}
	if !gatePGLeaves(t, d, "syslog_messages")[leaf] {
		t.Fatal("the leaf was dropped")
	}
	if err := d.dropArchivedPartition("syslog_messages", leaf, v+1); err != nil {
		t.Fatalf("drop once V covers it: %v", err)
	}
	if gatePGLeaves(t, d, "syslog_messages")[leaf] {
		t.Fatal("the leaf is still attached")
	}
}

// TestArchiveGate_Flows_PG: flow_samples (both shapes, 3 h at 60 000 rows an
// hour) and flow_if_counters (40 days): the rollup consumes, and retention
// deletes, only rows at or below V; the gated statements' plans at density.
func TestArchiveGate_Flows_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	d.archiveGateCfg = ArchiveGateConfig{Flows: true}
	ret := config.RetentionConfig{DefaultDays: 30, FlowDays: 30}
	now := time.Now().UTC()
	h0 := now.Truncate(time.Hour).Add(-3 * time.Hour)

	for _, shape := range []string{"partitioned (fresh install)", "plain heap"} {
		t.Run(shape, func(t *testing.T) {
			if strings.HasPrefix(shape, "plain") {
				if err := d.db.Exec(`DROP TABLE flow_samples CASCADE`).Error; err != nil {
					t.Fatal(err)
				}
				if err := d.db.Migrator().CreateTable(&models.FlowSample{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.db.Exec("DELETE FROM flow_rollups").Error; err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				archiveSeedFlows(t, d, h0.Add(time.Duration(i)*time.Hour+10*time.Minute), 60000)
			}
			if err := d.db.Exec("VACUUM ANALYZE flow_samples").Error; err != nil {
				t.Fatal(err)
			}
			// V: the end of the first hour; the second and third are held
			// although the second is past the rollup's 1 h.
			var v int64
			d.db.Raw(`SELECT max(id) FROM flow_samples WHERE "timestamp" < ?`, h0.Add(time.Hour)).Scan(&v)
			gatePGVerified(t, d, export.TableFlows, v)
			below := gatePGCount(t, d, "SELECT count(*) FROM flow_samples WHERE id <= ?", v)
			above := gatePGCount(t, d, "SELECT count(*) FROM flow_samples WHERE id > ?", v)

			cutoff := truncateToBucket(time.Now().Add(-time.Hour), "5min")
			g := d.archiveGate(context.Background(), export.TableFlows)
			bStart := gatePlan(t, d, shape+" rollup start (gated)",
				`SELECT MIN(timestamp) FROM "flow_samples" WHERE timestamp < $1 AND id <= $2`, g.capCutoff(cutoff), v)
			where, args := g.andID("", nil)
			ret30 := now.AddDate(0, 0, -30)
			st := retentionBatchQuery(dryRun(d), &models.FlowSample{}, "timestamp", "timestamp", ret30, where, args, cleanupDeleteBatchSize).
				Find(&[]int64{}).Statement
			bRet := gatePlan(t, d, shape+" flow_samples retention (gated)", st.SQL.String(), st.Vars...)
			t.Logf("%s: rollup start %d buffers, flow_samples retention batch %d", shape, bStart, bRet)

			d.RunFlowRollupCycle()
			if n := gatePGCount(t, d, "SELECT count(*) FROM flow_samples WHERE id > ?", v); n != above {
				t.Fatalf("%d flow samples above V left, want all %d", n, above)
			}
			if n := gatePGCount(t, d, "SELECT count(*) FROM flow_samples WHERE id <= ?", v); n != 0 {
				t.Fatalf("%d flow samples at or below V left, want 0", n)
			}
			if n := gatePGCount(t, d, "SELECT COALESCE(sum(flow_count), 0) FROM flow_rollups"); n != below {
				t.Fatalf("rolled up %d samples, want %d (exactly the rows at or below V)", n, below)
			}
			var maxID int64
			d.db.Raw("SELECT max(id) FROM flow_samples").Scan(&maxID)
			gatePGVerified(t, d, export.TableFlows, maxID)
			d.RunFlowRollupCycle()
			if n := gatePGCount(t, d, `SELECT count(*) FROM flow_samples WHERE "timestamp" < ?`, cutoff); n != 0 {
				t.Fatalf("%d samples past the rollup cutoff left after the archive caught up", n)
			}
			left := gatePGCount(t, d, "SELECT count(*) FROM flow_samples")
			if n := gatePGCount(t, d, "SELECT COALESCE(sum(flow_count), 0) FROM flow_rollups"); n != below+above-left {
				t.Fatalf("rollups hold %d samples after catching up, want %d: every sample counted exactly once", n, below+above-left)
			}
		})
	}

	// flow_if_counters: never rolled up, retention is its only delete. Its
	// only time index leads with device_id, so the ungated batch (no ORDER
	// BY) is a sequential scan today; the gate must not make it worse.
	if err := d.db.Exec(`INSERT INTO flow_if_counters ("timestamp", device_id, probe_id, sampler_address, if_index, created_at)
		SELECT now() - interval '40 days' + make_interval(secs => g * 2), 1 + g % 3, 1, '192.0.2.1', g % 48, now()
		FROM generate_series(0, 400000 - 1) g`).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Exec("VACUUM ANALYZE flow_if_counters").Error; err != nil {
		t.Fatal(err)
	}
	var v int64
	d.db.Raw(`SELECT max(id) FROM flow_if_counters WHERE "timestamp" < now() - interval '35 days'`).Scan(&v)
	gatePGVerified(t, d, export.TableCounters, v)
	above := gatePGCount(t, d, "SELECT count(*) FROM flow_if_counters WHERE id > ?", v)
	g := d.archiveGate(context.Background(), export.TableCounters)
	where, args := g.andID("", nil)
	ret30 := now.AddDate(0, 0, -30)
	gst := retentionBatchQuery(dryRun(d), &models.FlowInterfaceCounter{}, "timestamp", "", ret30, where, args, cleanupDeleteBatchSize).Find(&[]int64{}).Statement
	ust := retentionBatchQuery(dryRun(d), &models.FlowInterfaceCounter{}, "timestamp", "", ret30, "", nil, cleanupDeleteBatchSize).Find(&[]int64{}).Statement
	bG := explainBuffers(t, d, "counters retention (gated)", gst.SQL.String(), gst.Vars...)
	bU := explainBuffers(t, d, "counters retention (ungated)", ust.SQL.String(), ust.Vars...)
	t.Logf("flow_if_counters retention batch: %d buffers gated, %d ungated", bG, bU)
	if bG > 2*bU+100 {
		t.Errorf("the gated counters batch reads %d buffers against %d ungated", bG, bU)
	}
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatal(err)
	}
	if n := gatePGCount(t, d, "SELECT count(*) FROM flow_if_counters WHERE id > ?", v); n != above {
		t.Fatalf("%d counter rows above V left, want all %d", n, above)
	}
	if n := gatePGCount(t, d, "SELECT count(*) FROM flow_if_counters WHERE id <= ?", v); n != 0 {
		t.Fatalf("%d counter rows at or below V left, want 0", n)
	}
}
