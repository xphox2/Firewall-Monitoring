//go:build integration

// Migration v80 on a real PostgreSQL: the unused net_events leaf indexes go,
// no reader's plan changes, and the drop never stalls ingest for longer than
// its lock bound.
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// sqlRecorder is a GORM logger that keeps the rendered SQL of every
// statement, so a test can EXPLAIN exactly what a code path sent.
type sqlRecorder struct {
	mu   sync.Mutex
	sqls []string
}

func (r *sqlRecorder) LogMode(logger.LogLevel) logger.Interface      { return r }
func (r *sqlRecorder) Info(context.Context, string, ...interface{})  {}
func (r *sqlRecorder) Warn(context.Context, string, ...interface{})  {}
func (r *sqlRecorder) Error(context.Context, string, ...interface{}) {}
func (r *sqlRecorder) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	s, _ := fc()
	r.mu.Lock()
	r.sqls = append(r.sqls, s)
	r.mu.Unlock()
}

func (r *sqlRecorder) last(t *testing.T) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sqls) == 0 {
		t.Fatal("no statement recorded")
	}
	return r.sqls[len(r.sqls)-1]
}

// planShape EXPLAINs sql and returns its nodes (type, relation, index — no
// costs) one per line, and the plan's total cost.
func planShape(t *testing.T, d *Database, label, sql string, args ...any) (string, float64) {
	t.Helper()
	var raw string
	if err := d.pgxPool.QueryRow(context.Background(), "EXPLAIN (FORMAT JSON) "+sql, args...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN %s: %v\n%s", label, err, sql)
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
		fmt.Fprintf(&b, "%s%s %s %s\n", strings.Repeat("  ", depth), n.Type, n.Relation, n.Index)
		for _, c := range n.Plans {
			walk(c, depth+1)
		}
	}
	walk(top[0].Plan, 0)
	return b.String(), top[0].Plan.TotalCost
}

// TestDropUnusedNetEventIndexes_PG: a pre-v80 install (the three plan
// indexes on every leaf, on the DEFAULT child and on a leaf left standalone
// by an interrupted move) with ~900 000 rows in three daily leaves. Every
// reader of net_events — the rollup's hour reads and MIN(ts) probes, the
// backfill's dedup probe and replace-mode DELETE (whole range and
// device-scoped), the device purge batch and the DEFAULT trim — plans the
// same before and after v80, none of them on a dropped index. v80 runs while
// a reader holds today's leaf: inserts into that leaf wait no longer than the
// lock bound, the held drops are retried, and every retired index goes. A
// re-run and the next EnsurePartitions build nothing back.
func TestDropUnusedNetEventIndexes_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	d.netEventRetentionDays = 30
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if err := d.db.Exec(q, args...).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// The pre-v80 shape: the three indexes the old plan built on every leaf.
	today := utcDay(time.Now())
	stray := "net_events_" + today.AddDate(0, 0, -60).Format("20060102") // standalone, mid-move
	exec(fmt.Sprintf(`CREATE TABLE %s (LIKE net_events INCLUDING DEFAULTS)`, stray))
	children := append(pgLeaves(t, d, "net_events"), stray)
	retiredCols := map[string]string{"rule_key_ts": "rule_key, ts", "src_ip_ts": "src_ip, ts", "dst_ip_ts": "dst_ip, ts"}
	for _, leaf := range children {
		for suffix, cols := range retiredCols {
			exec(fmt.Sprintf(`CREATE INDEX idx_%s_%s ON %s (%s)`, leaf, suffix, leaf, cols))
		}
	}
	// A table outside the family whose index carries a matching suffix stays.
	exec(`CREATE TABLE net_events_staging_x (rule_key text, ts timestamptz)`)
	exec(`CREATE INDEX idx_net_events_staging_x_rule_key_ts ON net_events_staging_x (rule_key, ts)`)
	wantRetired := len(children) * len(retiredCols)
	if got, err := d.netEventsRetiredIndexes(); err != nil || len(got) != wantRetired {
		t.Fatalf("retired indexes before v80: %d (%v), want %d", len(got), err, wantRetired)
	}

	// ~900 000 rows over the last three days, two devices, varied rules and
	// endpoints (synthetic documentation ranges), plus strays in the DEFAULT.
	start := today.AddDate(0, 0, -3)
	const rows = 900000
	exec(`INSERT INTO net_events (ts, device_id, probe_id, activity, action, raw_id, raw_ts, rule_key, src_ip, dst_ip, bytes_in, bytes_out)
		SELECT t, 1 + (g % 2), 1, 1, 1 + (g % 3), g, t, 'i:' || (g % 40),
		       ('198.51.100.' || (g % 250))::inet, ('203.0.113.' || (g % 200))::inet, g % 9000, g % 7000
		FROM (SELECT ?::timestamptz + g * (?::bigint * interval '1 microsecond') AS t, g FROM generate_series(1, ?) g) s`,
		start, (72*time.Hour).Microseconds()/rows, rows)
	exec(`INSERT INTO net_events (ts, device_id, probe_id, activity, action, raw_id, raw_ts)
		SELECT ?::timestamptz - g * interval '1 second', 1, 1, 1, 1, 2000000 + g, ?::timestamptz - g * interval '1 second'
		FROM generate_series(1, 2000) g`, today.AddDate(0, 0, -45), today.AddDate(0, 0, -45))
	exec(`ANALYZE net_events`)

	// The readers, as their code paths send them.
	hour := start.Add(30 * time.Hour)
	readers := func() map[string]string {
		rec := &sqlRecorder{}
		tx := d.db.Session(&gorm.Session{Logger: rec})
		sqls := map[string]string{}
		if _, err := d.selectNetEventRollupGroups(tx, hour, hour.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		sqls["rollup groups (one hour)"] = rec.last(t)
		if _, err := d.selectNetEventRollupPairs(tx, hour, hour.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		sqls["rollup pairs (one hour)"] = rec.last(t)
		if _, _, err := oldestEligibleOn(tx.Table("net_events").Where("ts >= ? AND ts < ?", today.AddDate(0, 0, -30), today), "ts"); err != nil {
			t.Fatal(err)
		}
		sqls["rollup MIN(ts) window"] = rec.last(t)
		if _, _, err := oldestEligibleOn(tx.Table("net_events").Where("ts >= ?", start.AddDate(0, 0, 1)), "ts"); err != nil {
			t.Fatal(err)
		}
		sqls["rollup MIN(ts) next day"] = rec.last(t)
		return sqls
	}
	// The dedup probe and the replace-mode DELETE of a 5 000-row batch.
	var ids []int64
	for i := int64(0); i < 5000; i++ {
		ids = append(ids, 450000+i)
	}
	var lo, hi time.Time
	if err := d.db.Raw(`SELECT MIN(ts), MAX(ts) FROM net_events WHERE raw_id BETWEEN 450000 AND 454999`).Row().Scan(&lo, &hi); err != nil {
		t.Fatal(err)
	}
	dev := int64(2)
	plans := func() map[string]string {
		out := map[string]string{}
		for label, sql := range readers() {
			out[label], _ = planShape(t, d, label, sql)
		}
		probe := d.db.Session(&gorm.Session{DryRun: true}).Table("net_events").
			Where("ts >= ? AND ts <= ? AND raw_id IN ?", lo, hi, ids).Pluck("raw_id", &[]int64{}).Statement
		out["backfill dedup probe"], _ = planShape(t, d, "probe", probe.SQL.String(), probe.Vars...)
		probeDev := d.db.Session(&gorm.Session{DryRun: true}).Table("net_events").
			Where("ts >= ? AND ts <= ? AND raw_id IN ?", lo, hi, ids).Where("device_id = ?", dev).Pluck("raw_id", &[]int64{}).Statement
		out["backfill dedup probe (device)"], _ = planShape(t, d, "probe device", probeDev.SQL.String(), probeDev.Vars...)
		// commitBackfillBatch's pgx statements, verbatim.
		out["replace-mode DELETE"], _ = planShape(t, d, "replace delete",
			"DELETE FROM net_events WHERE ts >= $1 AND ts <= $2 AND raw_id = ANY($3)", lo, hi, ids)
		out["replace-mode DELETE (device)"], _ = planShape(t, d, "replace delete device",
			"DELETE FROM net_events WHERE ts >= $1 AND ts <= $2 AND raw_id = ANY($3) AND device_id = $4", lo, hi, ids, dev)
		// batchedDeleteWhere as the device purge and the DEFAULT trim call it.
		out["device purge batch"], _ = planShape(t, d, "purge",
			"DELETE FROM net_events WHERE id IN (SELECT id FROM net_events WHERE device_id = $1 ORDER BY ts LIMIT $2)", dev, 2000)
		out["DEFAULT trim batch"], _ = planShape(t, d, "trim",
			"DELETE FROM net_events_default WHERE id IN (SELECT id FROM net_events_default WHERE ts < $1 ORDER BY ts LIMIT $2)", today.AddDate(0, 0, -30), 5000)
		return out
	}
	before := plans()
	for label, p := range before {
		for suffix := range retiredCols {
			if strings.Contains(p, suffix) {
				t.Errorf("%s uses a retired index before v80:\n%s", label, p)
			}
		}
	}

	// Sizes, for the log.
	var retiredBytes int64
	if err := d.db.Raw(`SELECT COALESCE(SUM(pg_relation_size(c.oid)), 0) FROM pg_class c
		WHERE c.relkind = 'i' AND (c.relname LIKE '%\_rule\_key\_ts' OR c.relname LIKE '%\_src\_ip\_ts' OR c.relname LIKE '%\_dst\_ip\_ts')
		  AND c.relname LIKE 'idx\_net\_events\_%' AND c.relname NOT LIKE 'idx\_net\_events\_staging%'`).Scan(&retiredBytes).Error; err != nil {
		t.Fatal(err)
	}

	// v80 under a reader of today's leaf, with live inserts into it.
	origTimeout, origRounds, origSleep := netEventIndexDropLockTimeout, netEventIndexDropRounds, netEventIndexDropRetrySleep
	netEventIndexDropLockTimeout, netEventIndexDropRounds, netEventIndexDropRetrySleep = 300*time.Millisecond, 10, 200*time.Millisecond
	t.Cleanup(func() {
		netEventIndexDropLockTimeout, netEventIndexDropRounds, netEventIndexDropRetrySleep = origTimeout, origRounds, origSleep
	})
	todayLeaf := "net_events_" + today.Format("20060102")
	reader, err := d.pgxPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Exec(ctx, "SELECT COUNT(*) FROM "+todayLeaf); err != nil {
		t.Fatal(err)
	}
	const holdFor = 1500 * time.Millisecond
	go func() {
		time.Sleep(holdFor)
		_ = reader.Rollback(ctx)
	}()
	stop := make(chan struct{})
	var maxStall time.Duration
	var inserts int
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			t0 := time.Now()
			if _, err := d.pgxPool.Exec(ctx, `INSERT INTO net_events (ts, device_id, probe_id, activity, action, raw_id, raw_ts) VALUES (now(), 1, 1, 1, 1, 0, now())`); err != nil {
				t.Errorf("insert during v80: %v", err)
				return
			}
			if dt := time.Since(t0); dt > maxStall {
				maxStall = dt
			}
			inserts++
			time.Sleep(10 * time.Millisecond)
		}
	}()
	t0 := time.Now()
	if err := d.migrateDropUnusedNetEventIndexes(); err != nil {
		t.Fatalf("v80: %v", err)
	}
	took := time.Since(t0)
	close(stop)
	<-done
	t.Logf("v80 over %d retired indexes (%d MB on this fixture) took %s while a reader held %s for %s; %d inserts into that leaf meanwhile, the slowest %s",
		wantRetired, retiredBytes>>20, took.Round(time.Millisecond), todayLeaf, holdFor, inserts, maxStall.Round(time.Millisecond))
	if took < holdFor {
		t.Errorf("v80 finished in %s although a reader held %s for %s: the held drops were not waited for", took, todayLeaf, holdFor)
	}
	if limit := netEventIndexDropLockTimeout + 250*time.Millisecond; maxStall > limit {
		t.Errorf("an insert into %s waited %s behind v80, over the lock bound (%s + margin)", todayLeaf, maxStall, netEventIndexDropLockTimeout)
	}
	if got, err := d.netEventsRetiredIndexes(); err != nil || len(got) != 0 {
		t.Fatalf("retired indexes after v80: %v %v", got, err)
	}
	for _, leaf := range []string{todayLeaf, "net_events_default"} {
		if idx := childNonUniqueIndexCols(t, d, leaf); len(idx) != 2 {
			t.Errorf("%s has %v after v80, want (device_id, ts) and (ts)", leaf, idx)
		}
	}
	if !d.db.Migrator().HasIndex("net_events_staging_x", "idx_net_events_staging_x_rule_key_ts") {
		t.Error("v80 dropped an index outside the net_events leaves")
	}

	// Every reader plans as before (same statistics: dropping an index on
	// plain columns changes none of the table's).
	after := plans()
	for label, p := range before {
		if after[label] != p {
			t.Errorf("%s plans differently after v80:\nbefore\n%s\nafter\n%s", label, p, after[label])
		}
	}
	for label, p := range after {
		t.Logf("plan %s:\n%s", label, p)
	}

	// Idempotent, and nothing rebuilds them.
	if err := d.migrateDropUnusedNetEventIndexes(); err != nil {
		t.Fatalf("v80 re-run: %v", err)
	}
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions after v80: %v", err)
	}
	if got, err := d.netEventsRetiredIndexes(); err != nil || len(got) != 0 {
		t.Fatalf("retired indexes after a re-run and EnsurePartitions: %v %v", got, err)
	}
}
