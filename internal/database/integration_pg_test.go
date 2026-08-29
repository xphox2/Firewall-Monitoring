//go:build integration

// Postgres integration tests (AUDIT-118). Production is Postgres-only, but the
// rest of the suite runs on in-memory SQLite (NewDatabaseForTesting) and can't
// exercise the Postgres-specific paths: the dialect's to_char() TimeBucket
// strings (the v0.10.238 minute-bucket regression that broke spike timestamps),
// the pinned-conn advisory-lock migration runner (AUDIT-044),
// EnsurePartitions/ConfigureAutovacuum, and pg_try_advisory_lock.
//
// This file is behind `//go:build integration`, so the default `go test ./...`
// never compiles it. Even under `-tags=integration` the suite SKIPs unless
// TEST_PG_DSN is set, so a compile/skip check is safe with no database present.
// CI runs it against a postgres:16 service container; `make test-integration`
// runs it locally for anyone with a Postgres.
package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// pgIsPartitioned reports whether table is a RANGE-partitioned parent.
func pgIsPartitioned(t *testing.T, d *Database, table string) bool {
	t.Helper()
	var ok bool
	if err := d.Gorm().Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = ?)`, table).Scan(&ok).Error; err != nil {
		t.Fatalf("partition probe %s: %v", table, err)
	}
	return ok
}

// childNonUniqueIndexCols returns, for each non-unique index on the given
// child partition (cascaded parent indexes included), its ordered column list
// keyed by index name. Mirrors parentPartitionedIndexColumns but for leaf
// relations (relkind 'i').
func childNonUniqueIndexCols(t *testing.T, d *Database, child string) map[string][]string {
	t.Helper()
	var rows []struct {
		IndexName string
		Cols      string
	}
	if err := d.Gorm().Raw(`
		SELECT i.relname AS index_name,
		       string_agg(a.attname, ',' ORDER BY k.ord) AS cols
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_class t ON t.oid = x.indrelid
		JOIN LATERAL unnest(x.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE t.relname = ?
		  AND i.relkind = 'i'
		  AND NOT x.indisunique
		  AND x.indexprs IS NULL
		GROUP BY i.relname`, child).Scan(&rows).Error; err != nil {
		t.Fatalf("child index probe %s: %v", child, err)
	}
	out := make(map[string][]string, len(rows))
	for _, r := range rows {
		if r.Cols == "" {
			continue
		}
		out[r.IndexName] = strings.Split(r.Cols, ",")
	}
	return out
}

// newPGForTest delegates to the shared NewIntegrationDB harness (defined in
// integration_testkit.go) — connects to TEST_PG_DSN (skipping if unset), resets
// the public schema, runs migrations, returns a migrated *Database.
func newPGForTest(t *testing.T) *Database {
	t.Helper()
	return NewIntegrationDB(t)
}

func TestPostgresIntegration(t *testing.T) {
	d := newPGForTest(t) // skips if TEST_PG_DSN is unset

	t.Run("MigrationsRecorded", func(t *testing.T) {
		var rows []models.SchemaMigration
		if err := d.Gorm().Order("version").Find(&rows).Error; err != nil {
			t.Fatalf("read schema_migrations: %v", err)
		}
		if len(rows) != len(registeredMigrations) {
			t.Fatalf("want %d recorded migrations, got %+v", len(registeredMigrations), rows)
		}
		for i, m := range registeredMigrations {
			if rows[i].Version != m.version || rows[i].Name != m.name {
				t.Fatalf("recorded[%d] = {%d %q}, want {%d %q}", i, rows[i].Version, rows[i].Name, m.version, m.name)
			}
		}
		// Idempotent re-run (also re-exercises the pinned-conn advisory lock).
		if err := d.RunMigrations(); err != nil {
			t.Fatalf("RunMigrations re-run: %v", err)
		}
		var n int64
		d.Gorm().Model(&models.SchemaMigration{}).Count(&n)
		if n != int64(len(registeredMigrations)) {
			t.Fatalf("re-run changed the recorded set; want %d, got %d", len(registeredMigrations), n)
		}
	})

	// AUDIT-028/146: after migrations on a fresh DB, all 6 high-volume tables
	// are partitioned parents.
	t.Run("AllSixArePartitionedParents", func(t *testing.T) {
		for _, pt := range partitionTables {
			if !pgIsPartitioned(t, d, pt.tableName) {
				t.Errorf("%s is not a partitioned parent after migrations (AUDIT-028/146)", pt.tableName)
			}
		}
	})

	t.Run("EnsurePartitionsCreatesAndRoutes", func(t *testing.T) {
		if err := d.EnsurePartitions(); err != nil {
			t.Fatalf("EnsurePartitions: %v", err)
		}
		now := time.Now().UTC()
		child := fmt.Sprintf("interface_stats_%d%02d", now.Year(), int(now.Month()))
		var cnt int
		d.Gorm().Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = ?", child).Scan(&cnt)
		if cnt != 1 {
			t.Fatalf("EnsurePartitions did not create current-month child %s", child)
		}
		// An inserted row routes into the current-month child partition.
		if err := d.Gorm().Create(&models.InterfaceStats{DeviceID: 1, Timestamp: now, Name: "port1"}).Error; err != nil {
			t.Fatalf("insert InterfaceStats: %v", err)
		}
		var inChild int64
		d.Gorm().Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s", child)).Scan(&inChild)
		if inChild != 1 {
			t.Fatalf("inserted row did not route into %s (got %d)", child, inChild)
		}
	})

	t.Run("QueryPrunesToOnePartition", func(t *testing.T) {
		now := time.Now().UTC()
		cur := fmt.Sprintf("interface_stats_%d%02d", now.Year(), int(now.Month()))
		nm := now.AddDate(0, 1, 0)
		next := fmt.Sprintf("interface_stats_%d%02d", nm.Year(), int(nm.Month()))
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		var plan []string
		q := fmt.Sprintf("EXPLAIN SELECT * FROM interface_stats WHERE device_id = 1 AND timestamp >= '%s' AND timestamp < '%s'",
			start.Format("2006-01-02"), start.AddDate(0, 1, 0).Format("2006-01-02"))
		if err := d.Gorm().Raw(q).Scan(&plan).Error; err != nil {
			t.Fatalf("EXPLAIN: %v", err)
		}
		joined := strings.Join(plan, "\n")
		if !strings.Contains(joined, cur) {
			t.Fatalf("EXPLAIN did not scan the current-month partition %s:\n%s", cur, joined)
		}
		if strings.Contains(joined, next) {
			t.Fatalf("EXPLAIN scanned an out-of-range partition %s (pruning failed):\n%s", next, joined)
		}
	})

	// LC-19 (2026-07-04 audit): on a real Postgres, every model-tag index must
	// be SERVED on the current-month child partitions after EnsurePartitions.
	// The pre-fix hard-coded recreation list silently dropped the AUDIT-034
	// flow_samples src/dst indexes (and probe_id / syslog_summaries indexes)
	// on every fresh install — the sqlite-mode AutoMigrate test could never
	// catch it because the partition conversion is PG-only.
	//
	// AUDIT-174 reshaped the assertion from index NAME to index COLUMNS: the
	// (severity, timestamp) index on syslog leaves and the (timestamp) index on
	// trap_events leaves now arrive as the CASCADED child of the v54/v57
	// parent partitioned indexes (auto-named by PG), and EnsurePartitions
	// deliberately skips its own same-columned entries. What LC-19 protects is
	// coverage, not spelling — so assert that some non-unique index on the
	// child serves each wanted column list (equal, or wanted is its leading
	// prefix).
	t.Run("PartitionModelTagIndexes_LC19", func(t *testing.T) {
		now := time.Now().UTC()
		suffix := fmt.Sprintf("%d%02d", now.Year(), int(now.Month()))
		want := map[string][][]string{
			"flow_samples": {{"device_id", "timestamp"}, {"timestamp"}, {"probe_id"}, {"src_addr"}, {"dst_addr"}},
			// (severity, timestamp), not (severity): the standalone severity index
			// was replaced by the composite that per-severity retention deletes
			// need, and partitionIndexPlan drops the standalone as a redundant
			// leading prefix.
			"syslog_messages":  {{"device_id", "timestamp"}, {"timestamp"}, {"probe_id"}, {"severity", "timestamp"}},
			"trap_events":      {{"device_id", "timestamp"}, {"timestamp"}, {"probe_id"}, {"severity"}},
			"syslog_summaries": {{"device_id", "timestamp"}, {"timestamp"}, {"interval_type"}, {"severity"}},
			"interface_stats":  {{"device_id", "timestamp"}, {"timestamp"}, {"device_id", "index", "timestamp"}},
			"system_status":    {{"device_id", "timestamp"}, {"timestamp"}},
		}
		for table, wantCols := range want {
			child := fmt.Sprintf("%s_%s", table, suffix)
			have := childNonUniqueIndexCols(t, d, child)
			if len(have) == 0 {
				t.Errorf("partition %s has no non-unique indexes at all", child)
				continue
			}
			for _, cols := range wantCols {
				served := false
				for _, idxCols := range have {
					if isColPrefix(cols, idxCols) {
						served = true
						break
					}
				}
				if !served {
					t.Errorf("partition %s: no index serves (%s) — per-partition indexes must cover the model's gorm index tags (LC-19); have %v",
						child, strings.Join(cols, ", "), have)
				}
			}
		}
	})

	// AUDIT-174 (2026-08-27 audit): after EnsurePartitions on a fresh schema —
	// where the v54/v57 PARENT partitioned indexes exist and cascade to every
	// leaf — no child of any partitioned parent may carry two non-unique
	// indexes over the same key columns (same indkey). This is the audit's
	// exact gap: the LC-19 check above counts coverage and the old version
	// counted only the PLAN's names, so a cascaded twin under a different name
	// passed every test while doubling index write amplification and disk on
	// every monthly leaf.
	t.Run("NoDuplicateChildIndexes_AUDIT174", func(t *testing.T) {
		parents := make([]string, 0, len(partitionTables))
		for _, def := range partitionTables {
			parents = append(parents, def.tableName)
		}
		var dups []struct {
			Child string
			Key   string
			Names string
		}
		if err := d.Gorm().Raw(`
			SELECT t.relname AS child,
			       x.indkey::text AS key,
			       string_agg(i.relname, ', ' ORDER BY i.relname) AS names
			FROM pg_index x
			JOIN pg_class i ON i.oid = x.indexrelid
			JOIN pg_class t ON t.oid = x.indrelid
			JOIN pg_inherits h ON h.inhrelid = t.oid
			JOIN pg_class parent ON parent.oid = h.inhparent
			WHERE parent.relname IN ?
			  AND NOT x.indisunique
			  AND i.relkind = 'i'
			GROUP BY t.relname, x.indkey::text
			HAVING COUNT(*) > 1`, parents).Scan(&dups).Error; err != nil {
			t.Fatalf("duplicate-index probe: %v", err)
		}
		for _, dup := range dups {
			t.Errorf("child %s carries duplicate non-unique indexes over indkey %q: %s (AUDIT-174: a parent-covered plan entry was created anyway)",
				dup.Child, dup.Key, dup.Names)
		}
	})

	// AUDIT-174 review fix: installs created between v0.11.183 and v0.11.213
	// already carry the duplicate leaf btrees (this deployment's prod does
	// not, but the published images mean the fleet does). EnsurePartitions
	// must now DROP a pre-existing plan-named twin on any leaf a covering
	// parent partitioned index serves. Simulate the pre-fix state by creating
	// the plan-named duplicate on a live syslog leaf, re-run EnsurePartitions,
	// and require the twin gone while the cascaded parent index survives.
	t.Run("DropsPreexistingDuplicateLeafIndex_AUDIT174", func(t *testing.T) {
		var child string
		if err := d.Gorm().Raw(`
			SELECT c.relname FROM pg_inherits h
			JOIN pg_class c ON c.oid = h.inhrelid
			JOIN pg_class p ON p.oid = h.inhparent
			WHERE p.relname = 'syslog_messages'
			ORDER BY c.relname LIMIT 1`).Scan(&child).Error; err != nil || child == "" {
			t.Fatalf("no syslog_messages child found (err=%v)", err)
		}
		dupName := "idx_" + child + "_severity_timestamp"
		if err := d.Gorm().Exec(
			`CREATE INDEX IF NOT EXISTS ` + dupName + ` ON ` + child + ` (severity, "timestamp")`).Error; err != nil {
			t.Fatalf("create pre-fix duplicate: %v", err)
		}
		if err := d.EnsurePartitions(); err != nil {
			t.Fatalf("EnsurePartitions: %v", err)
		}
		var n int
		d.Gorm().Raw(`SELECT COUNT(*) FROM pg_class WHERE relname = ? AND relkind = 'i'`, dupName).Scan(&n)
		if n != 0 {
			t.Errorf("pre-existing duplicate %s survived EnsurePartitions — fleet installs keep both btrees (AUDIT-174 review fix)", dupName)
		}
		// The cascaded parent index must still serve the columns.
		var served int
		d.Gorm().Raw(`
			SELECT COUNT(*) FROM pg_index x
			JOIN pg_class i ON i.oid = x.indexrelid
			JOIN pg_class t ON t.oid = x.indrelid
			WHERE t.relname = ? AND NOT x.indisunique`, child).Scan(&served)
		if served == 0 {
			t.Errorf("child %s has no non-unique index left — the drop removed the wrong index", child)
		}
	})

	// NOTE: the PopulatedTableSkipped subtest is intentionally registered LAST
	// (after DeviceCRUD), not here. It resets the shared `public` schema via a
	// second handle to the same physical test database, which would leave
	// interface_stats plain and system_status a childless partitioned parent —
	// corrupting the partitioned state that CleanupDropsOldPartition and
	// TimeBucketRoundTrip depend on. Running it last keeps it self-contained.

	t.Run("CleanupDropsOldPartition", func(t *testing.T) {
		if err := d.Gorm().Exec(
			`CREATE TABLE IF NOT EXISTS interface_stats_200001 PARTITION OF interface_stats FOR VALUES FROM ('2000-01-01') TO ('2000-02-01')`).Error; err != nil {
			t.Fatalf("create old partition: %v", err)
		}
		handled, err := d.dropPartitionsOlderThan("interface_stats", time.Now())
		if err != nil || !handled {
			t.Fatalf("dropPartitionsOlderThan: handled=%v err=%v", handled, err)
		}
		var n int
		d.Gorm().Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = 'interface_stats_200001'").Scan(&n)
		if n != 0 {
			t.Fatal("old partition interface_stats_200001 was not dropped")
		}
		cur := fmt.Sprintf("interface_stats_%d%02d", time.Now().UTC().Year(), int(time.Now().UTC().Month()))
		d.Gorm().Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = ?", cur).Scan(&n)
		if n != 1 {
			t.Fatalf("current-month partition %s should survive the drop", cur)
		}
	})

	// LC-23 (2026-07-04 audit): syslog_messages now takes the partition-drop
	// fast path when BOTH severity windows are bounded — a monthly partition
	// wholly older than max(critical, info) holds only expired rows. When the
	// critical class is kept forever (SyslogCriticalDays=0, the code default),
	// no partition may ever be dropped.
	t.Run("CleanupSyslogPartitionDrop_LC23", func(t *testing.T) {
		mkOld := func(name, from, to string) {
			t.Helper()
			if err := d.Gorm().Exec(fmt.Sprintf(
				`CREATE TABLE IF NOT EXISTS %s PARTITION OF syslog_messages FOR VALUES FROM ('%s') TO ('%s')`,
				name, from, to)).Error; err != nil {
				t.Fatalf("create old partition %s: %v", name, err)
			}
		}
		partCount := func(name string) int {
			var n int
			d.Gorm().Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = ?", name).Scan(&n)
			return n
		}

		// Keep-forever config: the old partition must survive cleanup.
		mkOld("syslog_messages_200001", "2000-01-01", "2000-02-01")
		if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 90, SyslogCriticalDays: 0, SyslogInfoDays: 7}); err != nil {
			t.Fatalf("CleanupOldData (keep-forever): %v", err)
		}
		if partCount("syslog_messages_200001") != 1 {
			t.Fatal("syslog_messages_200001 was dropped despite SyslogCriticalDays=0 (critical rows are kept forever)")
		}

		// Bounded windows: the wholly-expired partition is dropped, the
		// current-month partition survives.
		if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 90, SyslogCriticalDays: 30, SyslogInfoDays: 7}); err != nil {
			t.Fatalf("CleanupOldData (bounded): %v", err)
		}
		if partCount("syslog_messages_200001") != 0 {
			t.Fatal("syslog_messages_200001 was not dropped despite being older than both severity windows (LC-23 fast path)")
		}
		now := time.Now().UTC()
		cur := fmt.Sprintf("syslog_messages_%d%02d", now.Year(), int(now.Month()))
		if partCount(cur) != 1 {
			t.Fatalf("current-month partition %s should survive the syslog partition drop", cur)
		}
	})

	// Headline v0.10.238 guard: the Postgres to_char() bucket strings must match
	// the layouts charts.parseBucketToMillis parses, on a real Postgres.
	t.Run("TimeBucketRoundTrip", func(t *testing.T) {
		// Use a timestamp in the CURRENT month at a fixed intra-day time. A
		// hard-coded past month is a time-bomb: system_status is monthly
		// RANGE-partitioned and EnsurePartitions only creates the current +
		// future months, so once the calendar advances past that month the
		// insert fails with "no partition of relation ... found" (SQLSTATE
		// 23514). Deriving the day from time.Now keeps the row inside a live
		// partition forever; the fixed 12:34 keeps the bucket assertions
		// deterministic and clear of any minute/hour/day boundary.
		n := time.Now().UTC()
		known := time.Date(n.Year(), n.Month(), n.Day(), 12, 34, 56, 0, time.UTC)
		if err := d.Gorm().Create(&models.SystemStatus{
			DeviceID: 1, Timestamp: known, CPUUsage: 1,
		}).Error; err != nil {
			t.Fatalf("insert SystemStatus: %v", err)
		}
		day := known.Format("2006-01-02")
		cases := []struct{ unit, want, layout string }{
			{"minute", day + " 12:34", "2006-01-02 15:04"},
			{"hour", day + " 12:00", "2006-01-02 15:04"},
			{"day", day, "2006-01-02"},
		}
		pg := postgresDialect{}
		for _, c := range cases {
			t.Run(c.unit, func(t *testing.T) {
				var got string
				if err := d.Gorm().Model(&models.SystemStatus{}).
					Select(pg.TimeBucket(c.unit, "timestamp")+" AS bucket").
					Where("device_id = ?", 1).
					Scan(&got).Error; err != nil {
					t.Fatalf("bucket query (%s): %v", c.unit, err)
				}
				if got != c.want {
					t.Fatalf("bucket %s = %q, want %q", c.unit, got, c.want)
				}
				if _, err := time.Parse(c.layout, got); err != nil {
					t.Fatalf("bucket %s = %q does not parse with app layout %q (v0.10.238 regression): %v", c.unit, got, c.layout, err)
				}
				if parseBucketToMillis(got) == BucketMillisUnparseableSentinel() {
					t.Fatalf("parseBucketToMillis(%q) returned the unparseable sentinel; the chart would drop this bucket", got)
				}
			})
		}
	})

	t.Run("ConfigureAutovacuumNoError", func(t *testing.T) {
		if err := d.ConfigureAutovacuum(); err != nil {
			t.Fatalf("ConfigureAutovacuum: want nil, got %v", err)
		}
	})

	t.Run("AdvisoryLockAcquires", func(t *testing.T) {
		if !d.tryAcquireStartupLock() {
			t.Fatal("tryAcquireStartupLock returned false on a fresh session; expected true")
		}
	})

	// AUDIT-040: the API singleton lock must contend across sessions. A 2nd
	// acquire on the same *Database pins a different pooled conn (a different PG
	// session), simulating a 2nd cmd/api process.
	t.Run("APISingletonLock_AUDIT040", func(t *testing.T) {
		rel1, ok1, err := d.AcquireAPISingletonLock()
		if err != nil {
			t.Fatalf("first acquire: %v", err)
		}
		if !ok1 {
			t.Fatal("first acquire: want acquired=true on a free lock")
		}
		rel2, ok2, err := d.AcquireAPISingletonLock()
		if err != nil {
			t.Fatalf("second acquire: %v", err)
		}
		if ok2 {
			rel2()
			t.Fatal("second acquire: want acquired=false while the lock is held")
		}
		if rel2 == nil {
			t.Fatal("second acquire: release must be non-nil (no-op) even on contention")
		}
		rel1() // release the holder
		rel3, ok3, err := d.AcquireAPISingletonLock()
		if err != nil {
			t.Fatalf("third acquire: %v", err)
		}
		if !ok3 {
			t.Fatal("third acquire: want acquired=true after release")
		}
		rel3()
	})

	t.Run("DeviceCRUD", func(t *testing.T) {
		dev := &models.Device{Name: "it-dev-1", IPAddress: "10.0.0.1"}
		if err := d.CreateDevice(dev); err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}
		if dev.ID == 0 {
			t.Fatal("CreateDevice did not populate ID")
		}
		got, err := d.GetDevice(dev.ID)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if got.Name != "it-dev-1" || got.IPAddress != "10.0.0.1" {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
		if got.Vendor != "fortigate" {
			t.Fatalf("Vendor default not applied: %q", got.Vendor)
		}
	})

	// PopulatedTableSkipped runs LAST: it DROPs and recreates the shared public
	// schema (via a second handle to the same physical test DB) to verify the
	// AUDIT-028 skip path on a populated table, which destroys the partitioned
	// state the earlier subtests rely on. Keeping it last avoids cross-subtest
	// contamination. The populated-table case is verified via a baseline-only DB
	// (so v2 hasn't converted), an inserted row, then a direct
	// migratePartitionHighVolume call which must SKIP (leave the table plain).
	t.Run("PopulatedTableSkipped", func(t *testing.T) {
		d2 := newPGForTest(t) // fresh reset + full migrations… then we test the skip path on a NEW table
		// Reset to baseline-only so interface_stats is plain again.
		if err := d2.Gorm().Exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;").Error; err != nil {
			t.Fatalf("reset: %v", err)
		}
		if err := d2.runMigrationList([]migration{{version: 1, name: "baseline", run: (*Database).migrateBaseline}}); err != nil {
			t.Fatalf("baseline-only: %v", err)
		}
		if pgIsPartitioned(t, d2, "interface_stats") {
			t.Fatal("interface_stats should be plain after baseline-only")
		}
		if err := d2.Gorm().Create(&models.InterfaceStats{DeviceID: 1, Timestamp: time.Now().UTC(), Name: "p"}).Error; err != nil {
			t.Fatalf("insert into plain table: %v", err)
		}
		if err := d2.migratePartitionHighVolume(); err != nil {
			t.Fatalf("migratePartitionHighVolume: %v", err)
		}
		if pgIsPartitioned(t, d2, "interface_stats") {
			t.Fatal("populated interface_stats was auto-converted; it must be SKIPPED (AUDIT-028)")
		}
	})
}
