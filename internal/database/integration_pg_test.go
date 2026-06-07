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
	"net/url"
	"os"
	"strconv"
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

// cfgFromDSN parses a URL-form DSN (postgres://user:pass@host:port/db?sslmode=…)
// into the cfg.Database.* fields Connect() consumes. URL form keeps this
// dependency-free (net/url) and matches the DSN the CI job sets.
func cfgFromDSN(t *testing.T, dsn string) *config.Config {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("TEST_PG_DSN is not a valid URL: %v", err)
	}
	port := 5432
	if p := u.Port(); p != "" {
		if n, aerr := strconv.Atoi(p); aerr == nil {
			port = n
		}
	}
	pw, _ := u.User.Password()
	name := strings.TrimPrefix(u.Path, "/")
	ssl := u.Query().Get("sslmode")
	if ssl == "" {
		ssl = "disable"
	}
	// Safety rail: the suite drops/recreates the public schema, so refuse to run
	// against anything that isn't obviously a throwaway test database.
	if !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("refusing to run: TEST_PG_DSN dbname %q must contain 'test' "+
			"(this suite DROPs/recreates the public schema)", name)
	}

	cfg := &config.Config{}
	cfg.Database.Type = "postgres"
	cfg.Database.Host = u.Hostname()
	cfg.Database.Port = port
	cfg.Database.User = u.User.Username()
	cfg.Database.Password = pw
	cfg.Database.Name = name
	cfg.Database.SSLMode = ssl
	cfg.Database.StatementTimeout = 0 // migrations run DDL; don't time-box them
	cfg.Database.MaxOpenConns = 5
	return cfg
}

// newPGForTest connects to TEST_PG_DSN (skipping the suite if unset), resets the
// public schema to a clean slate, runs migrations, and returns a migrated
// *Database with Close() registered for cleanup.
func newPGForTest(t *testing.T) *Database {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("TEST_PG_DSN not set; skipping Postgres integration suite")
	}
	cfg := cfgFromDSN(t, dsn)

	// Reset to an empty public schema via a throwaway handle so re-runs against
	// a persistent Postgres never trip over leftover tables/rows.
	reset, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect (reset handle): %v", err)
	}
	if err := reset.Gorm().Exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;").Error; err != nil {
		_ = reset.Close()
		t.Fatalf("reset public schema: %v", err)
	}
	_ = reset.Close()

	d, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if err := d.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations on real Postgres: %v", err)
	}
	return d
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

	// The populated-table case is verified via a baseline-only DB (so v2 hasn't
	// converted), an inserted row, then a direct migratePartitionHighVolume call
	// which must SKIP (leave the table plain).
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

	// Headline v0.10.238 guard: the Postgres to_char() bucket strings must match
	// the layouts charts.parseBucketToMillis parses, on a real Postgres.
	t.Run("TimeBucketRoundTrip", func(t *testing.T) {
		known := time.Date(2026, 6, 2, 12, 34, 56, 0, time.UTC)
		if err := d.Gorm().Create(&models.SystemStatus{
			DeviceID: 1, Timestamp: known, CPUUsage: 1,
		}).Error; err != nil {
			t.Fatalf("insert SystemStatus: %v", err)
		}
		cases := []struct{ unit, want, layout string }{
			{"minute", "2026-06-02 12:34", "2006-01-02 15:04"},
			{"hour", "2026-06-02 12:00", "2006-01-02 15:04"},
			{"day", "2026-06-02", "2006-01-02"},
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
}
