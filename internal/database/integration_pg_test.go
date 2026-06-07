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
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

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

	t.Run("MigrationsRecordBaseline", func(t *testing.T) {
		var rows []models.SchemaMigration
		if err := d.Gorm().Order("version").Find(&rows).Error; err != nil {
			t.Fatalf("read schema_migrations: %v", err)
		}
		if len(rows) != 1 || rows[0].Version != 1 || rows[0].Name != "baseline" {
			t.Fatalf("want exactly [{1 baseline}], got %+v", rows)
		}
		// Idempotent re-run (also re-exercises the pinned-conn advisory lock).
		if err := d.RunMigrations(); err != nil {
			t.Fatalf("RunMigrations re-run: %v", err)
		}
		var n int64
		d.Gorm().Model(&models.SchemaMigration{}).Count(&n)
		if n != 1 {
			t.Fatalf("re-run changed the recorded set; want 1, got %d", n)
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

	// AutoMigrate creates plain (non-partitioned) tables, so EnsurePartitions
	// must no-op with a warning and return nil — not error, not create partitions.
	t.Run("EnsurePartitionsNoErrorOnPlainTables", func(t *testing.T) {
		if err := d.EnsurePartitions(); err != nil {
			t.Fatalf("EnsurePartitions on plain tables: want nil, got %v", err)
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
