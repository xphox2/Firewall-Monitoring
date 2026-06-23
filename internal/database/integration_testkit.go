//go:build integration

// Shared Postgres integration-test harness (AUDIT-118/123). Exported so both the
// database-package suite (integration_pg_test.go) and the cross-package
// end-to-end suites (e.g. internal/api/handlers) can connect to the same real
// Postgres without duplicating the connect/reset/migrate dance. This file is
// behind `//go:build integration`, so it never compiles into a normal build —
// importing "testing" here is intentional and harmless.
package database

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/config"
)

// NewIntegrationDB connects to TEST_PG_DSN (skipping the test if unset), resets
// the public schema to a clean slate, runs migrations, and returns a migrated
// *Database with Close registered for cleanup. Safe to call from any package's
// integration suite.
//
// SHARED-DATABASE CONTRACT: the reset below is `DROP SCHEMA public CASCADE`, and
// it runs OUTSIDE the migration advisory lock. Every package that uses this
// harness points at the same TEST_PG_DSN database, so two integration package
// binaries running concurrently will reset each other's schema mid-migration
// (nondeterministic "relation ... does not exist", historically surfacing in
// TestPostgresIntegration/PopulatedTableSkipped). The CI and Makefile invocations
// therefore pass `go test -p 1` to run the integration packages one at a time.
// If you add a third integration package or drop `-p 1`, this race comes back.
func NewIntegrationDB(tb testing.TB) *Database {
	tb.Helper()
	dsn := strings.TrimSpace(os.Getenv("TEST_PG_DSN"))
	if dsn == "" {
		tb.Skip("TEST_PG_DSN not set; skipping Postgres integration suite")
	}
	cfg := integrationCfgFromDSN(tb, dsn)

	// Reset to an empty public schema via a throwaway handle so re-runs against a
	// persistent Postgres never trip over leftover tables/rows.
	reset, err := Connect(cfg)
	if err != nil {
		tb.Fatalf("Connect (reset handle): %v", err)
	}
	if err := reset.Gorm().Exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;").Error; err != nil {
		_ = reset.Close()
		tb.Fatalf("reset public schema: %v", err)
	}
	_ = reset.Close()

	d, err := Connect(cfg)
	if err != nil {
		tb.Fatalf("Connect: %v", err)
	}
	tb.Cleanup(func() { _ = d.Close() })

	if err := d.RunMigrations(); err != nil {
		tb.Fatalf("RunMigrations on real Postgres: %v", err)
	}
	return d
}

// integrationCfgFromDSN parses a URL-form DSN (postgres://user:pass@host:port/db?sslmode=…)
// into the cfg.Database.* fields Connect() consumes. URL form keeps this
// dependency-free (net/url) and matches the DSN the CI job sets.
func integrationCfgFromDSN(tb testing.TB, dsn string) *config.Config {
	tb.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		tb.Fatalf("TEST_PG_DSN is not a valid URL: %v", err)
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
		tb.Fatalf("refusing to run: TEST_PG_DSN dbname %q must contain 'test' "+
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
