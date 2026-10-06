//go:build integration

package database

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// TestMigrationLock_PooledConnectionsKeepStatementTimeout_PG: the migration
// lock lifts statement_timeout with a session-level SET on its pinned
// connection; after RunMigrations every pooled connection — that one included
// — must report the DSN's statement_timeout again (before 0.11.301 the lock
// connection went back to the pool untimed until the pool retired it).
func TestMigrationLock_PooledConnectionsKeepStatementTimeout_PG(t *testing.T) {
	_ = NewIntegrationDB(t) // a migrated schema
	cfg := integrationCfgFromDSN(t, os.Getenv("TEST_PG_DSN"))
	cfg.Database.StatementTimeout = 7 * time.Second
	d, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := d.RunMigrations(); err != nil { // takes, lifts and releases the lock connection
		t.Fatal(err)
	}
	sqlDB, err := d.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Hold every connection the pool may have at once, so the one the lock
	// used is among them.
	n := cfg.Database.MaxOpenConns
	conns := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	pids := map[int64]bool{}
	for i := 0; i < n; i++ {
		c, err := sqlDB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var st string
		var pid int64
		if err := c.QueryRowContext(ctx, "SELECT current_setting('statement_timeout'), pg_backend_pid()").Scan(&st, &pid); err != nil {
			t.Fatal(err)
		}
		pids[pid] = true
		if st != "7s" {
			t.Errorf("pooled connection %d (pid %d): statement_timeout %q, want 7s", i, pid, st)
		}
	}
	if len(pids) != n {
		t.Fatalf("%d distinct backends for %d held connections", len(pids), n)
	}
}
