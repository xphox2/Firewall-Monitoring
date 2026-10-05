//go:build integration

// v74 (syslog_messages.format) on a real PostgreSQL: metadata-only on both
// table shapes production and fresh installs have — a plain heap (production:
// ~161 GB, never converted) and the partitioned parent of a fresh install —
// under a short lock_timeout that keeps ingest moving while it waits.
package database

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/jackc/pgx/v5"
)

// syslogRelfilenodes maps each heap relation of syslog_messages (the table
// itself when plain, every leaf when partitioned) to its relfilenode. A table
// rewrite allocates a new relfilenode, so an unchanged map proves none ran.
func syslogRelfilenodes(t *testing.T, d *Database) map[string]int64 {
	t.Helper()
	var rows []struct {
		Relname     string
		Relfilenode int64
	}
	if err := d.Gorm().Raw(`SELECT c.relname, c.relfilenode FROM pg_class c
		WHERE c.relkind = 'r' AND (c.relname = 'syslog_messages'
			OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'syslog_messages'::regclass))`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("syslog_messages has no heap relation")
	}
	m := map[string]int64{}
	for _, r := range rows {
		m[r.Relname] = r.Relfilenode
	}
	return m
}

// assertFormatColumn checks syslog_messages.format and the same column on
// every leaf: smallint, nullable, no default, no fast-default "missing"
// value, and no index on it.
func assertFormatColumn(t *testing.T, d *Database) {
	t.Helper()
	var cols []struct {
		Relname       string
		Typname       string
		Attnotnull    bool
		Atthasdef     bool
		Atthasmissing bool
	}
	if err := d.Gorm().Raw(`SELECT c.relname, ty.typname, a.attnotnull, a.atthasdef, a.atthasmissing
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_type ty ON ty.oid = a.atttypid
		WHERE a.attname = 'format' AND NOT a.attisdropped AND (c.relname = 'syslog_messages'
			OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'syslog_messages'::regclass))`).Scan(&cols).Error; err != nil {
		t.Fatal(err)
	}
	want := 1 // a plain heap
	if pgIsPartitioned(t, d, "syslog_messages") {
		want += len(syslogRelfilenodes(t, d)) // the parent and every leaf
	}
	if len(cols) != want {
		t.Fatalf("format column on %d relations, want %d (the table, and every leaf when partitioned): %+v", len(cols), want, cols)
	}
	for _, c := range cols {
		if c.Typname != "int2" || c.Attnotnull || c.Atthasdef || c.Atthasmissing {
			t.Errorf("%s.format = %+v, want int2, nullable, no default, no missing value", c.Relname, c)
		}
	}
	var idx int64
	if err := d.Gorm().Raw(`SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE a.attname = 'format' AND (c.relname = 'syslog_messages'
			OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'syslog_messages'::regclass))`).Scan(&idx).Error; err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Errorf("%d index(es) on format, want none", idx)
	}
}

// upgradeV74 puts the database back in the pre-v74 shape (column gone, v74
// unrecorded), seeds n rows, runs the migrations and returns how long v74's
// RunMigrations took. It fails the test on any table rewrite.
func upgradeV74(t *testing.T, d *Database, n int) time.Duration {
	t.Helper()
	for _, s := range []string{
		`ALTER TABLE syslog_messages DROP COLUMN IF EXISTS format`,
		`DELETE FROM schema_migrations WHERE version = 74`,
	} {
		if err := d.Gorm().Exec(s).Error; err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := d.Gorm().Exec(`INSERT INTO syslog_messages ("timestamp", device_id, probe_id, hostname, message, severity, facility, created_at)
		SELECT now() - (g % 86400) * interval '1 second', 1, 1, 'fw-example-01', 'action=deny dst=203.0.113.' || (g % 250), 5, 20, now()
		FROM generate_series(1, ?) g`, n).Error; err != nil {
		t.Fatalf("seed %d rows: %v", n, err)
	}
	before := syslogRelfilenodes(t, d)
	start := time.Now()
	if err := d.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations (applies v74): %v", err)
	}
	took := time.Since(start)
	if after := syslogRelfilenodes(t, d); len(after) != len(before) {
		t.Fatalf("relations changed: %v -> %v", before, after)
	} else {
		for rel, node := range before {
			if after[rel] != node {
				t.Errorf("%s relfilenode %d -> %d: v74 REWROTE the table", rel, node, after[rel])
			}
		}
	}
	assertFormatColumn(t, d)
	var nonNull int64
	d.Gorm().Raw(`SELECT count(*) FROM syslog_messages WHERE format IS NOT NULL`).Scan(&nonNull)
	if nonNull != 0 {
		t.Errorf("%d existing rows read a non-NULL format, want 0", nonNull)
	}
	var recorded int64
	d.Gorm().Raw(`SELECT count(*) FROM schema_migrations WHERE version = 74 AND name = 'syslog_format_column'`).Scan(&recorded)
	if recorded != 1 {
		t.Fatalf("v74 recorded %d times, want 1", recorded)
	}
	return took
}

// roundTripFormat saves rows through the ingest's writer and reads the
// stored codes back.
func roundTripFormat(t *testing.T, d *Database) {
	t.Helper()
	now := time.Now().UTC()
	msgs := []models.SyslogMessage{
		{Timestamp: now, DeviceID: 1, ProbeID: 1, Hostname: "fw-example-01", Message: "rt-framed", Severity: 5, StoredFormat: models.SyslogFormatCode("fortios_kv")},
		{Timestamp: now, DeviceID: 1, ProbeID: 1, Hostname: "fw-example-01", Message: "rt-legacy", Severity: 5},
	}
	if err := d.SaveSyslogMessages(msgs); err != nil {
		t.Fatalf("SaveSyslogMessages: %v", err)
	}
	var got []models.SyslogMessage
	if err := d.Gorm().Where("message LIKE 'rt-%'").Order("message").Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || models.SyslogFormatName(got[0].StoredFormat) != "fortios_kv" || got[1].StoredFormat != nil {
		t.Fatalf("round trip: %+v", got)
	}
	if err := d.Gorm().Exec(`DELETE FROM syslog_messages WHERE message LIKE 'rt-%'`).Error; err != nil {
		t.Fatal(err)
	}
}

func TestSyslogFormatColumnV74_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	if !pgIsPartitioned(t, d, "syslog_messages") {
		t.Fatal("syslog_messages is not partitioned on the fresh-install path")
	}

	t.Run("FreshInstallPartitioned", func(t *testing.T) {
		// The baseline AutoMigrate created the column before v2 partitioned
		// the table; every leaf has it, and v74 found it and took no lock.
		assertFormatColumn(t, d)
		roundTripFormat(t, d)
	})

	t.Run("UpgradePartitioned", func(t *testing.T) {
		took := upgradeV74(t, d, 50000)
		t.Logf("v74 on the partitioned parent (%d leaves, 50 000 rows): %s", len(syslogRelfilenodes(t, d)), took)
		roundTripFormat(t, d)
	})

	t.Run("LockTimeoutKeepsIngestMoving", func(t *testing.T) {
		shrinkV74Lock(t, 300*time.Millisecond, 50, 700*time.Millisecond)
		if err := d.Gorm().Exec(`ALTER TABLE syslog_messages DROP COLUMN IF EXISTS format`).Error; err != nil {
			t.Fatal(err)
		}
		release := holdSyslogReader(t, d)
		done := make(chan error, 1)
		go func() { done <- d.migrateSyslogFormatColumn() }()
		time.Sleep(150 * time.Millisecond) // the first attempt is now queued for its lock
		// An insert issued while the ALTER is queued waits behind it, but only
		// until its lock_timeout gives up; then it goes through although the
		// reader still holds the table.
		inserted := make(chan error, 1)
		go func() {
			inserted <- d.Gorm().Exec(`INSERT INTO syslog_messages ("timestamp", message, severity) VALUES (now(), 'during-v74', 5)`).Error
		}()
		select {
		case err := <-inserted:
			if err != nil {
				t.Fatalf("insert during v74: %v", err)
			}
		case <-time.After(2 * time.Second):
			// Unblock everything before failing, or the test hangs.
			release()
			<-inserted
			<-done
			t.Fatal("an insert waited over 2s behind the queued ALTER; the lock_timeout (300ms) must bound it")
		}
		select {
		case err := <-done:
			t.Fatalf("v74 finished while the reader held the table: %v", err)
		case <-time.After(time.Second):
		}
		release()
		if err := <-done; err != nil {
			t.Fatalf("v74 after the reader released: %v", err)
		}
		assertFormatColumn(t, d)
	})

	t.Run("GivesUpAfterRetries", func(t *testing.T) {
		shrinkV74Lock(t, 100*time.Millisecond, 3, 50*time.Millisecond)
		if err := d.Gorm().Exec(`ALTER TABLE syslog_messages DROP COLUMN IF EXISTS format`).Error; err != nil {
			t.Fatal(err)
		}
		release := holdSyslogReader(t, d)
		res := make(chan error, 1)
		go func() { res <- d.migrateSyslogFormatColumn() }()
		var err error
		select {
		case err = <-res:
			release()
		case <-time.After(5 * time.Second):
			release()
			<-res
			t.Fatal("v74 still waiting after 5s behind a reader; each attempt must give up at its lock_timeout")
		}
		if st := sqlState(err); err == nil || (st != "55P03" && st != "57014") || !strings.Contains(err.Error(), "attempt 3/3") {
			t.Fatalf("v74 under a permanent reader = %v, want a lock/statement timeout (55P03/57014) after 3 attempts", err)
		}
		if err := d.migrateSyslogFormatColumn(); err != nil {
			t.Fatalf("v74 retry once the reader is gone: %v", err)
		}
		assertFormatColumn(t, d)
	})

	t.Run("StaggeredLeafReadersBoundInsertStall", func(t *testing.T) {
		// lock_timeout is per lock wait, and the ALTER holds ACCESS EXCLUSIVE
		// on the parent while it waits for each leaf in OID order (the order
		// find_all_inheritors locks them). Readers on every leaf, released one
		// by one just inside the lock_timeout, would walk the ALTER through
		// all of them with the parent held the whole time — every insert
		// stalled for about leaves x 250 ms. The statement_timeout caps each
		// attempt at the bound instead.
		const bound = 300 * time.Millisecond
		shrinkV74Lock(t, bound, 100, 100*time.Millisecond)
		if err := d.Gorm().Exec(`ALTER TABLE syslog_messages DROP COLUMN IF EXISTS format`).Error; err != nil {
			t.Fatal(err)
		}
		var leaves []string
		if err := d.Gorm().Raw(`SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
			WHERE i.inhparent = 'syslog_messages'::regclass ORDER BY c.oid`).Scan(&leaves).Error; err != nil {
			t.Fatal(err)
		}
		if len(leaves) < 4 {
			t.Fatalf("%d leaves; the test needs several", len(leaves))
		}
		releases := make([]func(), len(leaves))
		for i, leaf := range leaves {
			releases[i] = holdReader(t, d, leaf)
		}
		done := make(chan error, 1)
		go func() { done <- d.migrateSyslogFormatColumn() }()
		go func() {
			for _, release := range releases {
				time.Sleep(250 * time.Millisecond)
				release()
			}
		}()
		time.Sleep(50 * time.Millisecond) // the first attempt holds the parent and waits on leaf 1
		var worst time.Duration
		for migrated := false; !migrated; {
			start := time.Now()
			inserted := make(chan error, 1)
			go func() {
				inserted <- d.Gorm().Exec(`INSERT INTO syslog_messages ("timestamp", message, severity) VALUES (now(), 'during-v74-staggered', 5)`).Error
			}()
			select {
			case err := <-inserted:
				if err != nil {
					t.Fatalf("insert during v74: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("insert still blocked after 10s")
			}
			if w := time.Since(start); w > worst {
				worst = w
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("v74 with staggered leaf readers: %v", err)
				}
				migrated = true
			case <-time.After(50 * time.Millisecond):
			}
		}
		t.Logf("%d leaves; longest insert wait while v74 retried: %s (bound %s)", len(leaves), worst, bound)
		if worst > 3*bound {
			t.Errorf("an insert waited %s behind v74 (bound %s): the attempt must be capped as a whole, not per lock wait", worst, bound)
		}
		assertFormatColumn(t, d)
	})

	t.Run("UpgradePlainHeap", func(t *testing.T) {
		// Production's shape: a plain heap that was never partitioned.
		if err := d.Gorm().Exec(`DROP TABLE syslog_messages CASCADE`).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.Gorm().Migrator().CreateTable(&models.SyslogMessage{}); err != nil {
			t.Fatal(err)
		}
		if pgIsPartitioned(t, d, "syslog_messages") {
			t.Fatal("the recreated syslog_messages is partitioned; want a plain heap")
		}
		took := upgradeV74(t, d, 200000)
		t.Logf("v74 on a plain heap of 200 000 rows: %s", took)
		roundTripFormat(t, d)
	})
}

// shrinkV74Lock sets v74's lock bounds for one subtest.
func shrinkV74Lock(t *testing.T, timeout time.Duration, retries int, sleep time.Duration) {
	t.Helper()
	ot, or, osl := syslogFormatLockTimeout, syslogFormatLockRetries, syslogFormatRetrySleep
	syslogFormatLockTimeout, syslogFormatLockRetries, syslogFormatRetrySleep = timeout, retries, sleep
	t.Cleanup(func() { syslogFormatLockTimeout, syslogFormatLockRetries, syslogFormatRetrySleep = ot, or, osl })
}

// holdSyslogReader opens a transaction on its own connection that has read
// syslog_messages (ACCESS SHARE, held to commit) — a long reader the ALTER's
// ACCESS EXCLUSIVE must queue behind. The returned func ends it.
func holdSyslogReader(t *testing.T, d *Database) func() {
	t.Helper()
	return holdReader(t, d, "syslog_messages")
}

// holdReader is holdSyslogReader for any relation (a single leaf). Each
// reader gets its own connection outside the Database pool, so holding
// several never starves the code under test. The release func is safe to
// call from another goroutine and more than once.
func holdReader(t *testing.T, d *Database, rel string) func() {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("TEST_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		_ = conn.Close(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT count(*) FROM (SELECT 1 FROM `+rel+` LIMIT 1) s`); err != nil {
		_ = conn.Close(ctx)
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_ = tx.Rollback(ctx)
			_ = conn.Close(ctx)
		})
	}
	t.Cleanup(release)
	return release
}
