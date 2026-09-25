package database

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"firewall-mon/internal/models"
)

// Retention used to abandon a whole table for a day on a single statement
// timeout. Observed on production 2026-09-24:
//
//	cleanup.go:107 ERROR: canceling statement due to statement timeout (SQLSTATE 57014)
//	main.go:248: Data cleanup error: failed to cleanup syslog_message (30d):
//	batched delete (batch size 10000)
//
// The 24h ticker then reissued the identical statement, so syslog_messages
// drifted to 36 days of history under a 30-day policy (156.6M rows, 161 GB,
// +18 GB/week). The device-purge loop had already learned to halve its batch on
// 57014; retention had not.

func seedOldSyslog(t *testing.T, d *Database, n int, ts time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := d.Gorm().Create(&models.SyslogMessage{
			Timestamp: ts.Add(time.Duration(i) * time.Second),
			Message:   "old", Severity: 6,
		}).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

func pgTimeout() error   { return &pgconn.PgError{Code: "57014", Message: "canceling statement"} }
func pgLockError() error { return &pgconn.PgError{Code: "55P03", Message: "lock timeout"} }

// TestRetentionDelete_HalvesTheBatchOnStatementTimeout: a batch that times out
// must be retried smaller, and the pass must still delete everything.
func TestRetentionDelete_HalvesTheBatchOnStatementTimeout(t *testing.T) {
	d := NewDatabaseForTesting(t)
	old := time.Now().Add(-48 * time.Hour)
	seedOldSyslog(t, d, 12, old)

	origBatch, origFloor := cleanupDeleteBatchSize, batchDeleteFloor
	origSleep := batchDeleteInterSleep
	cleanupDeleteBatchSize, batchDeleteFloor = 8, 1
	batchDeleteInterSleep = 0
	defer func() {
		cleanupDeleteBatchSize, batchDeleteFloor = origBatch, origFloor
		batchDeleteInterSleep = origSleep
	}()

	var sizes []int
	fails := 2
	cleanupBatchHook = func(batchSize int) error {
		sizes = append(sizes, batchSize)
		if fails > 0 {
			fails--
			return pgTimeout()
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", time.Now(), ""); err != nil {
		t.Fatalf("a timed-out batch must be retried smaller, not abandon the table: %v", err)
	}
	if len(sizes) < 3 || sizes[0] != 8 || sizes[1] != 4 || sizes[2] != 2 {
		t.Errorf("batch sizes tried = %v, want the first three to halve 8, 4, 2", sizes)
	}
	var left int64
	d.Gorm().Model(&models.SyslogMessage{}).Count(&left)
	if left != 0 {
		t.Errorf("%d rows survived a cleanup that reported success", left)
	}
}

// TestRetentionDelete_RetriesTheSameBatchOnLockTimeout: a lock conflict (a
// partition DROP queued ahead of the delete) must not abandon the table either,
// and must NOT shrink the batch — the batch size was never the problem.
func TestRetentionDelete_RetriesTheSameBatchOnLockTimeout(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 5, time.Now().Add(-48*time.Hour))

	origBatch, origSleep, origLockSleep := cleanupDeleteBatchSize, batchDeleteInterSleep, batchDeleteLockRetrySleep
	cleanupDeleteBatchSize, batchDeleteInterSleep, batchDeleteLockRetrySleep = 8, 0, time.Millisecond
	defer func() {
		cleanupDeleteBatchSize, batchDeleteInterSleep, batchDeleteLockRetrySleep = origBatch, origSleep, origLockSleep
	}()

	var sizes []int
	fails := 3
	cleanupBatchHook = func(batchSize int) error {
		sizes = append(sizes, batchSize)
		if fails > 0 {
			fails--
			return pgLockError()
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", time.Now(), ""); err != nil {
		t.Fatalf("a lock-blocked batch must be retried, not abandon the table: %v", err)
	}
	for i, got := range sizes {
		if got != 8 {
			t.Errorf("attempt %d used batch %d, want 8 — a lock timeout says nothing about "+
				"the batch being too big, so it must not shrink", i, got)
		}
	}
	var left int64
	d.Gorm().Model(&models.SyslogMessage{}).Count(&left)
	if left != 0 {
		t.Errorf("%d rows survived a cleanup that reported success", left)
	}
}

// TestRetentionDelete_GivesUpAtTheFloor: halving is bounded. Below the floor the
// error must surface so the operator sees it, rather than looping forever.
func TestRetentionDelete_GivesUpAtTheFloor(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 4, time.Now().Add(-48*time.Hour))

	origBatch, origFloor, origSleep := cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep
	cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep = 8, 4, 0
	defer func() {
		cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep = origBatch, origFloor, origSleep
	}()

	attempts := 0
	cleanupBatchHook = func(int) error { attempts++; return pgTimeout() }
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", time.Now(), ""); err == nil {
		t.Fatal("a batch still timing out at the floor must return the error, not report success")
	}
	if attempts > 4 {
		t.Errorf("%d attempts before giving up; halving from 8 with floor 4 must stop after 2", attempts)
	}
}

// TestRetentionDelete_OrdersTheSubquery pins the ORDER BY, which is the defence
// that stops the timeouts arising in the first place.
//
// Unordered, the subquery's LIMIT takes whatever rows the scan reaches first, so
// PostgreSQL may seq-scan and re-walk the dead tuples earlier batches left —
// each batch costing more than the last until one exceeds the timeout. That is
// exactly what batchedDeleteWhere's comment predicted for a 134M-row
// syslog_messages, and what production hit on 2026-09-24. Ordered on the time
// column, it walks that column's index forward from the oldest live row and
// stops at LIMIT.
//
// This asserts the SQL shape rather than the rows deleted, deliberately: the
// property is a PostgreSQL planner one, and on the SQLite test lane it cannot be
// observed at all — SQLite picks the timestamp index for this predicate with or
// without the ORDER BY, so every behavioural assertion passes either way. Tried
// and discarded: seeding newest-first so physical order differs from time order
// still passes unordered, because the index is used regardless.
func TestRetentionDelete_OrdersTheSubquery(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 2, time.Now().Add(-48*time.Hour))

	var deleteSQL string
	if err := d.Gorm().Callback().Delete().After("gorm:delete").
		Register("test:capture_cleanup_delete", func(tx *gorm.DB) {
			if sql := tx.Statement.SQL.String(); strings.Contains(sql, "syslog_messages") {
				deleteSQL = sql
			}
		}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	defer func() { _ = d.Gorm().Callback().Delete().Remove("test:capture_cleanup_delete") }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", time.Now(), ""); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleteSQL == "" {
		t.Fatal("no DELETE against syslog_messages was captured")
	}
	if !strings.Contains(deleteSQL, "ORDER BY") {
		t.Errorf("the cleanup subquery is unordered:\n  %s\nWithout ORDER BY, PostgreSQL may "+
			"seq-scan the heap and re-walk the dead tuples previous batches left, so each "+
			"batch costs more than the last until one blows the statement timeout.", deleteSQL)
	}
}
