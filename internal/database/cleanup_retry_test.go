package database

import (
	"errors"
	"fmt"
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
//	main.go:248: Data cleanup error: failed to cleanup syslog_message
//	(severities [0 1 2 3 4 5], 30d): batched delete (batch size 10000)
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

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err != nil {
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

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err != nil {
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

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err == nil {
		t.Fatal("a batch still timing out at the floor must return the error, not report success")
	}
	// Exactly two: 8, then 4 (== floor, so no further halving). ">" would not
	// catch a spurious extra retry.
	if attempts != 2 {
		t.Errorf("%d attempts before giving up; halving from 8 with floor 4 must stop after 2", attempts)
	}
}

// TestRetentionDelete_OrdersOnlyTimeIndexedTables pins the gate in BOTH
// directions, which is the part that is easy to get catastrophically wrong.
//
// Measured on production, same predicate and LIMIT 10000:
//
//	syslog_messages  unordered 4,755 ms / 184,814 reads -> ordered    40 ms / 1,137
//	interface_stats  unordered     7 ms /     265 reads -> ordered 5,417 ms / 432,663
//
// 118x faster on the first, 765x SLOWER on the second (a full scan plus top-N
// heapsort per batch, because its only time index is composite and PG16 has no
// skip scan). So this asserts both that an allow-listed table IS ordered and that
// a composite-index table is NOT — the second is the regression the gate exists
// to prevent, and an earlier revision of this change would have shipped it.
//
// SQL shape rather than rows deleted, deliberately: SQLite picks the timestamp
// index for this predicate either way, so no behavioural assertion can tell the
// difference there — seeding newest-first to break the tie does not help. The
// behavioural pin is TestRetentionDeleteIntegration_DeletesOldestFirst, in the
// PostgreSQL lane.
func TestRetentionDelete_OrdersOnlyTimeIndexedTables(t *testing.T) {
	for _, tc := range []struct {
		name      string
		table     string
		model     interface{}
		wantOrder bool
		why       string
	}{
		{"time-indexed", "syslog_messages", &models.SyslogMessage{}, true,
			"syslog_messages has a standalone timestamp index; ordering is 118x faster"},
		{"composite-only", "interface_stats", &models.InterfaceStats{}, false,
			"interface_stats has only (device_id, timestamp); ordering is 765x SLOWER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			var deleteSQL string
			if err := d.Gorm().Callback().Delete().After("gorm:delete").
				Register("test:capture", func(tx *gorm.DB) {
					if sql := tx.Statement.SQL.String(); strings.Contains(sql, tc.table) {
						deleteSQL = sql
					}
				}); err != nil {
				t.Fatalf("register callback: %v", err)
			}
			defer func() { _ = d.Gorm().Callback().Delete().Remove("test:capture") }()

			if err := d.batchedDeleteOlderThan(tc.model, tc.table, time.Now()); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if deleteSQL == "" {
				t.Fatalf("no DELETE against %s was captured", tc.table)
			}
			if got := strings.Contains(deleteSQL, "ORDER BY"); got != tc.wantOrder {
				t.Errorf("ORDER BY present = %v, want %v for %s.\n  %s\n  %s",
					got, tc.wantOrder, tc.table, tc.why, deleteSQL)
			}
		})
	}
}

// TestRetentionDelete_GivesUpAfterTheLockRetryBudget: the 55P03 retry is bounded.
// Unbounded — or with a reset that stops the budget ever exhausting — this would
// hold maintenanceLockKey indefinitely, and that lock is shared with the rollup
// tick, which would be skipped for as long as the retry spun. (Before v0.11.256
// the lock was the work lock, and what it skipped was alert evaluation.)
func TestRetentionDelete_GivesUpAfterTheLockRetryBudget(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 4, time.Now().Add(-48*time.Hour))

	origSleep, origRetries := batchDeleteLockRetrySleep, batchDeleteLockRetries
	batchDeleteLockRetrySleep, batchDeleteLockRetries = time.Millisecond, 3
	defer func() { batchDeleteLockRetrySleep, batchDeleteLockRetries = origSleep, origRetries }()

	attempts := 0
	cleanupBatchHook = func(int) error { attempts++; return pgLockError() }
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err == nil {
		t.Fatal("a batch blocked past the retry budget must return the error, not loop forever")
	}
	if attempts != 4 {
		t.Errorf("attempts = %d, want 4 (one try plus %d retries)", attempts, batchDeleteLockRetries)
	}
}

func pgDeadlock() error { return &pgconn.PgError{Code: "40P01", Message: "deadlock detected"} }

// TestRetentionDelete_RetriesTheSameBatchOnDeadlock: since v0.11.256 the alert
// engine's multi-row auto-resolve UPDATE runs alongside retention, and on `alerts`
// the two can deadlock. The victim's batch is rolled back whole, so it must be
// retried unchanged — before this, one 40P01 returned from CleanupOldData and
// skipped every table after alerts until the next day. The hook fires before any
// SQL, so this pins the retry decision, not PG's rollback of a real deadlock.
func TestRetentionDelete_RetriesTheSameBatchOnDeadlock(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 5, time.Now().Add(-48*time.Hour))

	origBatch, origSleep, origLockSleep := cleanupDeleteBatchSize, batchDeleteInterSleep, batchDeleteLockRetrySleep
	cleanupDeleteBatchSize, batchDeleteInterSleep, batchDeleteLockRetrySleep = 8, 0, time.Millisecond
	defer func() {
		cleanupDeleteBatchSize, batchDeleteInterSleep, batchDeleteLockRetrySleep = origBatch, origSleep, origLockSleep
	}()

	var sizes []int
	fails := 2
	cleanupBatchHook = func(batchSize int) error {
		sizes = append(sizes, batchSize)
		if fails > 0 {
			fails--
			return pgDeadlock()
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err != nil {
		t.Fatalf("a deadlocked batch must be retried, not abandon the pass: %v", err)
	}
	for i, got := range sizes {
		if got != 8 {
			t.Errorf("attempt %d used batch %d, want 8 — a deadlock says nothing about the batch size", i, got)
		}
	}
	var left int64
	d.Gorm().Model(&models.SyslogMessage{}).Count(&left)
	if left != 0 {
		t.Errorf("%d rows survived a cleanup that reported success", left)
	}
}

// TestLockRetryable pins the classification both batch loops share. The purge
// loop's own hook fires before its transaction and returns directly, so it cannot
// reach the switch; the predicate is what makes the two loops agree.
func TestLockRetryable(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{pgLockError(), true},
		{pgDeadlock(), true},
		{fmt.Errorf("wrapped: %w", pgDeadlock()), true},
		{pgTimeout(), false}, // halved, not retried as-is
		{&pgconn.PgError{Code: "23505"}, false},
		{errors.New("plain"), false},
		{nil, false},
	} {
		if got := lockRetryable(tc.err); got != tc.want {
			t.Errorf("lockRetryable(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestAndFloor: a zero floor must leave the predicate untouched, so a normal day's
// DELETE is byte-identical to the one it replaced (and SQLite never sees it); a
// set floor is ANDed on without mutating the caller's args.
func TestAndFloor(t *testing.T) {
	if w, a := andFloor("", nil, time.Time{}); w != "" || a != nil {
		t.Errorf("zero floor, no predicate: got %q %v, want empty", w, a)
	}
	if w, a := andFloor("severity = ?", []interface{}{5}, time.Time{}); w != "severity = ?" || len(a) != 1 {
		t.Errorf("zero floor must not touch the predicate: got %q %v", w, a)
	}
	floor := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if w, a := andFloor("", nil, floor); w != "timestamp >= ?" || len(a) != 1 || a[0] != floor {
		t.Errorf("floor on empty predicate: got %q %v", w, a)
	}
	args := make([]interface{}, 1, 4)
	args[0] = []int{5, 6}
	w, a := andFloor("severity IN ?", args, floor)
	if w != "severity IN ? AND timestamp >= ?" || len(a) != 2 || a[1] != floor {
		t.Errorf("floor on existing predicate: got %q %v", w, a)
	}
	if len(args) != 1 {
		t.Errorf("andFloor mutated the caller's args slice to len %d", len(args))
	}
}
