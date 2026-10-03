package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// A table whose cleanup fails for good — system_status timing out at the
// batch floor, say — used to end the whole daily pass at that table: every
// table after it (syslog_messages, alerts, incidents) was skipped that day,
// and every day the failure persisted. The pass now runs every table and
// reports the failures together.
func TestCleanupOldData_ContinuesPastAFailingTable(t *testing.T) {
	d := NewDatabaseForTesting(t)
	old := time.Now().AddDate(0, 0, -60)
	if err := d.Gorm().Create(&models.SystemStatus{DeviceID: 1, Timestamp: old}).Error; err != nil {
		t.Fatal(err)
	}
	seedOldSyslog(t, d, 3, old)
	if err := d.Gorm().Create(&models.Alert{DeviceID: 1, Timestamp: old, Acknowledged: true,
		AlertType: "X", Severity: models.SeverityWarning, Message: "old"}).Error; err != nil {
		t.Fatal(err)
	}

	origSleep := batchDeleteInterSleep
	batchDeleteInterSleep = 0
	defer func() { batchDeleteInterSleep = origSleep }()

	// The first batch of the pass belongs to system_status, the first entry.
	// A non-retryable error there fails that table only.
	calls := 0
	cleanupBatchHook = func(int) error {
		calls++
		if calls == 1 {
			return errors.New("disk on fire")
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	err := d.CleanupOldData(config.RetentionConfig{StatusDays: 30, AlertDays: 30})
	if err == nil || !strings.Contains(err.Error(), "failed to cleanup system_status") || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("error = %v, want the system_status failure reported", err)
	}
	var status, syslog, alerts int64
	d.Gorm().Model(&models.SystemStatus{}).Count(&status)
	d.Gorm().Model(&models.SyslogMessage{}).Count(&syslog)
	d.Gorm().Model(&models.Alert{}).Count(&alerts)
	if status != 1 {
		t.Errorf("system_status rows = %d, want 1 (its cleanup failed)", status)
	}
	if syslog != 0 || alerts != 0 {
		t.Errorf("syslog_messages=%d alerts=%d rows survived; the tables after a failing one must still be cleaned", syslog, alerts)
	}
}

// Two failing tables are both reported, not just the first.
func TestCleanupOldData_ReportsEveryFailingTable(t *testing.T) {
	d := NewDatabaseForTesting(t)
	old := time.Now().AddDate(0, 0, -60)
	if err := d.Gorm().Create(&models.SystemStatus{DeviceID: 1, Timestamp: old}).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Gorm().Create(&models.InterfaceStats{DeviceID: 1, Timestamp: old}).Error; err != nil {
		t.Fatal(err)
	}
	origSleep := batchDeleteInterSleep
	batchDeleteInterSleep = 0
	defer func() { batchDeleteInterSleep = origSleep }()
	calls := 0
	cleanupBatchHook = func(int) error {
		calls++
		if calls <= 2 { // system_status, then interface_stats
			return errors.New("boom")
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	err := d.CleanupOldData(config.RetentionConfig{StatusDays: 30})
	if err == nil || !strings.Contains(err.Error(), "system_status") || !strings.Contains(err.Error(), "interface_stats") {
		t.Fatalf("error = %v, want both failing tables named", err)
	}
}

// A batch halved after a statement timeout grows back once a few full
// batches have succeeded at the smaller size, never past the configured
// size. Before, the rest of the table's pass stayed at the halved size.
func TestRetentionDelete_HalvedBatchGrowsBack(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 60, time.Now().Add(-48*time.Hour))

	origBatch, origFloor, origSleep, origGrow := cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep, batchDeleteGrowAfter
	cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep, batchDeleteGrowAfter = 8, 1, 0, 2
	defer func() {
		cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep, batchDeleteGrowAfter = origBatch, origFloor, origSleep, origGrow
	}()

	var sizes []int
	failed := false
	cleanupBatchHook = func(batchSize int) error {
		sizes = append(sizes, batchSize)
		if !failed {
			failed = true
			return pgTimeout()
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	// 8 (timeout) → 4, 4 succeed → back to 8 for the rest: 60 rows is
	// 8 + 4 + 4 + 8 + ... so the sequence must contain a return to 8 after
	// the two 4s, and never exceed 8.
	want := []int{8, 4, 4, 8}
	if len(sizes) < len(want) {
		t.Fatalf("batch sizes tried = %v, want at least %v", sizes, want)
	}
	for i, w := range want {
		if sizes[i] != w {
			t.Fatalf("batch sizes tried = %v, want to begin %v (halve, two full batches, grow back)", sizes, want)
		}
	}
	for _, s := range sizes {
		if s > 8 {
			t.Fatalf("batch sizes tried = %v: grew past the configured size", sizes)
		}
	}
	var left int64
	d.Gorm().Model(&models.SyslogMessage{}).Count(&left)
	if left != 0 {
		t.Errorf("%d rows survived", left)
	}
}

// Where the full size times out every time and the halved size never does,
// an unbounded grow-back would re-try the full size after every few
// successes and burn the 120 s statement_timeout plus a rollback each time.
// At most one grow-back per pass: two timeouts in all, and the pass completes
// at the halved size.
func TestRetentionDelete_GrowBackIsOncePerPass(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedOldSyslog(t, d, 60, time.Now().Add(-48*time.Hour))

	origBatch, origFloor, origSleep, origGrow := cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep, batchDeleteGrowAfter
	cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep, batchDeleteGrowAfter = 8, 1, 0, 2
	defer func() {
		cleanupDeleteBatchSize, batchDeleteFloor, batchDeleteInterSleep, batchDeleteGrowAfter = origBatch, origFloor, origSleep, origGrow
	}()

	timeouts := 0
	cleanupBatchHook = func(batchSize int) error {
		if batchSize == 8 {
			timeouts++
			return pgTimeout()
		}
		return nil
	}
	defer func() { cleanupBatchHook = nil }()

	if err := d.batchedDeleteOlderThanOn(&models.SyslogMessage{}, "timestamp", "timestamp", time.Now(), ""); err != nil {
		t.Fatalf("the pass must complete at the halved size: %v", err)
	}
	if timeouts != 2 {
		t.Fatalf("%d statement timeouts in one pass; want exactly 2 (the first, and one grow-back attempt)", timeouts)
	}
	var left int64
	d.Gorm().Model(&models.SyslogMessage{}).Count(&left)
	if left != 0 {
		t.Errorf("%d rows survived", left)
	}
}
