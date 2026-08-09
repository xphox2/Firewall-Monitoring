package database

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// TestDropRedundantSyslogDeviceIndex_V56 pins that migration v56 removes
// idx_syslog_messages_device_id and leaves the composite that supersedes it.
//
// The single-column index is a strict leading prefix of idx_syslog_device_ts
// (device_id, timestamp), so it can serve no query the composite cannot. On
// production it cost 881 MB for 14 scans over the life of the database.
func TestDropRedundantSyslogDeviceIndex_V56(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Recreate the index a pre-v56 database would carry, so the migration has
	// something to remove rather than passing vacuously.
	if err := d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_syslog_messages_device_id ON syslog_messages (device_id)`).Error; err != nil {
		t.Fatalf("seed legacy index: %v", err)
	}

	if err := d.migrateDropRedundantSyslogDeviceIndex(); err != nil {
		t.Fatalf("v56: %v", err)
	}

	var names []string
	if err := d.db.Raw(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='syslog_messages'`).Scan(&names).Error; err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	joined := strings.Join(names, ",")

	if strings.Contains(joined, "idx_syslog_messages_device_id") {
		t.Errorf("idx_syslog_messages_device_id survived v56; indexes = %v", names)
	}
	// The composite must remain — it is what the device-filtered syslog page
	// depends on, and dropping the narrow index is only safe because it exists.
	if !strings.Contains(joined, "idx_syslog_device_ts") {
		t.Errorf("idx_syslog_device_ts is missing after v56; dropping the narrow index "+
			"is only safe while the composite covers it. indexes = %v", names)
	}

	// Idempotent: a re-run on an already-migrated database must not error.
	if err := d.migrateDropRedundantSyslogDeviceIndex(); err != nil {
		t.Errorf("v56 re-run must be idempotent, got: %v", err)
	}
}

// TestSyslogMessageModel_NoStandaloneDeviceIndex stops a fresh install from
// recreating what v56 drops. AutoMigrate builds indexes from struct tags, so a
// bare `index` on DeviceID would rebuild the redundant one on every new
// deployment and quietly undo the migration for everybody but existing installs.
func TestSyslogMessageModel_NoStandaloneDeviceIndex(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var names []string
	if err := d.db.Raw(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='syslog_messages'`).Scan(&names).Error; err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	joined := strings.Join(names, ",")

	if strings.Contains(joined, "idx_syslog_messages_device_id") {
		t.Errorf("AutoMigrate recreated idx_syslog_messages_device_id from the model tags — "+
			"the standalone `index` on SyslogMessage.DeviceID must stay removed, or every "+
			"fresh install carries the redundant index v56 exists to drop. indexes = %v", names)
	}
	if !strings.Contains(joined, "idx_syslog_device_ts") {
		t.Errorf("idx_syslog_device_ts absent from a fresh AutoMigrate; the composite must "+
			"survive removing the standalone tag. indexes = %v", names)
	}
}
