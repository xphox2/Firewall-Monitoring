//go:build !production

package database

import (
	"time"

	"firewall-mon/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewDatabaseForTesting creates an in-memory SQLite Database for use in tests.
// The returned Database has no batch inserters (syslogBatch etc. are nil) since
// handlers use db.Gorm().Create() directly for single-record writes.
func NewDatabaseForTesting(t interface {
	Helper()
	Fatal(...interface{})
}) *Database {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal("NewDatabaseForTesting: open SQLite:", err)
	}

	testModels := []interface{}{
		&models.Probe{},
		&models.ProbeApproval{},
		&models.ProbeHeartbeat{},
		&models.ProbeCommand{},
		&models.IPSecTunnel{},
		&models.Device{},
		&models.Site{},
		&models.SystemStatus{},
		&models.ServerMetric{},
		&models.InterfaceStats{},
		&models.VPNStatus{},
		&models.HAStatus{},
		// LC-20: the remaining per-poll status tables, now covered by
		// CleanupOldData's entries slice (vpn_status/ha_status are above).
		&models.SecurityStats{},
		&models.SDWANHealth{},
		&models.LicenseInfo{},
		&models.HardwareSensor{},
		&models.ProcessorStats{},
		&models.DiskUsage{},
		&models.LoadAverage{},
		&models.TopologyEntry{},
		&models.TopologyNeighbor{},
		&models.DeviceConfigRevision{},
		&models.TrapEvent{},
		&models.SyslogMessage{},
		&models.FlowSample{},
		&models.FlowRollup{},
		&models.AgentDrops{},
		&models.FlowDetection{},
		&models.ThreatIntel{},
		&models.ThreatFeedStatus{},
		&models.FlowInterfaceCounter{},
		&models.DeniedEvent{},
		&models.Alert{},
		&models.AlertPolicy{},
		&models.AlertRule{},
		&models.DeviceAlertConfig{},
		&models.SiteAlertConfig{},
		&models.MaintenanceWindow{},
		&models.PingResult{},
		&models.PingStats{},
		// AUDIT-029: the four tables that the cleanup regression
		// tests exercise. They were previously missing from
		// this list, which made the test discover the missing
		// AutoMigrate as a "no such table" failure rather than
		// the actual audit-029 row-preservation failure.
		&models.InterfaceErrors{},
		&models.ProcessStats{},
		&models.InterfaceAddress{},
		&models.DeviceConnection{},
		&models.LoginAttempt{},
		&models.AuditLog{},
		&models.IRCMessageLog{},
		&models.SyslogSummary{},
		&models.UptimeRecord{},
		&models.ProcessedBatch{},
		&models.SystemSetting{},
		&models.Admin{},
		&models.ApiToken{},
		&models.AdminRecoveryCode{},
		&models.Incident{},
		// v0.11.46: flow-source silencing table.
		&models.FlowSourceSuppression{},
		// Event-rule engine (v35+): rules.
		&models.EventRule{},
		// Event Rule Profiles (v48): profile + sparse toggle matrix.
		&models.EventRuleProfile{},
		&models.EventRuleProfileToggle{},
		// v59: syslog ingest meter buckets.
		&models.SyslogIngestHourly{},
	}

	for _, m := range testModels {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatal("NewDatabaseForTesting: AutoMigrate:", err)
		}
	}

	// Device names are unique among ACTIVE devices only (migration v63). The
	// harness runs AutoMigrate, never registeredMigrations, so the partial
	// unique index is applied here so unit tests exercise the real constraint.
	// The DROP guards against a unique idx_devices_name from an older model
	// tag; the current tag declares a plain index, which is left in place.
	var uniqueName int64
	db.Raw(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_devices_name' AND sql LIKE 'CREATE UNIQUE%'`).Scan(&uniqueName)
	if uniqueName > 0 {
		if err := db.Exec(`DROP INDEX IF EXISTS idx_devices_name`).Error; err != nil {
			t.Fatal("NewDatabaseForTesting: drop unique idx_devices_name:", err)
		}
		if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_name ON devices (name)`).Error; err != nil {
			t.Fatal("NewDatabaseForTesting: create idx_devices_name:", err)
		}
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_name_active ON devices (name) WHERE retired_at IS NULL`).Error; err != nil {
		t.Fatal("NewDatabaseForTesting: create idx_devices_name_active:", err)
	}

	// The ingest meter is real here: SaveSyslogMessages must count on the test
	// backend exactly as it does in production, and the meter is the only
	// producer of syslog_ingest_hourly.
	return &Database{db: db, dialect: sqliteDialect{}, ingest: newSyslogIngestMeter(time.Now)}
}

// SetEncryptionKeyForTesting installs an AES key derived from secret so that
// tests outside this package (e.g. the API handlers) can assert real
// encrypted-at-rest behavior ({enc} prefix in stored rows) instead of the
// plaintext passthrough a keyless test Database gives. Test-only — this file
// is build-tagged !production alongside NewDatabaseForTesting.
func (d *Database) SetEncryptionKeyForTesting(secret string) {
	d.encKeys = keyChain{current: deriveKey(secret)}
}
