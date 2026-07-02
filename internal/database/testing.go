//go:build !production

package database

import (
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
		&models.Device{},
		&models.Site{},
		&models.SystemStatus{},
		&models.InterfaceStats{},
		&models.VPNStatus{},
		&models.HAStatus{},
		&models.HardwareSensor{},
		&models.ProcessorStats{},
		&models.DeviceConfigRevision{},
		&models.TrapEvent{},
		&models.SyslogMessage{},
		&models.FlowSample{},
		&models.FlowRollup{},
		&models.AgentDrops{},
		&models.FlowDetection{},
		&models.ThreatIntel{},
		&models.FlowInterfaceCounter{},
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
	}

	for _, m := range testModels {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatal("NewDatabaseForTesting: AutoMigrate:", err)
		}
	}

	return &Database{db: db, dialect: sqliteDialect{}}
}
