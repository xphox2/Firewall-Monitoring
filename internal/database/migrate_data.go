package database

import (
	"fmt"
	"log"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TableMigrationStatus tracks the migration progress for a single table.
type TableMigrationStatus struct {
	TableName string `json:"table_name"`
	TotalRows int64  `json:"total_rows"`
	Migrated  int64  `json:"migrated"`
	Status    string `json:"status"` // pending, running, done, skipped, error
	Error     string `json:"error,omitempty"`
}

// MigrationState holds the overall state of a SQLite→PostgreSQL data migration.
type MigrationState struct {
	mu         sync.RWMutex
	Running    bool                   `json:"running"`
	Tables     []TableMigrationStatus `json:"tables"`
	StartedAt  *time.Time             `json:"started_at,omitempty"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
	Error      string                 `json:"error,omitempty"`
	SourcePath string                 `json:"source_path"`
}

// MigrationSnapshot is a mutex-free copy of MigrationState for JSON serialization.
type MigrationSnapshot struct {
	Running    bool                   `json:"running"`
	Tables     []TableMigrationStatus `json:"tables"`
	StartedAt  *time.Time             `json:"started_at,omitempty"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
	Error      string                 `json:"error,omitempty"`
	SourcePath string                 `json:"source_path"`
}

// Snapshot returns a deep copy of the migration state, safe for JSON serialization.
func (ms *MigrationState) Snapshot() MigrationSnapshot {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	snap := MigrationSnapshot{
		Running:    ms.Running,
		StartedAt:  ms.StartedAt,
		FinishedAt: ms.FinishedAt,
		Error:      ms.Error,
		SourcePath: ms.SourcePath,
	}
	snap.Tables = make([]TableMigrationStatus, len(ms.Tables))
	copy(snap.Tables, ms.Tables)
	return snap
}

type tableEntry struct {
	model     interface{}
	tableName string
	batchSize int
}

// MigrateFromSQLite copies all rows from the source SQLite database into the
// current (PostgreSQL) database. Progress is reported via state. This method
// is intended to be called in a goroutine.
func (d *Database) MigrateFromSQLite(sourceDBPath string, state *MigrationState) {
	now := time.Now()
	state.mu.Lock()
	state.Running = true
	state.StartedAt = &now
	state.FinishedAt = nil
	state.Error = ""
	state.SourcePath = sourceDBPath
	state.mu.Unlock()

	defer func() {
		fin := time.Now()
		state.mu.Lock()
		state.Running = false
		state.FinishedAt = &fin
		state.mu.Unlock()
	}()

	// Open source SQLite read-only
	srcDB, err := gorm.Open(sqlite.Open(sourceDBPath+"?mode=ro"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		state.mu.Lock()
		state.Error = fmt.Sprintf("failed to open source database: %v", err)
		state.mu.Unlock()
		log.Printf("[migrate] %s", state.Error)
		return
	}
	sqlDB, err := srcDB.DB()
	if err != nil {
		state.mu.Lock()
		state.Error = fmt.Sprintf("failed to get underlying sql.DB: %v", err)
		state.mu.Unlock()
		return
	}
	defer sqlDB.Close()

	// FK-safe order: parents before children, high-volume tables get larger batches
	tables := []tableEntry{
		// No FK dependencies
		{&[]models.Admin{}, "admins", 500},
		{&[]models.SystemSetting{}, "system_settings", 500},
		{&[]models.LoginAttempt{}, "login_attempts", 500},
		// Self-referential
		{&[]models.Site{}, "sites", 500},
		// → Site
		{&[]models.Probe{}, "probes", 500},
		// → Site, Probe
		{&[]models.Device{}, "devices", 500},
		// → Device
		{&[]models.DeviceTunnel{}, "device_tunnels", 500},
		{&[]models.DeviceConnection{}, "device_connections", 500},
		// → Probe
		{&[]models.ProbeApproval{}, "probe_approvals", 500},
		{&[]models.ProbeHeartbeat{}, "probe_heartbeats", 500},
		// Device-dependent telemetry
		{&[]models.SystemStatus{}, "system_status", 1000},
		{&[]models.InterfaceStats{}, "interface_stats", 1000},
		{&[]models.VPNStatus{}, "vpn_status", 1000},
		{&[]models.HAStatus{}, "ha_status", 500},
		{&[]models.HardwareSensor{}, "hardware_sensors", 500},
		{&[]models.ProcessorStats{}, "processor_stats", 500},
		{&[]models.TrapEvent{}, "trap_events", 500},
		{&[]models.Alert{}, "alerts", 500},
		{&[]models.UptimeRecord{}, "uptime_records", 500},
		{&[]models.SecurityStats{}, "security_stats", 500},
		{&[]models.SDWANHealth{}, "sdwan_health", 500},
		{&[]models.LicenseInfo{}, "license_info", 500},
		{&[]models.InterfaceAddress{}, "interface_addresses", 500},
		{&[]models.PingResult{}, "ping_results", 1000},
		{&[]models.PingStats{}, "ping_stats", 500},
		{&[]models.SyslogMessage{}, "syslog_messages", 1000},
		{&[]models.FlowSample{}, "flow_samples", 1000},
		// → Site
		{&[]models.SiteDatabase{}, "site_databases", 500},
		// IRC tables
		{&[]models.IRCServer{}, "irc_servers", 500},
		{&[]models.IRCChannel{}, "irc_channels", 500},
		{&[]models.IRCCommand{}, "irc_commands", 500},
		{&[]models.IRCMessageLog{}, "irc_message_logs", 500},
	}

	// Initialize table statuses
	state.mu.Lock()
	state.Tables = make([]TableMigrationStatus, len(tables))
	for i, t := range tables {
		state.Tables[i] = TableMigrationStatus{
			TableName: t.tableName,
			Status:    "pending",
		}
	}
	state.mu.Unlock()

	for i, t := range tables {
		d.migrateTable(srcDB, state, i, t)
	}

	log.Println("[migrate] data migration complete")
}

// migrateTable copies one table from source to target.
func (d *Database) migrateTable(srcDB *gorm.DB, state *MigrationState, idx int, t tableEntry) {
	tableName := t.tableName

	// Count rows in source
	var srcCount int64
	if err := srcDB.Table(tableName).Count(&srcCount).Error; err != nil {
		state.mu.Lock()
		state.Tables[idx].Status = "error"
		state.Tables[idx].Error = fmt.Sprintf("count source: %v", err)
		state.mu.Unlock()
		log.Printf("[migrate] %s: failed to count source rows: %v", tableName, err)
		return
	}

	state.mu.Lock()
	state.Tables[idx].TotalRows = srcCount
	state.Tables[idx].Status = "running"
	state.mu.Unlock()

	if srcCount == 0 {
		state.mu.Lock()
		state.Tables[idx].Status = "done"
		state.mu.Unlock()
		log.Printf("[migrate] %s: 0 rows, skipping", tableName)
		return
	}

	// Check if target already has data → skip for idempotency
	var dstCount int64
	if err := d.db.Table(tableName).Count(&dstCount).Error; err != nil {
		state.mu.Lock()
		state.Tables[idx].Status = "error"
		state.Tables[idx].Error = fmt.Sprintf("count target: %v", err)
		state.mu.Unlock()
		log.Printf("[migrate] %s: failed to count target rows: %v", tableName, err)
		return
	}
	if dstCount > 0 {
		state.mu.Lock()
		state.Tables[idx].Status = "skipped"
		state.Tables[idx].Migrated = dstCount
		state.Tables[idx].Error = fmt.Sprintf("target already has %d rows", dstCount)
		state.mu.Unlock()
		log.Printf("[migrate] %s: target has %d rows, skipping", tableName, dstCount)
		return
	}

	// Migrate in batches using raw map scanning for generality
	batchSize := t.batchSize
	var migrated int64

	for offset := 0; int64(offset) < srcCount; offset += batchSize {
		var rows []map[string]interface{}
		if err := srcDB.Table(tableName).Order("id ASC").Offset(offset).Limit(batchSize).Find(&rows).Error; err != nil {
			state.mu.Lock()
			state.Tables[idx].Status = "error"
			state.Tables[idx].Error = fmt.Sprintf("read batch at offset %d: %v", offset, err)
			state.mu.Unlock()
			log.Printf("[migrate] %s: read error at offset %d: %v", tableName, offset, err)
			return
		}

		if len(rows) == 0 {
			break
		}

		if err := d.db.Table(tableName).Create(rows).Error; err != nil {
			state.mu.Lock()
			state.Tables[idx].Status = "error"
			state.Tables[idx].Error = fmt.Sprintf("write batch at offset %d: %v", offset, err)
			state.mu.Unlock()
			log.Printf("[migrate] %s: write error at offset %d: %v", tableName, offset, err)
			return
		}

		migrated += int64(len(rows))
		state.mu.Lock()
		state.Tables[idx].Migrated = migrated
		state.mu.Unlock()
	}

	// Reset PostgreSQL sequence to max(id)
	seqSQL := fmt.Sprintf(
		"SELECT setval(pg_get_serial_sequence('%s','id'), COALESCE((SELECT MAX(id) FROM %s), 1))",
		tableName, tableName,
	)
	if err := d.db.Exec(seqSQL).Error; err != nil {
		log.Printf("[migrate] %s: failed to reset sequence: %v", tableName, err)
		// Non-fatal — continue
	}

	state.mu.Lock()
	state.Tables[idx].Status = "done"
	state.mu.Unlock()
	log.Printf("[migrate] %s: migrated %d rows", tableName, migrated)
}
