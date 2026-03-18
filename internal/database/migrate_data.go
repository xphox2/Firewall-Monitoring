package database

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// sanitizeNullBytes strips 0x00 bytes from all string fields in a struct.
// PostgreSQL rejects null bytes in text columns; SQLite allows them.
func sanitizeNullBytes(v any) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		if f.Kind() == reflect.String && f.CanSet() {
			if s := f.String(); strings.ContainsRune(s, 0) {
				f.SetString(strings.ReplaceAll(s, "\x00", ""))
			}
		}
	}
}

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

// migrateFn is a function that migrates one table. Each is a closure over a
// concrete model type so GORM handles SQLite↔PG type mapping (bools, times).
type migrateFn func(d *Database, srcDB *gorm.DB, state *MigrationState, idx int)

// migrateTyped returns a migrateFn for model type T with the given batch size.
func migrateTyped[T any](tableName string, batchSize int) migrateFn {
	return func(d *Database, srcDB *gorm.DB, state *MigrationState, idx int) {
		// Count source rows
		var srcCount int64
		if err := srcDB.Table(tableName).Count(&srcCount).Error; err != nil {
			setTableError(state, idx, fmt.Sprintf("count source: %v", err))
			log.Printf("[migrate] %s: failed to count source: %v", tableName, err)
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

		// Idempotency: skip if target already has >= source rows (already migrated).
		// If target has fewer rows (e.g. probe inserted a handful during migration),
		// truncate and re-copy the full dataset.
		var dstCount int64
		if err := d.db.Table(tableName).Count(&dstCount).Error; err != nil {
			setTableError(state, idx, fmt.Sprintf("count target: %v", err))
			log.Printf("[migrate] %s: failed to count target: %v", tableName, err)
			return
		}
		if dstCount >= srcCount {
			state.mu.Lock()
			state.Tables[idx].Status = "skipped"
			state.Tables[idx].Migrated = dstCount
			state.Tables[idx].Error = fmt.Sprintf("target already has %d rows", dstCount)
			state.mu.Unlock()
			log.Printf("[migrate] %s: target has %d rows (>= source %d), skipping", tableName, dstCount, srcCount)
			return
		}
		if dstCount > 0 {
			log.Printf("[migrate] %s: target has %d rows but source has %d — truncating target", tableName, dstCount, srcCount)
			if err := d.db.Exec(fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", tableName)).Error; err != nil {
				setTableError(state, idx, fmt.Sprintf("truncate: %v", err))
				log.Printf("[migrate] %s: truncate failed: %v", tableName, err)
				return
			}
		}

		// Advance PG sequence past source MAX(id) BEFORE copying, so concurrent
		// inserts (from probes) get IDs above the migrated range and don't clash.
		var srcMaxID int64
		srcDB.Table(tableName).Select("COALESCE(MAX(id), 0)").Scan(&srcMaxID)
		if srcMaxID > 0 {
			seqSQL := fmt.Sprintf(
				"SELECT setval(pg_get_serial_sequence('%s','id'), %d)",
				tableName, srcMaxID,
			)
			if err := d.db.Exec(seqSQL).Error; err != nil {
				log.Printf("[migrate] %s: failed to pre-advance sequence: %v", tableName, err)
			}
		}

		// Migrate in typed batches
		var migrated int64
		for offset := 0; int64(offset) < srcCount; offset += batchSize {
			var rows []T
			if err := srcDB.Order("id ASC").Offset(offset).Limit(batchSize).Find(&rows).Error; err != nil {
				setTableError(state, idx, fmt.Sprintf("read at offset %d: %v", offset, err))
				log.Printf("[migrate] %s: read error at offset %d: %v", tableName, offset, err)
				return
			}
			if len(rows) == 0 {
				break
			}
			// Strip null bytes from strings — PG rejects 0x00 in text columns
			for i := range rows {
				sanitizeNullBytes(&rows[i])
			}
			if err := d.db.Create(&rows).Error; err != nil {
				setTableError(state, idx, fmt.Sprintf("write at offset %d: %v", offset, err))
				log.Printf("[migrate] %s: write error at offset %d: %v", tableName, offset, err)
				return
			}
			migrated += int64(len(rows))
			state.mu.Lock()
			state.Tables[idx].Migrated = migrated
			state.mu.Unlock()
		}

		// Reset PostgreSQL sequence
		seqSQL := fmt.Sprintf(
			"SELECT setval(pg_get_serial_sequence('%s','id'), COALESCE((SELECT MAX(id) FROM %s), 1))",
			tableName, tableName,
		)
		if err := d.db.Exec(seqSQL).Error; err != nil {
			log.Printf("[migrate] %s: failed to reset sequence: %v", tableName, err)
		}

		state.mu.Lock()
		state.Tables[idx].Status = "done"
		state.mu.Unlock()
		log.Printf("[migrate] %s: migrated %d rows", tableName, migrated)
	}
}

func setTableError(state *MigrationState, idx int, msg string) {
	state.mu.Lock()
	state.Tables[idx].Status = "error"
	state.Tables[idx].Error = msg
	state.mu.Unlock()
}

// MigrateAdminsFromSQLite copies just the admins table synchronously so that
// InitAdmin sees the imported admin and preserves the old password. This is
// fast (typically 1 row) and should be called before InitAdmin.
func (d *Database) MigrateAdminsFromSQLite(sourceDBPath string) {
	srcDB, err := gorm.Open(sqlite.Open(sourceDBPath+"?mode=ro"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Printf("[migrate] admins pre-import: failed to open source: %v", err)
		return
	}
	sqlConn, _ := srcDB.DB()
	defer sqlConn.Close()

	var dstCount int64
	d.db.Table("admins").Count(&dstCount)
	if dstCount > 0 {
		return // already has data
	}

	var rows []models.Admin
	if err := srcDB.Order("id ASC").Find(&rows).Error; err != nil {
		log.Printf("[migrate] admins pre-import: read error: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	if err := d.db.Create(&rows).Error; err != nil {
		log.Printf("[migrate] admins pre-import: write error: %v", err)
		return
	}
	// Reset sequence
	d.db.Exec("SELECT setval(pg_get_serial_sequence('admins','id'), COALESCE((SELECT MAX(id) FROM admins), 1))")
	log.Printf("[migrate] admins pre-import: imported %d admin(s)", len(rows))
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
	sqlConn, err := srcDB.DB()
	if err != nil {
		state.mu.Lock()
		state.Error = fmt.Sprintf("failed to get underlying sql.DB: %v", err)
		state.mu.Unlock()
		return
	}
	defer sqlConn.Close()

	// Table name + typed migration function, in FK-safe order
	type entry struct {
		name string
		fn   migrateFn
	}
	tables := []entry{
		// No FK dependencies
		{"admins", migrateTyped[models.Admin]("admins", 500)},
		{"system_settings", migrateTyped[models.SystemSetting]("system_settings", 500)},
		{"login_attempts", migrateTyped[models.LoginAttempt]("login_attempts", 500)},
		// Self-referential
		{"sites", migrateTyped[models.Site]("sites", 500)},
		// → Site
		{"probes", migrateTyped[models.Probe]("probes", 500)},
		// → Site, Probe
		{"devices", migrateTyped[models.Device]("devices", 500)},
		// → Device
		{"device_tunnels", migrateTyped[models.DeviceTunnel]("device_tunnels", 500)},
		{"device_connections", migrateTyped[models.DeviceConnection]("device_connections", 500)},
		// → Probe
		{"probe_approvals", migrateTyped[models.ProbeApproval]("probe_approvals", 500)},
		{"probe_heartbeats", migrateTyped[models.ProbeHeartbeat]("probe_heartbeats", 500)},
		// Device-dependent telemetry (high-volume get 1000)
		{"system_status", migrateTyped[models.SystemStatus]("system_status", 1000)},
		{"interface_stats", migrateTyped[models.InterfaceStats]("interface_stats", 1000)},
		{"vpn_status", migrateTyped[models.VPNStatus]("vpn_status", 1000)},
		{"ha_status", migrateTyped[models.HAStatus]("ha_status", 500)},
		{"hardware_sensors", migrateTyped[models.HardwareSensor]("hardware_sensors", 500)},
		{"processor_stats", migrateTyped[models.ProcessorStats]("processor_stats", 500)},
		{"trap_events", migrateTyped[models.TrapEvent]("trap_events", 500)},
		{"alerts", migrateTyped[models.Alert]("alerts", 500)},
		{"uptime_records", migrateTyped[models.UptimeRecord]("uptime_records", 500)},
		{"security_stats", migrateTyped[models.SecurityStats]("security_stats", 500)},
		{"sdwan_health", migrateTyped[models.SDWANHealth]("sdwan_health", 500)},
		{"license_info", migrateTyped[models.LicenseInfo]("license_info", 500)},
		{"interface_addresses", migrateTyped[models.InterfaceAddress]("interface_addresses", 500)},
		{"ping_results", migrateTyped[models.PingResult]("ping_results", 1000)},
		{"ping_stats", migrateTyped[models.PingStats]("ping_stats", 500)},
		{"syslog_messages", migrateTyped[models.SyslogMessage]("syslog_messages", 1000)},
		{"flow_samples", migrateTyped[models.FlowSample]("flow_samples", 1000)},
		// → Site
		{"site_databases", migrateTyped[models.SiteDatabase]("site_databases", 500)},
		// IRC tables
		{"irc_servers", migrateTyped[models.IRCServer]("irc_servers", 500)},
		{"irc_channels", migrateTyped[models.IRCChannel]("irc_channels", 500)},
		{"irc_commands", migrateTyped[models.IRCCommand]("irc_commands", 500)},
		{"irc_message_logs", migrateTyped[models.IRCMessageLog]("irc_message_logs", 500)},
	}

	// Initialize table statuses
	state.mu.Lock()
	state.Tables = make([]TableMigrationStatus, len(tables))
	for i, t := range tables {
		state.Tables[i] = TableMigrationStatus{
			TableName: t.name,
			Status:    "pending",
		}
	}
	state.mu.Unlock()

	for i, t := range tables {
		t.fn(d, srcDB, state, i)
	}

	// Check if any table had errors
	hasErrors := false
	state.mu.RLock()
	for _, ts := range state.Tables {
		if ts.Status == "error" {
			hasErrors = true
			break
		}
	}
	state.mu.RUnlock()

	// Rename source SQLite file so migration doesn't re-trigger on next restart
	if !hasErrors {
		renamed := sourceDBPath + ".migrated"
		if err := os.Rename(sourceDBPath, renamed); err != nil {
			log.Printf("[migrate] warning: could not rename source file: %v", err)
		} else {
			log.Printf("[migrate] renamed %s → %s", sourceDBPath, renamed)
		}
		// Also rename WAL/SHM files if they exist
		for _, suffix := range []string{"-wal", "-shm"} {
			old := sourceDBPath + suffix
			if _, err := os.Stat(old); err == nil {
				os.Rename(old, renamed+suffix)
			}
		}
	}

	log.Println("[migrate] data migration complete")
}
