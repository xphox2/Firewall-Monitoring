package database

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	db          *gorm.DB
	encKey      []byte
	dialect     Dialect
	syslogBatch *BatchInserter[models.SyslogMessage]
	trapBatch   *BatchInserter[models.TrapEvent]
	pingBatch   *BatchInserter[models.PingResult]
}

func (d *Database) Gorm() *gorm.DB {
	return d.db
}

func (d *Database) IsPostgres() bool {
	return d.dialect.IsPostgres()
}

// pgQuote quotes a value for use in a PostgreSQL key=value DSN.
// Wraps in single quotes and escapes embedded single quotes and backslashes.
func pgQuote(s string) string {
	if !strings.ContainsAny(s, " '\\") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

func NewDatabase(cfg *config.Config) (*Database, error) {
	var db *gorm.DB
	var dial Dialect
	var err error

	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port,
		pgQuote(cfg.Database.User), pgQuote(cfg.Database.Password),
		pgQuote(cfg.Database.Name), cfg.Database.SSLMode)
	db, err = gorm.Open(postgres.Open(dsn), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	sqlDB, dbErr := db.DB()
	if dbErr != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", dbErr)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(1 * time.Minute)
	dial = postgresDialect{}
	log.Printf("Database: connected to PostgreSQL at %s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Name)

	var encKey []byte
	if cfg.Server.EncryptionKey != "" {
		encKey = deriveKey(cfg.Server.EncryptionKey)
	} else if cfg.Server.JWTSecretKey != "" {
		log.Println("WARNING: ENCRYPTION_KEY not set — falling back to JWT secret for database encryption. To use a separate key, set ENCRYPTION_KEY to the SAME value as JWT_SECRET_KEY first, then rotate it.")
		encKey = deriveKey(cfg.Server.JWTSecretKey)
	}

	d := &Database{db: db, encKey: encKey, dialect: dial}

	// Initialize batch inserters
	d.syslogBatch = NewBatchInserter[models.SyslogMessage](500, 2*time.Second, func(items []models.SyslogMessage) error {
		return d.db.Create(&items).Error
	})
	d.trapBatch = NewBatchInserter[models.TrapEvent](100, 5*time.Second, func(items []models.TrapEvent) error {
		return d.db.Create(&items).Error
	})
	d.pingBatch = NewBatchInserter[models.PingResult](100, 5*time.Second, func(items []models.PingResult) error {
		return d.db.Create(&items).Error
	})

	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// Ensure PostgreSQL partitions exist for high-volume tables
	if err := d.EnsurePartitions(); err != nil {
		log.Printf("Partition setup warning: %v", err)
	}

	// Configure aggressive autovacuum for high-volume tables
	if err := d.ConfigureAutovacuum(); err != nil {
		log.Printf("Autovacuum config warning: %v", err)
	}

	// Ensure a default alert policy exists
	d.EnsureDefaultPolicy()

	// Backfill vendor for existing devices
	db.Exec("UPDATE devices SET vendor = 'fortigate' WHERE vendor = '' OR vendor IS NULL")

	// Encrypt any existing plaintext SNMP credentials
	d.migrateEncryptSecrets()

	return d, nil
}

func (d *Database) migrate() error {
	allModels := []interface{}{
		&models.SystemStatus{},
		&models.InterfaceStats{},
		&models.VPNStatus{},
		&models.HAStatus{},
		&models.HardwareSensor{},
		&models.ProcessorStats{},
		&models.TrapEvent{},
		&models.Alert{},
		&models.UptimeRecord{},
		&models.LoginAttempt{},
		&models.Device{},
		&models.DeviceTunnel{},
		&models.DeviceConnection{},
		&models.SystemSetting{},
		&models.Admin{},
		&models.Site{},
		&models.Probe{},
		&models.ProbeApproval{},
		&models.ProbeHeartbeat{},
		&models.PingResult{},
		&models.PingStats{},
		&models.SyslogMessage{},
		&models.SyslogSummary{},
		&models.FlowSample{},
		&models.FlowRollup{},
		&models.SiteDatabase{},
		&models.SecurityStats{},
		&models.SDWANHealth{},
		&models.LicenseInfo{},
		&models.InterfaceAddress{},
		&models.IRCServer{},
		&models.IRCChannel{},
		&models.IRCCommand{},
		&models.IRCMessageLog{},
		&models.AlertPolicy{},
		&models.AlertRule{},
		&models.DeviceAlertConfig{},
		&models.SiteAlertConfig{},
		&models.MaintenanceWindow{},
		&models.DeviceConfigRevision{},
		&models.ProcessStats{},
		&models.InterfaceErrors{},
	}

	// Migrate each model individually so one failure doesn't block others.
	// GORM may attempt table recreation which may fail with "already exists" on upgrades.
	for _, model := range allModels {
		if err := d.db.AutoMigrate(model); err != nil {
			log.Printf("AutoMigrate warning for %T: %v", model, err)
		}
	}

	// One-time fix: if IRC tables have wrong column names from prior migrations,
	// drop and recreate them. Detect by checking for the correct server_password column.
	m := d.db.Migrator()
	if m.HasTable(&models.IRCServer{}) && !m.HasColumn(&models.IRCServer{}, "ServerPassword") {
		log.Println("IRC migrate: detected old schema, recreating IRC tables")
		ircTables := []interface{}{&models.IRCMessageLog{}, &models.IRCCommand{}, &models.IRCChannel{}, &models.IRCServer{}}
		for _, tbl := range ircTables {
			if m.HasTable(tbl) {
				if err := m.DropTable(tbl); err != nil {
					log.Printf("IRC migrate: drop table: %v", err)
				}
			}
		}
		for _, tbl := range ircTables {
			if err := d.db.AutoMigrate(tbl); err != nil {
				log.Printf("IRC migrate: recreate table: %v", err)
			}
		}
	}

	return nil
}

// EnsurePartitions creates monthly range partitions for high-volume tables on PostgreSQL.
// Partitions are created for the current month + 6 months ahead.
// This is safe for existing servers - it only creates new partitions, never modifies existing data.
func (d *Database) EnsurePartitions() error {
	if !d.dialect.IsPostgres() {
		return nil // Partitioning is PostgreSQL-only
	}

	type partitionDef struct {
		tableName string
		column    string
	}
	tables := []partitionDef{
		{"syslog_messages", "timestamp"},
		{"syslog_summaries", "timestamp"},
		{"trap_events", "timestamp"},
		{"flow_samples", "timestamp"},
	}

	// Create partitions for current month + 6 months ahead
	now := time.Now()
	for i := 0; i <= 6; i++ {
		year, month, _ := now.Date()
		month = month + time.Month(i)
		yearOffset := 0
		for month > 12 {
			month -= 12
			yearOffset++
		}
		year += yearOffset
		partitionStart := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		partitionEnd := partitionStart.AddDate(0, 1, 0)

		startStr := partitionStart.Format("2006-01-02")
		endStr := partitionEnd.Format("2006-01-02")

		for _, def := range tables {
			partitionName := fmt.Sprintf("%s_%d%02d", def.tableName, year, month)
			// Check if partition already exists
			var count int
			d.db.Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = ?", partitionName).Scan(&count)
			if count > 0 {
				continue // Partition exists
			}

			// Create the partition
			sql := fmt.Sprintf(`
				CREATE TABLE %s PARTITION OF %s
				FOR VALUES FROM ('%s') TO ('%s')`,
				partitionName, def.tableName, startStr, endStr)
			if err := d.db.Exec(sql).Error; err != nil {
				log.Printf("Partition creation warning for %s: %v", partitionName, err)
				continue
			}

			// Create indexes on the partition for efficient queries
			indexes := []struct {
				name  string
				cols  string
				where string
			}{
				{fmt.Sprintf("idx_%s_device_ts", partitionName), fmt.Sprintf("(%s, %s)", "device_id", def.column), ""},
				{fmt.Sprintf("idx_%s_timestamp", partitionName), fmt.Sprintf("(%s)", def.column), ""},
			}

			// Add severity index for syslog/trap tables
			if def.tableName == "syslog_messages" {
				indexes = append(indexes,
					struct {
						name  string
						cols  string
						where string
					}{fmt.Sprintf("idx_%s_severity", partitionName), "(severity)", ""})
			}
			if def.tableName == "trap_events" {
				indexes = append(indexes,
					struct {
						name  string
						cols  string
						where string
					}{fmt.Sprintf("idx_%s_severity", partitionName), "(severity)", ""})
			}

			for _, idx := range indexes {
				createIdxSQL := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s %s", idx.name, partitionName, idx.cols)
				if idx.where != "" {
					createIdxSQL += " WHERE " + idx.where
				}
				if err := d.db.Exec(createIdxSQL).Error; err != nil {
					log.Printf("Index creation warning on %s: %v", partitionName, err)
				}
			}

			log.Printf("Created partition: %s", partitionName)
		}
	}

	return nil
}

// ConfigureAutovacuum sets aggressive autovacuum parameters for high-volume tables.
// This reduces table bloat and improves query performance on PostgreSQL.
func (d *Database) ConfigureAutovacuum() error {
	if !d.dialect.IsPostgres() {
		return nil // Autovacuum is PostgreSQL-only
	}

	// High-volume tables that benefit from aggressive autovacuum
	tables := []string{
		"syslog_messages",
		"syslog_summaries",
		"trap_events",
		"flow_samples",
		"ping_results",
		"alerts",
	}

	// Autovacuum settings for high-volume tables:
	// - vacuum_scale_factor = 0.01 (1% vs default 20%) - vacuum more frequently
	// - analyze_scale_factor = 0.05 (5% vs default 10%) - analyze more frequently
	// - vacuum_cost_delay = 10ms (vs default 20ms) - vacuum more aggressively
	// - vacuum_cost_limit = 2000 (vs default 200) - allow more work per vacuum
	for _, table := range tables {
		sql := fmt.Sprintf(`
			ALTER TABLE %s SET (%
				autovacuum_vacuum_scale_factor = 0.01,
				autovacuum_analyze_scale_factor = 0.05,
				autovacuum_vacuum_cost_delay = 10,
				autovacuum_vacuum_cost_limit = 2000
			)`, table)
		if err := d.db.Exec(sql).Error; err != nil {
			// Log but don't fail - table might not exist yet or be a partitioned table
			log.Printf("Autovacuum config warning for %s: %v", table, err)
			continue
		}
		log.Printf("Configured autovacuum for %s", table)
	}

	return nil
}

func (d *Database) SaveSystemStatus(status *models.SystemStatus) error {
	return d.db.Create(status).Error
}

func (d *Database) GetSystemStatus(limit int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&statuses).Error
	return statuses, err
}

func (d *Database) SaveInterfaceStats(stats []models.InterfaceStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
}

func (d *Database) GetInterfaceStats(limit int) ([]models.InterfaceStats, error) {
	var stats []models.InterfaceStats
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&stats).Error
	return stats, err
}

func (d *Database) SaveInterfaceAddresses(addrs []models.InterfaceAddress) error {
	if len(addrs) == 0 {
		return nil
	}
	return d.db.Create(&addrs).Error
}

// GetLatestInterfaceAddresses returns the latest interface address snapshot per device.
func (d *Database) GetLatestInterfaceAddresses() ([]models.InterfaceAddress, error) {
	var addrs []models.InterfaceAddress
	err := d.db.Raw(`
		SELECT a.* FROM interface_addresses a
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
		ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts
	`).Scan(&addrs).Error
	return addrs, err
}

// GetAllLatestInterfaces returns the latest interface stats snapshot across all devices.
func (d *Database) GetAllLatestInterfaces() ([]models.InterfaceStats, error) {
	var ifaces []models.InterfaceStats
	err := d.db.Raw(`
		SELECT i.* FROM interface_stats i
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
		ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts
	`).Scan(&ifaces).Error
	return ifaces, err
}

func (d *Database) GetLatestSystemStatus() (*models.SystemStatus, error) {
	var status models.SystemStatus
	err := d.db.Order("timestamp DESC").First(&status).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (d *Database) GetLatestInterfaceStats() ([]models.InterfaceStats, error) {
	// Get the most recent timestamp
	var latest models.InterfaceStats
	if err := d.db.Order("timestamp DESC").First(&latest).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	// Get all interfaces from that timestamp
	var stats []models.InterfaceStats
	err := d.db.Where("timestamp = ?", latest.Timestamp).Find(&stats).Error
	return stats, err
}

func (d *Database) SaveVPNStatuses(statuses []models.VPNStatus) error {
	if len(statuses) == 0 {
		return nil
	}
	return d.db.Create(&statuses).Error
}

func (d *Database) GetLatestVPNStatuses(deviceID uint) ([]models.VPNStatus, error) {
	var latest models.VPNStatus
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latest).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	var statuses []models.VPNStatus
	err := d.db.Where("device_id = ? AND timestamp = ?", deviceID, latest.Timestamp).Find(&statuses).Error
	if err != nil || len(statuses) == 0 {
		return statuses, err
	}

	// Cross-fill Phase 2 subnets from peer devices
	// Find connections involving this device
	var connections []models.DeviceConnection
	d.db.Where("source_device_id = ? OR dest_device_id = ?", deviceID, deviceID).Find(&connections)

	// Get all peer device IDs
	peerIDs := make(map[uint]bool)
	for _, conn := range connections {
		if conn.SourceDeviceID != deviceID {
			peerIDs[conn.SourceDeviceID] = true
		}
		if conn.DestDeviceID != deviceID {
			peerIDs[conn.DestDeviceID] = true
		}
	}

	// Pre-fetch all peer tunnels indexed by remote IP (more reliable than name matching)
	// A tunnel on device A with RemoteIP=X matched to device B means device B likely has
	// a tunnel with RemoteIP pointing back to A. Match by IP, not name.
	peerTunnelsByRemoteIP := make(map[string]models.VPNStatus) // remoteIP -> latest tunnel with subnets
	for peerID := range peerIDs {
		var peerVPNs []models.VPNStatus
		d.db.Where("device_id = ?", peerID).Order("timestamp DESC").Find(&peerVPNs)
		for _, pv := range peerVPNs {
			if pv.LocalSubnet != "" || pv.RemoteSubnet != "" {
				if pv.RemoteIP != "" {
					existing, exists := peerTunnelsByRemoteIP[pv.RemoteIP]
					if !exists || (pv.LocalSubnet != "" && existing.LocalSubnet == "") {
						peerTunnelsByRemoteIP[pv.RemoteIP] = pv
					}
				}
			}
		}
	}

	// Collect this device's known IPs for matching
	deviceIPSet := make(map[uint]map[string]bool)
	for _, s := range statuses {
		if _, ok := deviceIPSet[s.DeviceID]; !ok {
			deviceIPSet[s.DeviceID] = make(map[string]bool)
			var dev models.Device
			if err := d.db.Select("ip_address").First(&dev, s.DeviceID).Error; err == nil {
				deviceIPSet[s.DeviceID][dev.IPAddress] = true
			}
		}
	}

	// Cross-fill: for each tunnel missing subnets, find a peer tunnel whose RemoteIP matches our device
	for i := range statuses {
		if statuses[i].LocalSubnet == "" || statuses[i].RemoteSubnet == "" {
			// Try matching by our device's IPs against peer tunnels' RemoteIP
			myIPs := deviceIPSet[statuses[i].DeviceID]
			var peerTunnel *models.VPNStatus
			for ip := range myIPs {
				if pt, ok := peerTunnelsByRemoteIP[ip]; ok {
					peerTunnel = &pt
					break
				}
			}
			// Also try matching by this tunnel's RemoteIP
			if peerTunnel == nil && statuses[i].RemoteIP != "" {
				if pt, ok := peerTunnelsByRemoteIP[statuses[i].RemoteIP]; ok {
					peerTunnel = &pt
				}
			}
			if peerTunnel != nil {
				if statuses[i].LocalSubnet == "" && peerTunnel.LocalSubnet != "" {
					statuses[i].LocalSubnet = peerTunnel.LocalSubnet
				}
				if statuses[i].RemoteSubnet == "" && peerTunnel.RemoteSubnet != "" {
					statuses[i].RemoteSubnet = peerTunnel.RemoteSubnet
				}
			}
		}
	}

	return statuses, err
}

func (d *Database) SaveAlert(alert *models.Alert) error {
	return d.db.Create(alert).Error
}

func (d *Database) GetAlerts(limit int, acknowledged *bool) ([]models.Alert, error) {
	var alerts []models.Alert
	query := d.db.Order("timestamp DESC").Limit(limit)
	if acknowledged != nil {
		query = query.Where("acknowledged = ?", *acknowledged)
	}
	err := query.Find(&alerts).Error
	return alerts, err
}

func (d *Database) AcknowledgeAlert(id uint) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Update("acknowledged", true).Error
}

func (d *Database) SaveTrapEvent(trap *models.TrapEvent) error {
	if d.trapBatch != nil {
		d.trapBatch.Add(*trap)
		return nil
	}
	return d.db.Create(trap).Error
}

func (d *Database) SaveTrapEvents(traps []models.TrapEvent) error {
	if len(traps) == 0 {
		return nil
	}
	return d.db.Create(&traps).Error
}

func (d *Database) GetTrapEvents(limit int) ([]models.TrapEvent, error) {
	var traps []models.TrapEvent
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&traps).Error
	return traps, err
}

func (d *Database) SaveUptimeRecord(record *models.UptimeRecord) error {
	return d.db.Create(record).Error
}

func (d *Database) GetUptimeRecords(limit int) ([]models.UptimeRecord, error) {
	var records []models.UptimeRecord
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&records).Error
	return records, err
}

func (d *Database) SaveLoginAttempt(attempt *models.LoginAttempt) error {
	return d.db.Create(attempt).Error
}

func (d *Database) GetLoginAttempts(since time.Time, limit int) ([]models.LoginAttempt, error) {
	var attempts []models.LoginAttempt
	err := d.db.Where("timestamp > ?", since).Order("timestamp DESC").Limit(limit).Find(&attempts).Error
	return attempts, err
}

func (d *Database) SaveConfigRevision(rev *models.DeviceConfigRevision) error {
	tx := d.db.Begin()
	if err := tx.Create(rev).Error; err != nil {
		tx.Rollback()
		return err
	}
	var count int64
	if err := tx.Model(&models.DeviceConfigRevision{}).Where("device_id = ?", rev.DeviceID).Count(&count).Error; err != nil {
		tx.Rollback()
		return err
	}
	if count > 5 {
		deleteCount := count - 5
		var toDelete []uint
		if err := tx.Model(&models.DeviceConfigRevision{}).
			Where("device_id = ?", rev.DeviceID).
			Order("timestamp ASC").
			Limit(int(deleteCount)).
			Pluck("id", &toDelete).Error; err != nil {
			tx.Rollback()
			return err
		}
		if len(toDelete) > 0 {
			if err := tx.Where("device_id = ? AND id IN ?", rev.DeviceID, toDelete).Delete(&models.DeviceConfigRevision{}).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit().Error
}

func (d *Database) SaveProcessStats(stats *models.ProcessStats) error {
	return d.db.Create(stats).Error
}

func (d *Database) SaveInterfaceErrors(errs []models.InterfaceErrors) error {
	if len(errs) == 0 {
		return nil
	}
	return d.db.Create(&errs).Error
}

func (d *Database) CleanupOldData(ret config.RetentionConfig) error {
	type cleanupEntry struct {
		model interface{}
		name  string
		days  int
	}

	statusDays := ret.Days(ret.StatusDays)
	flowDays := ret.Days(ret.FlowDays)
	trapDays := ret.Days(ret.TrapDays)
	pingDays := ret.Days(ret.PingDays)
	alertDays := ret.Days(ret.AlertDays)
	defaultDays := ret.Days(0)

	entries := []cleanupEntry{
		{&models.SystemStatus{}, "system_status", statusDays},
		{&models.InterfaceStats{}, "interface_stats", statusDays},
		{&models.ProcessorStats{}, "processor_stats", statusDays},
		{&models.HardwareSensor{}, "hardware_sensors", statusDays},
		{&models.TrapEvent{}, "trap_event", trapDays},
		{&models.LoginAttempt{}, "login_attempt", defaultDays},
		{&models.FlowSample{}, "flow_sample", flowDays},
		{&models.InterfaceAddress{}, "interface_addresses", statusDays},
		{&models.PingResult{}, "ping_result", pingDays},
	}

	for _, e := range entries {
		cutoff := time.Now().AddDate(0, 0, -e.days)
		if err := d.db.Where("timestamp < ?", cutoff).Delete(e.model).Error; err != nil {
			return fmt.Errorf("failed to cleanup %s: %w", e.name, err)
		}
	}

	// Syslog: handle critical (0-5) and informational (6-7) differently
	// Critical syslog (severity 0-5): delete after SyslogCriticalDays (0 = never delete)
	if ret.SyslogCriticalDays > 0 {
		criticalCutoff := time.Now().AddDate(0, 0, -ret.SyslogCriticalDays)
		if err := d.db.Where("timestamp < ? AND severity < 6", criticalCutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
			return fmt.Errorf("failed to cleanup syslog_message: %w", err)
		}
	}

	// Informational syslog (severity 6-7): delete after SyslogInfoDays
	// This catches any informational syslog that wasn't aggregated (aggregation runs every 5 min)
	infoDays := ret.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // default fallback
	}
	infoCutoff := time.Now().AddDate(0, 0, -infoDays)
	if err := d.db.Where("timestamp < ? AND severity >= 6", infoCutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup informational syslog_message: %w", err)
	}

	// Syslog summaries: delete after SyslogInfoDays (they are derived from informational syslog)
	summaryDays := ret.SyslogInfoDays
	if summaryDays <= 0 {
		summaryDays = 7 // default fallback
	}
	summaryCutoff := time.Now().AddDate(0, 0, -summaryDays)
	if err := d.db.Where("timestamp < ?", summaryCutoff).Delete(&models.SyslogSummary{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup syslog_summary: %w", err)
	}

	// Legacy SyslogDays applies only when neither new config is set (backwards compat)
	if ret.SyslogDays > 0 && ret.SyslogCriticalDays == 0 && ret.SyslogInfoDays == 0 {
		cutoff := time.Now().AddDate(0, 0, -ret.SyslogDays)
		if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
			return fmt.Errorf("failed to cleanup syslog_message: %w", err)
		}
	}

	// Alerts: only delete acknowledged alerts
	alertCutoff := time.Now().AddDate(0, 0, -alertDays)
	if err := d.db.Where("acknowledged = true AND timestamp < ?", alertCutoff).Delete(&models.Alert{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup alert: %w", err)
	}

	return nil
}

func (d *Database) Close() error {
	// Flush and stop all batch inserters before closing the DB
	if d.syslogBatch != nil {
		d.syslogBatch.Stop()
	}
	if d.trapBatch != nil {
		d.trapBatch.Stop()
	}
	if d.pingBatch != nil {
		d.pingBatch.Stop()
	}

	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (d *Database) GetAllDevices() ([]models.Device, error) {
	var devices []models.Device
	err := d.db.Preload("Site").Preload("Probe").Find(&devices).Error
	for i := range devices {
		d.DecryptDeviceSecrets(&devices[i])
	}
	return devices, err
}

func (d *Database) GetDevice(id uint) (*models.Device, error) {
	var device models.Device
	err := d.db.Preload("Site").Preload("Probe").First(&device, id).Error
	if err != nil {
		return nil, err
	}
	d.DecryptDeviceSecrets(&device)
	return &device, nil
}

// ResolveDeviceByIP finds a device ID by management IP or interface address.
func (d *Database) ResolveDeviceByIP(ip string) uint {
	// Check management IP first
	var device models.Device
	if err := d.db.Where("ip_address = ?", ip).Select("id").First(&device).Error; err == nil {
		return device.ID
	}
	// Check interface addresses
	var addr models.InterfaceAddress
	if err := d.db.Where("ip_address = ?", ip).Select("device_id").First(&addr).Error; err == nil {
		return addr.DeviceID
	}
	return 0
}

func (d *Database) CreateDevice(device *models.Device) error {
	d.EncryptDeviceSecrets(device)
	err := d.db.Create(device).Error
	// Decrypt back so the caller sees plaintext
	d.DecryptDeviceSecrets(device)
	return err
}

func (d *Database) UpdateDevice(device *models.Device) error {
	return d.db.Save(device).Error
}

// UpdateDeviceStatus performs a targeted update of only status and last_polled fields.
func (d *Database) UpdateDeviceStatus(id uint, status string, lastPolled time.Time) error {
	return d.db.Model(&models.Device{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":      status,
		"last_polled": lastPolled,
	}).Error
}

// UpdateDeviceSSLVPN updates SSL-VPN user/session counts for a device.
func (d *Database) UpdateDeviceSSLVPN(id uint, users, tunnels int) error {
	return d.db.Model(&models.Device{}).Where("id = ?", id).Updates(map[string]interface{}{
		"sslvpn_users":   users,
		"sslvpn_tunnels": tunnels,
	}).Error
}

// MarkStaleProbeDevicesOffline marks probe-assigned devices as "offline" if their
// last_polled timestamp is older than the given threshold. Returns the count of affected rows.
func (d *Database) MarkStaleProbeDevicesOffline(staleThreshold time.Time) (int64, error) {
	result := d.db.Model(&models.Device{}).
		Where("probe_id IS NOT NULL AND enabled = ? AND status = ? AND last_polled < ?", true, "online", staleThreshold).
		Update("status", "offline")
	return result.RowsAffected, result.Error
}

func (d *Database) DeleteDevice(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// Delete all related monitoring data
		for _, model := range []interface{}{
			&models.SystemStatus{},
			&models.InterfaceStats{},
			&models.VPNStatus{},
			&models.HAStatus{},
			&models.HardwareSensor{},
			&models.ProcessorStats{},
			&models.Alert{},
			&models.UptimeRecord{},
			&models.TrapEvent{},
			&models.DeviceTunnel{},
			&models.InterfaceAddress{},
		} {
			if err := tx.Where("device_id = ?", id).Delete(model).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("source_device_id = ? OR dest_device_id = ?", id, id).Delete(&models.DeviceConnection{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Device{}, id).Error
	})
}

func (d *Database) GetAllConnections() ([]models.DeviceConnection, error) {
	var conns []models.DeviceConnection
	err := d.db.Preload("SourceDevice").Preload("DestDevice").Find(&conns).Error
	return conns, err
}

// GetConnectionStatuses returns only id and status for all connections (lightweight).
func (d *Database) GetConnectionStatuses() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := d.db.Model(&models.DeviceConnection{}).Select("id, status").Find(&results).Error
	return results, err
}

// GetDeviceStatuses returns only id and status for all devices (lightweight).
func (d *Database) GetDeviceStatuses() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := d.db.Model(&models.Device{}).Select("id, status").Find(&results).Error
	return results, err
}

// ConnectionEvent represents a unified event from alerts, traps, or syslog.
type ConnectionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "alert", "trap", "syslog"
	DeviceID  uint      `json:"device_id"`
	Severity  string    `json:"severity"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
}

// GetConnectionEvents returns correlated events (alerts, traps, syslog) for two devices.
func (d *Database) GetConnectionEvents(srcDeviceID, dstDeviceID uint, hours int) ([]ConnectionEvent, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	deviceIDs := []uint{srcDeviceID, dstDeviceID}
	var events []ConnectionEvent

	// Alerts
	var alerts []models.Alert
	d.db.Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(50).Find(&alerts)
	for _, a := range alerts {
		events = append(events, ConnectionEvent{
			Timestamp: a.Timestamp,
			Source:    "alert",
			DeviceID:  a.DeviceID,
			Severity:  a.Severity,
			Type:      a.AlertType,
			Message:   a.Message,
		})
	}

	// Traps
	var traps []models.TrapEvent
	d.db.Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(50).Find(&traps)
	for _, t := range traps {
		events = append(events, ConnectionEvent{
			Timestamp: t.Timestamp,
			Source:    "trap",
			DeviceID:  t.DeviceID,
			Severity:  t.Severity,
			Type:      t.TrapType,
			Message:   t.Message,
		})
	}

	// Syslog (severity <= 4 = warning and above)
	var syslogs []models.SyslogMessage
	d.db.Where("device_id IN ? AND severity <= 4 AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(30).Find(&syslogs)
	for _, s := range syslogs {
		sev := "info"
		if s.Severity <= 2 {
			sev = "critical"
		} else if s.Severity <= 4 {
			sev = "warning"
		}
		events = append(events, ConnectionEvent{
			Timestamp: s.Timestamp,
			Source:    "syslog",
			DeviceID:  s.DeviceID,
			Severity:  sev,
			Type:      "syslog",
			Message:   s.Message,
		})
	}

	// Sort by timestamp descending
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if len(events) > 100 {
		events = events[:100]
	}

	return events, nil
}

// GetAllLatestVPNStatuses returns the latest VPN tunnel snapshot for every device.
func (d *Database) GetAllLatestVPNStatuses() ([]models.VPNStatus, error) {
	var statuses []models.VPNStatus
	// Subquery: max timestamp per device
	sub := d.db.Model(&models.VPNStatus{}).Select("device_id, MAX(timestamp) as max_ts").Group("device_id")
	err := d.db.Where("(device_id, timestamp) IN (?)", sub).Find(&statuses).Error
	return statuses, err
}

// FindConnectionByDevicePairAndType finds a connection between two devices of a specific type.
func (d *Database) FindConnectionByDevicePairAndType(deviceA, deviceB uint, connType string) (*models.DeviceConnection, error) {
	var conn models.DeviceConnection
	err := d.db.Where(
		"((source_device_id = ? AND dest_device_id = ?) OR (source_device_id = ? AND dest_device_id = ?)) AND connection_type = ?",
		deviceA, deviceB, deviceB, deviceA, connType,
	).First(&conn).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &conn, err
}

// UpsertAutoConnection creates or updates an auto-detected connection.
// Uses device pair + connection_type as the unique key, allowing multiple
// connection types between the same pair (e.g. ipsec + l2vlan).
// Manual connections (AutoDetected=false) are never overwritten.
func (d *Database) UpsertAutoConnection(sourceID, destID uint, status, tunnelNames, name, connType, matchMethod string) error {
	if connType == "" {
		connType = "ipsec"
	}
	if matchMethod == "" {
		matchMethod = "ip_match"
	}

	existing, err := d.FindConnectionByDevicePairAndType(sourceID, destID, connType)
	if err != nil {
		return err
	}

	if existing != nil {
		if !existing.AutoDetected {
			return nil // don't touch manual connections
		}
		// Update existing auto-detected connection
		return d.db.Model(existing).Updates(map[string]interface{}{
			"status":          status,
			"tunnel_names":    tunnelNames,
			"connection_type": connType,
			"match_method":    matchMethod,
			"last_check":      time.Now(),
		}).Error
	}

	// Create new auto-detected connection with normalized direction
	conn := &models.DeviceConnection{
		Name:           name,
		SourceDeviceID: sourceID,
		DestDeviceID:   destID,
		ConnectionType: connType,
		Status:         status,
		AutoDetected:   true,
		TunnelNames:    tunnelNames,
		MatchMethod:    matchMethod,
		LastCheck:      time.Now(),
	}
	return d.db.Create(conn).Error
}

func (d *Database) CreateConnection(conn *models.DeviceConnection) error {
	return d.db.Create(conn).Error
}

func (d *Database) UpdateConnection(conn *models.DeviceConnection) error {
	return d.db.Save(conn).Error
}

func (d *Database) DeleteConnection(id uint) error {
	return d.db.Delete(&models.DeviceConnection{}, id).Error
}

// CleanupStaleAutoConnections removes auto-detected connections with tunnel names
// that should never have been matched (e.g., ssl.root present on every FortiGate).
func (d *Database) CleanupStaleAutoConnections(skipNames []string) int64 {
	if len(skipNames) == 0 {
		return 0
	}
	result := d.db.Where("auto_detected = ? AND tunnel_names IN ?", true, skipNames).
		Delete(&models.DeviceConnection{})
	return result.RowsAffected
}

// CleanupStaleAutoConnectionsBefore deletes auto-detected connections whose
// last_check is older than the given timestamp. Called after each detection
// cycle to remove connections whose interfaces no longer exist.
func (d *Database) CleanupStaleAutoConnectionsBefore(before time.Time) int64 {
	result := d.db.Where("auto_detected = ? AND last_check < ?", true, before).
		Delete(&models.DeviceConnection{})
	return result.RowsAffected
}

func (d *Database) GetAllSettings() ([]models.SystemSetting, error) {
	var settings []models.SystemSetting
	err := d.db.Find(&settings).Error
	return settings, err
}

func (d *Database) UpsertSetting(setting *models.SystemSetting) error {
	existing := models.SystemSetting{Key: setting.Key}
	if err := d.db.FirstOrCreate(&existing, models.SystemSetting{Key: setting.Key}).Error; err != nil {
		return err
	}
	existing.Value = setting.Value
	existing.Label = setting.Label
	existing.Category = setting.Category
	return d.db.Save(&existing).Error
}

func (d *Database) GetAdmin() (*models.Admin, error) {
	var admin models.Admin
	err := d.db.First(&admin).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &admin, err
}

func (d *Database) CreateAdmin(admin *models.Admin) error {
	return d.db.Create(admin).Error
}

func (d *Database) UpdateAdmin(admin *models.Admin) error {
	return d.db.Save(admin).Error
}

func (d *Database) InitAdmin(username, password string) error {
	admin, err := d.GetAdmin()
	if err != nil {
		return err
	}
	if admin == nil {
		return d.CreateAdmin(&models.Admin{Username: username, Password: password})
	}
	log.Printf("Admin user already exists, skipping initialization")
	return nil
}

func (d *Database) GetAdminByUsername(username string) (*auth.AdminAuth, error) {
	var admin models.Admin
	err := d.db.Where("username = ?", username).First(&admin).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &auth.AdminAuth{
		ID:           admin.ID,
		Username:     admin.Username,
		Password:     admin.Password,
		TokenVersion: admin.TokenVersion,
	}, nil
}

func (d *Database) UpdateAdminPassword(id uint, password string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).Update("password", password).Error
}

func (d *Database) GetAdminTokenVersion(id uint) (uint, error) {
	var admin models.Admin
	err := d.db.Select("token_version").First(&admin, id).Error
	if err != nil {
		return 0, err
	}
	return admin.TokenVersion, nil
}

func (d *Database) IncrementAdminTokenVersion(id uint) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
}

func (d *Database) GetAllSites() ([]models.Site, error) {
	var sites []models.Site
	err := d.db.Preload("ParentSite").Find(&sites).Error
	return sites, err
}

func (d *Database) GetSite(id uint) (*models.Site, error) {
	var site models.Site
	err := d.db.Preload("ParentSite").Preload("Probes").First(&site, id).Error
	if err != nil {
		return nil, err
	}
	return &site, nil
}

func (d *Database) GetSiteByName(name string) (*models.Site, error) {
	var site models.Site
	err := d.db.Where("name = ?", name).First(&site).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &site, err
}

func (d *Database) CreateSite(site *models.Site) error {
	return d.db.Create(site).Error
}

func (d *Database) UpdateSite(site *models.Site) error {
	return d.db.Save(site).Error
}

func (d *Database) DeleteSite(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("site_id = ?", id).Delete(&models.Probe{}).Error; err != nil {
			return err
		}
		if err := tx.Where("site_id = ?", id).Delete(&models.Device{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Site{}, id).Error
	})
}

func (d *Database) GetAllProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Preload("Site").Find(&probes).Error
	return probes, err
}

func (d *Database) GetProbe(id uint) (*models.Probe, error) {
	var probe models.Probe
	err := d.db.Preload("Site").First(&probe, id).Error
	if err != nil {
		return nil, err
	}
	return &probe, nil
}

func (d *Database) GetProbeByName(name string) (*models.Probe, error) {
	var probe models.Probe
	err := d.db.Where("name = ?", name).First(&probe).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &probe, err
}

func (d *Database) CreateProbe(probe *models.Probe) error {
	return d.db.Create(probe).Error
}

func (d *Database) UpdateProbe(probe *models.Probe) error {
	return d.db.Save(probe).Error
}

func (d *Database) DeleteProbe(id uint) error {
	return d.db.Delete(&models.Probe{}, id).Error
}

func (d *Database) GetProbesBySite(siteID uint) ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("site_id = ?", siteID).Find(&probes).Error
	return probes, err
}

func (d *Database) GetProbeByRegistrationKey(key string) (*models.Probe, error) {
	var probe models.Probe
	err := d.db.Where("registration_key = ?", key).First(&probe).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &probe, err
}

func (d *Database) ApproveProbe(probeID uint, approvedBy uint) error {
	now := time.Now()
	if err := d.db.Model(&models.Probe{}).Where("id = ?", probeID).Updates(map[string]interface{}{
		"status":          "approved",
		"approval_status": "approved",
		"approved_at":     now,
		"approved_by":     approvedBy,
	}).Error; err != nil {
		return err
	}
	approval := &models.ProbeApproval{
		ProbeID:     probeID,
		RequestedAt: now,
		ApprovedAt:  &now,
		ApprovedBy:  &approvedBy,
		Status:      "approved",
	}
	return d.db.Create(approval).Error
}

func (d *Database) RejectProbe(probeID uint, reason string) error {
	now := time.Now()
	if err := d.db.Model(&models.Probe{}).Where("id = ?", probeID).Updates(map[string]interface{}{
		"status":          "rejected",
		"approval_status": "rejected",
		"rejected_at":     now,
		"rejected_reason": reason,
	}).Error; err != nil {
		return err
	}
	approval := &models.ProbeApproval{
		ProbeID:        probeID,
		RequestedAt:    now,
		RejectedAt:     &now,
		RejectedReason: reason,
		Status:         "rejected",
	}
	return d.db.Create(approval).Error
}

func (d *Database) GetPendingProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("approval_status = ?", "pending").Find(&probes).Error
	return probes, err
}

func (d *Database) GetApprovedProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("approval_status = ?", "approved").Find(&probes).Error
	return probes, err
}

func (d *Database) UpdateProbeHeartbeat(heartbeat *models.ProbeHeartbeat) error {
	var existing models.ProbeHeartbeat
	err := d.db.Where("probe_id = ?", heartbeat.ProbeID).First(&existing).Error
	if err == gorm.ErrRecordNotFound {
		return d.db.Create(heartbeat).Error
	}
	existing.Status = heartbeat.Status
	existing.IPAddress = heartbeat.IPAddress
	existing.Version = heartbeat.Version
	existing.Uptime = heartbeat.Uptime
	existing.Timestamp = heartbeat.Timestamp
	return d.db.Save(&existing).Error
}

func (d *Database) GetProbeHeartbeats(probeID uint) ([]models.ProbeHeartbeat, error) {
	var heartbeats []models.ProbeHeartbeat
	err := d.db.Where("probe_id = ?", probeID).Order("timestamp DESC").Find(&heartbeats).Error
	return heartbeats, err
}

func (d *Database) SavePingResult(result *models.PingResult) error {
	if d.pingBatch != nil {
		d.pingBatch.Add(*result)
		return nil
	}
	return d.db.Create(result).Error
}

func (d *Database) SavePingResults(results []models.PingResult) error {
	if len(results) == 0 {
		return nil
	}
	return d.db.Create(&results).Error
}

func (d *Database) GetPingResults(deviceID uint, limit int) ([]models.PingResult, error) {
	var results []models.PingResult
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(limit).Find(&results).Error
	return results, err
}

func (d *Database) SavePingStats(stats *models.PingStats) error {
	if stats.ID == 0 {
		return d.db.Create(stats).Error
	}
	return d.db.Save(stats).Error
}

func (d *Database) GetPingStatsByTarget(deviceID uint, probeID uint, targetIP string) (*models.PingStats, error) {
	var stats models.PingStats
	err := d.db.Where("device_id = ? AND probe_id = ? AND target_ip = ?", deviceID, probeID, targetIP).First(&stats).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &stats, err
}

func (d *Database) SaveProcessorStats(stats []models.ProcessorStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
}

func (d *Database) GetLatestProcessorStats(deviceID uint) ([]models.ProcessorStats, error) {
	var latest models.ProcessorStats
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latest).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	var stats []models.ProcessorStats
	err := d.db.Where("device_id = ? AND timestamp = ?", deviceID, latest.Timestamp).
		Order(d.dialect.QuoteIdent("index") + " ASC").Find(&stats).Error
	return stats, err
}

func (d *Database) SaveHardwareSensors(sensors []models.HardwareSensor) error {
	if len(sensors) == 0 {
		return nil
	}
	return d.db.Create(&sensors).Error
}

func (d *Database) SaveHAStatuses(statuses []models.HAStatus) error {
	if len(statuses) == 0 {
		return nil
	}
	return d.db.Create(&statuses).Error
}

func (d *Database) SaveSecurityStats(stats []models.SecurityStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
}

func (d *Database) SaveSDWANHealth(health []models.SDWANHealth) error {
	if len(health) == 0 {
		return nil
	}
	return d.db.Create(&health).Error
}

// GetLatestSecurityStats returns the most recent security stats for a device.
func (d *Database) GetLatestSecurityStats(deviceID uint) (*models.SecurityStats, error) {
	var stats models.SecurityStats
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&stats).Error
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

// GetSecurityStatsHistory returns security stats time series for a device.
func (d *Database) GetSecurityStatsHistory(deviceID uint, hours int) ([]models.SecurityStats, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	var stats []models.SecurityStats
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp ASC").Find(&stats).Error
	return stats, err
}

// GetLatestSDWANHealth returns the most recent SD-WAN health records for a device.
func (d *Database) GetLatestSDWANHealth(deviceID uint) ([]models.SDWANHealth, error) {
	// Get distinct health monitor names, then fetch latest for each
	var names []string
	d.db.Model(&models.SDWANHealth{}).Where("device_id = ?", deviceID).
		Distinct("name").Pluck("name", &names)

	var results []models.SDWANHealth
	for _, name := range names {
		var h models.SDWANHealth
		if err := d.db.Where("device_id = ? AND name = ?", deviceID, name).
			Order("timestamp DESC").First(&h).Error; err == nil {
			results = append(results, h)
		}
	}
	return results, nil
}

// GetLatestHAStatus returns the most recent HA status records for a device.
func (d *Database) GetLatestHAStatus(deviceID uint) ([]models.HAStatus, error) {
	// Get distinct member serials, then fetch latest for each
	var serials []string
	d.db.Model(&models.HAStatus{}).Where("device_id = ?", deviceID).
		Distinct("member_serial").Pluck("member_serial", &serials)

	var results []models.HAStatus
	for _, serial := range serials {
		var h models.HAStatus
		if err := d.db.Where("device_id = ? AND member_serial = ?", deviceID, serial).
			Order("timestamp DESC").First(&h).Error; err == nil {
			results = append(results, h)
		}
	}
	return results, nil
}

func (d *Database) SaveLicenseInfo(licenses []models.LicenseInfo) error {
	if len(licenses) == 0 {
		return nil
	}
	return d.db.Create(&licenses).Error
}

func (d *Database) SaveSyslogMessage(msg *models.SyslogMessage) error {
	if d.syslogBatch != nil {
		d.syslogBatch.Add(*msg)
		return nil
	}
	return d.db.Create(msg).Error
}

func (d *Database) SaveSyslogMessages(msgs []models.SyslogMessage) error {
	if len(msgs) == 0 {
		return nil
	}
	return d.db.Create(&msgs).Error
}

func (d *Database) GetSyslogMessages(limit int) ([]models.SyslogMessage, error) {
	var messages []models.SyslogMessage
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&messages).Error
	return messages, err
}

func (d *Database) SaveFlowSamples(samples []models.FlowSample) error {
	if len(samples) == 0 {
		return nil
	}
	return d.db.Create(&samples).Error
}

func (d *Database) GetFlowSamples(limit int) ([]models.FlowSample, error) {
	var samples []models.FlowSample
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&samples).Error
	return samples, err
}

// InterfaceChartBucket holds a single time-bucket for interface chart data.
type InterfaceChartBucket struct {
	Bucket     string  `json:"bucket"`
	InBytes    float64 `json:"in_bytes"`
	OutBytes   float64 `json:"out_bytes"`
	InPackets  float64 `json:"in_packets"`
	OutPackets float64 `json:"out_packets"`
	InErrors   float64 `json:"in_errors"`
	OutErrors  float64 `json:"out_errors"`
}

// GetInterfaceChartData returns downsampled interface stats for charting.
func (d *Database) GetInterfaceChartData(deviceID uint, ifIndex int, rangeStr string) ([]InterfaceChartBucket, error) {
	var hours int
	var bucketExpr string
	switch rangeStr {
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "90d":
		hours = 2160
		bucketExpr = d.dialect.TimeBucket("day", "timestamp")
	default: // 24h
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	quotedIndex := d.dialect.QuoteIdent("index")

	var rows []InterfaceChartBucket
	err := d.db.Model(&models.InterfaceStats{}).
		Where(fmt.Sprintf("device_id = ? AND %s = ? AND timestamp > ?", quotedIndex), deviceID, ifIndex, cutoff).
		Select(fmt.Sprintf("%s as bucket, AVG(in_bytes) as in_bytes, AVG(out_bytes) as out_bytes, AVG(in_packets) as in_packets, AVG(out_packets) as out_packets, AVG(in_errors) as in_errors, AVG(out_errors) as out_errors", bucketExpr)).
		Group("bucket").Order("bucket ASC").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// GetSystemStatusHistory returns time-series system status data for a device
func (d *Database) GetSystemStatusHistory(deviceID uint, hours int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp ASC").Limit(2000).Find(&statuses).Error
	return statuses, err
}

// GetPingResultHistory returns time-series ping results for a device
func (d *Database) GetPingResultHistory(deviceID uint, hours int) ([]models.PingResult, error) {
	var results []models.PingResult
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp ASC").Limit(2000).Find(&results).Error
	return results, err
}

// TimeBucket is a generic time-series count bucket
type TimeBucket struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

// KeyCount is a generic key-value count pair
type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// protoNames maps IP protocol numbers to human-readable names.
var protoNames = map[uint8]string{
	0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 8: "EGP",
	17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE",
	50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
	88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 137: "MPLS-in-IP",
}

// protoName returns the human name for a protocol number, or "Proto N" as fallback.
func protoName(p uint8) string {
	if name, ok := protoNames[p]; ok {
		return name
	}
	return fmt.Sprintf("Proto %d", p)
}

// FlowStatsResult holds aggregated flow statistics
var wellKnownPorts = map[uint16]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 500: "IKE", 4500: "NAT-T",
	1194: "OpenVPN", 51820: "WireGuard",
}

type FlowStatsResult struct {
	TotalFlows       int64              `json:"total_flows"`
	TotalBytes       uint64             `json:"total_bytes"`
	TotalPackets     uint64             `json:"total_packets"`
	BitsPerSecond    float64            `json:"bits_per_second"`
	UniqueSources    int64              `json:"unique_sources"`
	UniqueDests      int64              `json:"unique_dests"`
	ProtocolCount    int64              `json:"protocol_count"`
	BucketSeconds    int                `json:"bucket_seconds"`
	AvgSamplingRate  float64            `json:"avg_sampling_rate"`
	EstimatedBytes   uint64             `json:"estimated_bytes"`
	ByProtocol       []KeyCount         `json:"by_protocol"`
	TopSources       []KeyCount         `json:"top_sources"`
	TopDestinations  []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
	TopPorts         []KeyCount         `json:"top_ports"`
	LocalTraffic     struct {
		Bytes   uint64 `json:"bytes"`
		Packets uint64 `json:"packets"`
		Flows   int64  `json:"flows"`
	} `json:"local_traffic"`
}

// topAddrsByBytes returns top N addresses grouped by addrCol, ordered by total bytes descending.
func topAddrsByBytes(base func() *gorm.DB, addrCol string, limit int) []KeyCount {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	base().Select(addrCol + " as addr, SUM(bytes) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out
}

// topAddrsByBytesRollup is like topAddrsByBytes but for rollup tables (bytes_sum column).
func topAddrsByBytesRollup(base func() *gorm.DB, addrCol string, limit int) []KeyCount {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	base().Select(addrCol + " as addr, SUM(bytes_sum) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out
}

// GetFlowStats returns aggregated flow statistics, optionally filtered by device.
// It queries both raw flow_samples (recent) and flow_rollups (older data).
func (d *Database) GetFlowStats(hours int, deviceID uint) (*FlowStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &FlowStatsResult{}

	// Determine which data source to use:
	// - hours <= 1: raw samples only (rollups haven't consumed them yet)
	// - hours > 1: union raw samples + rollups
	useRollups := hours > 1

	// --- Raw flow_samples base ---
	newRawBase := func() *gorm.DB {
		q := d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff)
		if deviceID > 0 {
			q = q.Where("device_id = ?", deviceID)
		}
		return q
	}

	// --- Rollup base (best available interval for the time range) ---
	rollupInterval := "5m"
	if hours > 48 {
		rollupInterval = "1h"
	}
	if hours > 720 { // 30 days
		rollupInterval = "1d"
	}
	newRollupBase := func() *gorm.DB {
		q := d.db.Model(&models.FlowRollup{}).Where("timestamp > ? AND interval_type = ?", cutoff, rollupInterval)
		if deviceID > 0 {
			q = q.Where("device_id = ?", deviceID)
		}
		return q
	}

	// Combined aggregates: count, bytes, unique src/dst from raw samples
	var rawAgg struct {
		TotalFlows    int64
		TotalBytes    uint64
		UniqueSources int64
		UniqueDests   int64
	}
	// Multiply bytes/packets by sampling_rate to estimate actual traffic volume
	if err := newRawBase().Select("COUNT(*) as total_flows, COALESCE(SUM(bytes),0) as total_bytes, " +
		"COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
		Scan(&rawAgg).Error; err != nil {
		return nil, fmt.Errorf("flow stats raw aggregates: %w", err)
	}
	result.TotalFlows = rawAgg.TotalFlows
	result.TotalBytes = rawAgg.TotalBytes
	result.UniqueSources = rawAgg.UniqueSources
	result.UniqueDests = rawAgg.UniqueDests

	// Add rollup aggregates if needed
	if useRollups {
		var rollupAgg struct {
			TotalFlows    int64
			TotalBytes    uint64
			UniqueSources int64
			UniqueDests   int64
		}
		if err := newRollupBase().Select("COALESCE(SUM(flow_count),0) as total_flows, COALESCE(SUM(bytes_sum),0) as total_bytes, " +
			"COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
			Scan(&rollupAgg).Error; err != nil {
			log.Printf("Flow stats rollup aggregates: %v", err)
		} else {
			result.TotalFlows += rollupAgg.TotalFlows
			result.TotalBytes += rollupAgg.TotalBytes
			// For unique counts, the union of distinct sets needs re-counting; this is approximate
			if rollupAgg.UniqueSources > result.UniqueSources {
				result.UniqueSources = rollupAgg.UniqueSources
			}
			if rollupAgg.UniqueDests > result.UniqueDests {
				result.UniqueDests = rollupAgg.UniqueDests
			}
		}
	}

	// Total packets from raw
	var totalPkts struct{ Sum uint64 }
	newRawBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPkts)
	result.TotalPackets = totalPkts.Sum

	// Average sampling rate (0 means no sampling or unknown)
	var avgRate struct{ Rate float64 }
	newRawBase().Select("COALESCE(AVG(CASE WHEN sampling_rate > 0 THEN sampling_rate ELSE NULL END),0) as rate").Scan(&avgRate)
	result.AvgSamplingRate = avgRate.Rate
	if result.AvgSamplingRate > 1 {
		result.EstimatedBytes = uint64(float64(result.TotalBytes) * result.AvgSamplingRate)
	} else {
		result.EstimatedBytes = result.TotalBytes
	}

	// Computed throughput
	if hours > 0 {
		result.BitsPerSecond = float64(result.TotalBytes) * 8 / (float64(hours) * 3600)
	}

	// Local traffic stats (port-0 internal traffic, e.g. IPv6 link-local)
	var localRaw struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	newRawBase().Where("src_port = 0 AND dst_port = 0").
		Select("COALESCE(SUM(bytes),0) as bytes, COALESCE(SUM(packets),0) as packets, COUNT(*) as flows").
		Scan(&localRaw)
	result.LocalTraffic.Bytes = localRaw.Bytes
	result.LocalTraffic.Packets = localRaw.Packets
	result.LocalTraffic.Flows = localRaw.Flows

	if useRollups {
		var localRollup struct {
			Bytes   uint64
			Packets uint64
			Flows   int64
		}
		newRollupBase().Where("dst_port = 0").
			Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
			Scan(&localRollup)
		result.LocalTraffic.Bytes += localRollup.Bytes
		result.LocalTraffic.Packets += localRollup.Packets
		result.LocalTraffic.Flows += localRollup.Flows
	}

	// Filtered bases that exclude port-0 local traffic for top-N charts
	newFilteredRawBase := func() *gorm.DB {
		return newRawBase().Where("NOT (src_port = 0 AND dst_port = 0)")
	}
	newFilteredRollupBase := func() *gorm.DB {
		return newRollupBase().Where("dst_port != 0")
	}

	// Protocol distribution (from raw; supplement with rollups)
	var protocols []struct {
		Protocol uint8
		Count    int64
	}
	if err := newRawBase().Select("protocol, COUNT(*) as count").Group("protocol").
		Order("count DESC").Limit(10).Scan(&protocols).Error; err != nil {
		log.Printf("Flow stats protocol distribution: %v", err)
	}
	if useRollups {
		var rollupProtos []struct {
			Protocol uint8
			Count    int64
		}
		newRollupBase().Select("protocol, SUM(flow_count) as count").Group("protocol").
			Order("count DESC").Limit(10).Scan(&rollupProtos)
		// Merge rollup protocol counts into raw
		protoMap := make(map[uint8]int64)
		for _, p := range protocols {
			protoMap[p.Protocol] = p.Count
		}
		for _, p := range rollupProtos {
			protoMap[p.Protocol] += p.Count
		}
		protocols = protocols[:0]
		for proto, count := range protoMap {
			protocols = append(protocols, struct {
				Protocol uint8
				Count    int64
			}{proto, count})
		}
		sort.Slice(protocols, func(i, j int) bool { return protocols[i].Count > protocols[j].Count })
		if len(protocols) > 10 {
			protocols = protocols[:10]
		}
	}
	for _, p := range protocols {
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
	}
	result.ProtocolCount = int64(len(protocols))

	// Top sources by bytes (filtered: excludes port-0 local traffic)
	result.TopSources = topAddrsByBytes(newFilteredRawBase, "src_addr", 10)
	if useRollups {
		rollupSrc := topAddrsByBytesRollup(newFilteredRollupBase, "src_addr", 10)
		result.TopSources = mergeKeyCounts(result.TopSources, rollupSrc, 10)
	}

	// Top destinations by bytes (filtered: excludes port-0 local traffic)
	result.TopDestinations = topAddrsByBytes(newFilteredRawBase, "dst_addr", 10)
	if useRollups {
		rollupDst := topAddrsByBytesRollup(newFilteredRollupBase, "dst_addr", 10)
		result.TopDestinations = mergeKeyCounts(result.TopDestinations, rollupDst, 10)
	}

	// Top conversations (filtered: excludes port-0 local traffic)
	var convos []struct {
		SrcAddr  string
		DstAddr  string
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	if err := newFilteredRawBase().Select("src_addr, dst_addr, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, dst_port, protocol").
		Order("bytes DESC").Limit(10).Scan(&convos).Error; err != nil {
		log.Printf("Flow stats top conversations: %v", err)
	}
	for _, c := range convos {
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr:  c.SrcAddr,
			DstAddr:  c.DstAddr,
			DstPort:  c.DstPort,
			Protocol: protoName(c.Protocol),
			Bytes:    c.Bytes,
			Packets:  c.Packets,
		})
	}

	// Top destination ports
	var topPorts []struct {
		Port  uint16
		Total int64
	}
	newFilteredRawBase().Select("dst_port as port, SUM(bytes) as total").
		Where("dst_port > 0").Group("dst_port").Order("total DESC").Limit(10).Scan(&topPorts)
	for _, p := range topPorts {
		portName := fmt.Sprintf("%d", p.Port)
		if n, ok := wellKnownPorts[p.Port]; ok {
			portName = n
		}
		result.TopPorts = append(result.TopPorts, KeyCount{Key: portName, Count: p.Total})
	}

	// Adaptive time bucketing for bytes over time
	bucketUnit := "hour"
	result.BucketSeconds = 3600
	if hours <= 6 {
		bucketUnit = "minute"
		result.BucketSeconds = 60
	} else if hours > 168 {
		bucketUnit = "day"
		result.BucketSeconds = 86400
	}
	var timeSeries []struct {
		Bucket string
		Total  int64
	}
	if err := newRawBase().Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries).Error; err != nil {
		log.Printf("Flow stats bytes over time: %v", err)
	}

	// Merge rollup time series
	if useRollups {
		var rollupTS []struct {
			Bucket string
			Total  int64
		}
		newRollupBase().Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes_sum) as total").
			Group("bucket").Order("bucket ASC").Scan(&rollupTS)
		timeSeries = mergeTimeSeries(timeSeries, rollupTS)
	}

	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

// mergeKeyCounts merges two KeyCount slices by summing counts for matching keys,
// then returns the top N sorted by count descending.
func mergeKeyCounts(a, b []KeyCount, limit int) []KeyCount {
	m := make(map[string]int64, len(a)+len(b))
	for _, kc := range a {
		m[kc.Key] += kc.Count
	}
	for _, kc := range b {
		m[kc.Key] += kc.Count
	}
	merged := make([]KeyCount, 0, len(m))
	for k, c := range m {
		merged = append(merged, KeyCount{Key: k, Count: c})
	}
	// Sort descending by count
	sort.Slice(merged, func(i, j int) bool { return merged[i].Count > merged[j].Count })
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

// mergeTimeSeries merges two time-bucketed series by summing totals for matching buckets.
func mergeTimeSeries(a, b []struct {
	Bucket string
	Total  int64
}) []struct {
	Bucket string
	Total  int64
} {
	m := make(map[string]int64, len(a)+len(b))
	for _, ts := range a {
		m[ts.Bucket] += ts.Total
	}
	for _, ts := range b {
		m[ts.Bucket] += ts.Total
	}
	// Collect and sort by bucket
	result := make([]struct {
		Bucket string
		Total  int64
	}, 0, len(m))
	for k, v := range m {
		result = append(result, struct {
			Bucket string
			Total  int64
		}{k, v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Bucket < result[j].Bucket })
	return result
}

// rollupRow holds aggregated data during rollup operations.
type rollupRow struct {
	Bucket          string
	DeviceID        uint
	SrcAddr         string
	DstAddr         string
	DstPort         uint16
	Protocol        uint8
	BytesSum        uint64
	PacketsSum      uint64
	FlowCount       int64
	SamplingRateAvg uint32
}

// batchInsertRollups inserts rollup rows in batches within the given transaction.
func batchInsertRollups(tx *gorm.DB, rows []rollupRow, intervalType, bucketFmt string) error {
	const batchSize = 500
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]models.FlowRollup, 0, end-i)
		for _, r := range rows[i:end] {
			ts, _ := time.Parse(bucketFmt, r.Bucket)
			batch = append(batch, models.FlowRollup{
				Timestamp:       ts,
				DeviceID:        r.DeviceID,
				IntervalType:    intervalType,
				SrcAddr:         r.SrcAddr,
				DstAddr:         r.DstAddr,
				DstPort:         r.DstPort,
				Protocol:        r.Protocol,
				BytesSum:        r.BytesSum,
				PacketsSum:      r.PacketsSum,
				FlowCount:       r.FlowCount,
				SamplingRateAvg: r.SamplingRateAvg,
			})
		}
		if err := tx.Create(&batch).Error; err != nil {
			return fmt.Errorf("batch insert rollups: %w", err)
		}
	}
	return nil
}

// RunFlowRollupCycle aggregates raw flow samples into rollup buckets for scalability.
// Called every 5 minutes by the poller:
//  1. Raw flows older than 1h → 5m rollups
//  2. 5m rollups older than 48h → 1h rollups
//  3. 1h rollups older than 30d → 1d rollups
func (d *Database) RunFlowRollupCycle() {
	work := false

	// Step 1: raw flows > 1h old → 5m rollups
	cutoff1h := time.Now().Add(-1 * time.Hour)
	if d.aggregateFlowsToRollup(cutoff1h, "5m") {
		work = true
	}

	// Step 2: 5m rollups > 48h old → 1h rollups
	cutoff48h := time.Now().Add(-48 * time.Hour)
	if d.aggregateRollupsUp("5m", "1h", cutoff48h) {
		work = true
	}

	// Step 3: 1h rollups > 30d old → 1d rollups
	cutoff30d := time.Now().Add(-30 * 24 * time.Hour)
	if d.aggregateRollupsUp("1h", "1d", cutoff30d) {
		work = true
	}

	if !work {
		log.Println("Flow rollup: cycle complete (no data to aggregate)")
	}
}

// aggregateFlowsToRollup groups raw FlowSamples older than cutoff into 5-minute rollups.
// Returns true if work was done.
func (d *Database) aggregateFlowsToRollup(cutoff time.Time, intervalType string) bool {
	bucketExpr := d.dialect.TimeBucket("5min", "timestamp")

	// Paginate: process in chunks to limit memory usage
	const pageSize = 50000
	offset := 0
	totalGroups := 0

	for {
		var rows []rollupRow
		if err := d.db.Model(&models.FlowSample{}).
			Where("timestamp < ?", cutoff).
			Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, " +
				"SUM(bytes) as bytes_sum, SUM(packets) as packets_sum, COUNT(*) as flow_count, " +
				"AVG(sampling_rate) as sampling_rate_avg").
			Group("bucket, device_id, src_addr, dst_addr, dst_port, protocol").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Flow rollup: error scanning raw flows: %v", err)
			return totalGroups > 0
		}

		if len(rows) == 0 {
			break
		}

		// Wrap insert+delete in a transaction for atomicity
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertRollups(tx, rows, intervalType, "2006-01-02 15:04"); err != nil {
				return err
			}
			return nil
		}); err != nil {
			log.Printf("Flow rollup: transaction error: %v", err)
			return totalGroups > 0
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false
	}

	// Delete consumed raw rows (outside the insert tx since we've confirmed inserts succeeded)
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.FlowSample{}).Error; err != nil {
		log.Printf("Flow rollup: error deleting consumed raw flows: %v", err)
	}
	log.Printf("Flow rollup: aggregated %d groups from raw flows into %s rollups", totalGroups, intervalType)
	return true
}

// aggregateRollupsUp promotes rollups from srcInterval older than cutoff into dstInterval.
// Uses weighted average for sampling rate. Returns true if work was done.
func (d *Database) aggregateRollupsUp(srcInterval, dstInterval string, cutoff time.Time) bool {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if dstInterval == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	var rows []rollupRow
	if err := d.db.Model(&models.FlowRollup{}).
		Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
		Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, " +
			"SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count, " +
			"CASE WHEN SUM(flow_count) > 0 THEN SUM(sampling_rate_avg * flow_count) / SUM(flow_count) ELSE 0 END as sampling_rate_avg").
		Group("bucket, device_id, src_addr, dst_addr, dst_port, protocol").
		Scan(&rows).Error; err != nil {
		log.Printf("Flow rollup: error scanning %s rollups: %v", srcInterval, err)
		return false
	}

	if len(rows) == 0 {
		return false
	}

	// Wrap insert+delete in a transaction for atomicity
	if err := d.db.Transaction(func(tx *gorm.DB) error {
		if err := batchInsertRollups(tx, rows, dstInterval, bucketFmt); err != nil {
			return err
		}
		// Delete consumed source rollups within the same transaction
		if err := tx.Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Delete(&models.FlowRollup{}).Error; err != nil {
			return fmt.Errorf("delete consumed %s rollups: %w", srcInterval, err)
		}
		return nil
	}); err != nil {
		log.Printf("Flow rollup: transaction error promoting %s to %s: %v", srcInterval, dstInterval, err)
		return false
	}

	log.Printf("Flow rollup: promoted %d groups from %s to %s rollups", len(rows), srcInterval, dstInterval)
	return true
}

// RunSyslogAggregationCycle aggregates old informational syslog into summaries for scalability.
// Called every 5 minutes by the poller:
//  1. Raw informational (severity 6-7) older than SyslogInfoDays → hourly summaries
//  2. Hourly summaries older than 48h → daily summaries
func (d *Database) RunSyslogAggregationCycle(retention config.RetentionConfig) error {
	infoDays := retention.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // default: aggregate after 7 days
	}

	work := false
	var lastErr error

	// Step 1: raw informational syslog > infoDays old → hourly summaries
	cutoffInfo := time.Now().AddDate(0, 0, -infoDays)
	if done, err := d.aggregateSyslogToSummary(cutoffInfo, "1h"); err != nil {
		lastErr = err
		log.Printf("Syslog aggregation: step 1 error: %v", err)
	} else if done {
		work = true
	}

	// Step 2: hourly summaries > 48h old → daily summaries
	cutoff48h := time.Now().Add(-48 * time.Hour)
	if done, err := d.promoteSyslogSummaries("1h", "1d", cutoff48h); err != nil {
		lastErr = err
		log.Printf("Syslog aggregation: step 2 error: %v", err)
	} else if done {
		work = true
	}

	if !work && lastErr == nil {
		log.Println("Syslog aggregation: cycle complete (no data to aggregate)")
	}

	return lastErr
}

// syslogSummaryRow holds aggregated data during syslog summary operations.
type syslogSummaryRow struct {
	Bucket         string
	DeviceID       uint
	Severity       int
	Facility       int
	AppName        string
	MessagePattern string
	Count          int64
	SampleMessage  string
}

// aggregateSyslogToSummary groups raw informational syslog older than cutoff into hourly summaries.
// Returns true if work was done, error if fatal.
func (d *Database) aggregateSyslogToSummary(cutoff time.Time, intervalType string) (bool, error) {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if intervalType == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	const pageSize = 10000
	offset := 0
	totalGroups := 0

	for {
		var rows []syslogSummaryRow
		if err := d.db.Model(&models.SyslogMessage{}).
			Where("timestamp < ? AND severity >= 6", cutoff). // only informational (6) and debug (7)
			Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, " +
				"COUNT(*) as count, MIN(message) as sample_message").
			Group("bucket, device_id, severity, facility, app_name").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Syslog aggregation: error scanning raw messages: %v", err)
			return totalGroups > 0, err
		}

		if len(rows) == 0 {
			break
		}

		// Wrap insert+delete in a transaction for atomicity per page
		// Note: This deletes ALL informational messages < cutoff for simplicity.
		// If this page fails, messages will be re-aggregated on next cycle (potential duplicates, but safe).
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertSyslogSummaries(tx, rows, intervalType, bucketFmt); err != nil {
				return err
			}
			// Delete informational messages older than cutoff
			if err := tx.Where("timestamp < ? AND severity >= 6", cutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
				return fmt.Errorf("delete raw syslog after aggregation: %w", err)
			}
			return nil
		}); err != nil {
			log.Printf("Syslog aggregation: transaction error: %v", err)
			return totalGroups > 0, err
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false, nil
	}

	log.Printf("Syslog aggregation: aggregated %d groups from raw syslog into %s summaries", totalGroups, intervalType)
	return true, nil
}

// batchInsertSyslogSummaries inserts syslog summary rows in batches.
func batchInsertSyslogSummaries(tx *gorm.DB, rows []syslogSummaryRow, intervalType, bucketFmt string) error {
	const batchSize = 500
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]models.SyslogSummary, 0, end-i)
		for _, r := range rows[i:end] {
			ts, _ := time.Parse(bucketFmt, r.Bucket)
			batch = append(batch, models.SyslogSummary{
				Timestamp:      ts,
				DeviceID:       r.DeviceID,
				IntervalType:   intervalType,
				Severity:       r.Severity,
				Facility:       r.Facility,
				AppName:        r.AppName,
				MessagePattern: r.MessagePattern,
				Count:          r.Count,
				SampleMessage:  r.SampleMessage,
			})
		}
		if err := tx.Create(&batch).Error; err != nil {
			return fmt.Errorf("batch insert syslog summaries: %w", err)
		}
	}
	return nil
}

// promoteSyslogSummaries promotes summaries from srcInterval older than cutoff into dstInterval.
// Returns true if work was done, error if fatal.
func (d *Database) promoteSyslogSummaries(srcInterval, dstInterval string, cutoff time.Time) (bool, error) {
	bucketUnit := "day"
	bucketFmt := "2006-01-02"
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	const pageSize = 5000
	offset := 0
	totalGroups := 0

	for {
		var rows []syslogSummaryRow
		if err := d.db.Model(&models.SyslogSummary{}).
			Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, message_pattern, " +
				"SUM(count) as count, MIN(sample_message) as sample_message").
			Group("bucket, device_id, severity, facility, app_name, message_pattern").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Syslog aggregation: error scanning %s summaries: %v", srcInterval, err)
			return totalGroups > 0, err
		}

		if len(rows) == 0 {
			break
		}

		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertSyslogSummaries(tx, rows, dstInterval, bucketFmt); err != nil {
				return err
			}
			if err := tx.Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
				Delete(&models.SyslogSummary{}).Error; err != nil {
				return fmt.Errorf("delete consumed %s syslog summaries: %w", srcInterval, err)
			}
			return nil
		}); err != nil {
			log.Printf("Syslog aggregation: transaction error promoting %s to %s: %v", srcInterval, dstInterval, err)
			return totalGroups > 0, err
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false, nil
	}

	log.Printf("Syslog aggregation: promoted %d groups from %s to %s summaries", totalGroups, srcInterval, dstInterval)
	return true, nil
}

// EventStatsResult holds aggregated event statistics (alerts, traps, syslog)
type EventStatsResult struct {
	Total      int64        `json:"total"`
	BySeverity []KeyCount   `json:"by_severity"`
	ByType     []KeyCount   `json:"by_type"`
	OverTime   []TimeBucket `json:"over_time"`
}

// timeSeriesCount queries hourly time-bucketed counts for model since cutoff.
func (d *Database) timeSeriesCount(model interface{}, cutoff time.Time) []TimeBucket {
	var rows []struct {
		Bucket string
		Count  int64
	}
	d.db.Model(model).Where("timestamp > ?", cutoff).
		Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, COUNT(*) as count").
		Group("bucket").Order("bucket ASC").Scan(&rows)
	buckets := make([]TimeBucket, 0, len(rows))
	for _, r := range rows {
		buckets = append(buckets, TimeBucket{Bucket: r.Bucket, Count: r.Count})
	}
	return buckets
}

// groupByString queries COUNT grouped by groupCol on model since cutoff.
func (d *Database) groupByString(model interface{}, cutoff time.Time, groupCol string) []KeyCount {
	var rows []struct {
		Key   string
		Count int64
	}
	qCol := d.dialect.QuoteIdent(groupCol)
	d.db.Model(model).Where("timestamp > ?", cutoff).
		Select(qCol + " as key, COUNT(*) as count").Group(qCol).Order("count DESC").Scan(&rows)
	counts := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		counts = append(counts, KeyCount{Key: r.Key, Count: r.Count})
	}
	return counts
}

// GetAlertStats returns aggregated alert statistics
func (d *Database) GetAlertStats(hours int) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	d.db.Model(&models.Alert{}).Where("timestamp > ?", cutoff).Count(&result.Total)
	result.BySeverity = d.groupByString(&models.Alert{}, cutoff, "severity")
	result.ByType = d.groupByString(&models.Alert{}, cutoff, "alert_type")
	result.OverTime = d.timeSeriesCount(&models.Alert{}, cutoff)

	return result, nil
}

// GetTrapStats returns aggregated trap statistics
func (d *Database) GetTrapStats(hours int) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	d.db.Model(&models.TrapEvent{}).Where("timestamp > ?", cutoff).Count(&result.Total)
	result.BySeverity = d.groupByString(&models.TrapEvent{}, cutoff, "severity")
	result.ByType = d.groupByString(&models.TrapEvent{}, cutoff, "trap_type")
	result.OverTime = d.timeSeriesCount(&models.TrapEvent{}, cutoff)

	return result, nil
}

// GetSyslogStats returns aggregated syslog statistics (raw + summaries combined)
func (d *Database) GetSyslogStats(hours int) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	// Total: raw syslog + summaries
	var rawCount int64
	if err := d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff).Count(&rawCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count raw syslog: %w", err)
	}
	var summaryCount int64
	if err := d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff).
		Select("COALESCE(SUM(count), 0)").Scan(&summaryCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count syslog summaries: %w", err)
	}
	result.Total = rawCount + summaryCount

	// Syslog severity is numeric, map to human-readable names
	sevNames := map[int]string{0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error", 4: "Warning", 5: "Notice", 6: "Info", 7: "Debug"}
	var bySev []struct {
		Severity int
		Count    int64
	}
	// Get severity counts from raw syslog
	if err := d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff).
		Select("severity, COUNT(*) as count").Group("severity").Scan(&bySev).Error; err != nil {
		return nil, fmt.Errorf("failed to get raw syslog severity counts: %w", err)
	}
	// Get severity counts from summaries
	var summaryBySev []struct {
		Severity int
		Count    int64
	}
	if err := d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff).
		Select("severity, SUM(count) as count").Group("severity").Scan(&summaryBySev).Error; err != nil {
		return nil, fmt.Errorf("failed to get summary severity counts: %w", err)
	}
	// Merge summary counts into bySev
	sevMap := make(map[int]int64)
	for _, s := range bySev {
		sevMap[s.Severity] += s.Count
	}
	for _, s := range summaryBySev {
		sevMap[s.Severity] += s.Count
	}
	for sev, count := range sevMap {
		name := sevNames[sev]
		if name == "" {
			name = fmt.Sprintf("Severity %d", sev)
		}
		result.BySeverity = append(result.BySeverity, KeyCount{Key: name, Count: count})
	}

	// OverTime: combine raw time series with summary counts
	rawTimeSeries := d.timeSeriesCount(&models.SyslogMessage{}, cutoff)
	// Get summary time series grouped by hour
	var summaryTimeSeries []struct {
		Bucket string
		Count  int64
	}
	if err := d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff).
		Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, SUM(count) as count").
		Group("bucket").Order("bucket ASC").Scan(&summaryTimeSeries).Error; err != nil {
		return nil, fmt.Errorf("failed to get summary time series: %w", err)
	}
	// Merge summary time series into raw time series
	summaryMap := make(map[string]int64)
	for _, r := range summaryTimeSeries {
		summaryMap[r.Bucket] += r.Count
	}
	for _, r := range rawTimeSeries {
		summaryMap[r.Bucket] += r.Count
	}
	// Sort by bucket for consistent ordering
	buckets := make([]string, 0, len(summaryMap))
	for bucket := range summaryMap {
		buckets = append(buckets, bucket)
	}
	sort.Strings(buckets)
	for _, bucket := range buckets {
		result.OverTime = append(result.OverTime, TimeBucket{Bucket: bucket, Count: summaryMap[bucket]})
	}

	return result, nil
}

// DashboardTimeSeries holds overview metrics over time
type DashboardTimeSeries struct {
	FlowsOverTime   []TimeBucket `json:"flows_over_time"`
	AlertsOverTime  []TimeBucket `json:"alerts_over_time"`
	SyslogOverTime  []TimeBucket `json:"syslog_over_time"`
	TrapsOverTime   []TimeBucket `json:"traps_over_time"`
	DeviceStatusMap []KeyCount   `json:"device_status"`
}

// GetDashboardTimeSeries returns dashboard-level time-series data
func (d *Database) GetDashboardTimeSeries(hours int) (*DashboardTimeSeries, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &DashboardTimeSeries{
		FlowsOverTime:  d.timeSeriesCount(&models.FlowSample{}, cutoff),
		AlertsOverTime: d.timeSeriesCount(&models.Alert{}, cutoff),
		SyslogOverTime: d.timeSeriesCount(&models.SyslogMessage{}, cutoff),
		TrapsOverTime:  d.timeSeriesCount(&models.TrapEvent{}, cutoff),
	}

	// Device status distribution
	var deviceStatus []struct {
		Status string
		Count  int64
	}
	d.db.Model(&models.Device{}).Where("enabled = ?", true).
		Select("status, COUNT(*) as count").Group("status").Scan(&deviceStatus)
	for _, s := range deviceStatus {
		result.DeviceStatusMap = append(result.DeviceStatusMap, KeyCount{Key: s.Status, Count: s.Count})
	}

	return result, nil
}

func (d *Database) GetDevicesByProbe(probeID uint) ([]models.Device, error) {
	var devices []models.Device
	err := d.db.Where("probe_id = ?", probeID).Preload("Site").Find(&devices).Error
	for i := range devices {
		d.DecryptDeviceSecrets(&devices[i])
	}
	return devices, err
}

// VPNChartBucket holds a single time-bucket for VPN tunnel chart data.
type VPNChartBucket struct {
	Bucket     string  `json:"bucket"`
	InBytes    float64 `json:"in_bytes"`
	OutBytes   float64 `json:"out_bytes"`
	InPackets  float64 `json:"in_packets"`
	OutPackets float64 `json:"out_packets"`
}

// GetVPNChartData returns downsampled VPN tunnel stats for charting.
func (d *Database) GetVPNChartData(deviceID uint, tunnelName string, rangeStr string) ([]VPNChartBucket, error) {
	var hours int
	var bucketExpr string
	switch rangeStr {
	case "1h":
		hours = 1
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	default: // 24h
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Use LAG() window function to compute per-sample deltas from cumulative SNMP counters.
	// First row per partition (LAG is NULL) returns NULL and is filtered by the outer WHERE.
	// Counter resets (new value < old value) use the raw value as the delta.
	query := fmt.Sprintf(`
		SELECT bucket, SUM(delta_in) as in_bytes, SUM(delta_out) as out_bytes,
		       SUM(delta_pin) as in_packets, SUM(delta_pout) as out_packets
		FROM (
			SELECT %s as bucket,
				CASE WHEN LAG(bytes_in) OVER w IS NULL THEN NULL
					WHEN bytes_in >= LAG(bytes_in) OVER w THEN bytes_in - LAG(bytes_in) OVER w
					ELSE bytes_in END as delta_in,
				CASE WHEN LAG(bytes_out) OVER w IS NULL THEN NULL
					WHEN bytes_out >= LAG(bytes_out) OVER w THEN bytes_out - LAG(bytes_out) OVER w
					ELSE bytes_out END as delta_out,
				CASE WHEN LAG(packets_in) OVER w IS NULL THEN NULL
					WHEN packets_in >= LAG(packets_in) OVER w THEN packets_in - LAG(packets_in) OVER w
					ELSE packets_in END as delta_pin,
				CASE WHEN LAG(packets_out) OVER w IS NULL THEN NULL
					WHEN packets_out >= LAG(packets_out) OVER w THEN packets_out - LAG(packets_out) OVER w
					ELSE packets_out END as delta_pout
			FROM vpn_status
			WHERE device_id = ? AND tunnel_name = ? AND timestamp > ?
			WINDOW w AS (ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`, bucketExpr)

	var rows []VPNChartBucket
	err := d.db.Raw(query, deviceID, tunnelName, cutoff).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Phase2Match represents a matched pair of Phase 2 selectors between two devices.
type Phase2Match struct {
	SourceTunnel string `json:"source_tunnel"`
	DestTunnel   string `json:"dest_tunnel"`
	SourcePhase1 string `json:"source_phase1"`
	DestPhase1   string `json:"dest_phase1"`
	LocalSubnet  string `json:"local_subnet"`
	RemoteSubnet string `json:"remote_subnet"`
	SourceStatus string `json:"source_status"`
	DestStatus   string `json:"dest_status"`
	SrcBytesIn   uint64 `json:"src_bytes_in"`
	SrcBytesOut  uint64 `json:"src_bytes_out"`
	DstBytesIn   uint64 `json:"dst_bytes_in"`
	DstBytesOut  uint64 `json:"dst_bytes_out"`
	SrcUptime    uint64 `json:"src_uptime"`
	DstUptime    uint64 `json:"dst_uptime"`
}

// ConnectionDetailResult holds full detail for a connection including matching tunnels.
type ConnectionDetailResult struct {
	Connection      models.DeviceConnection `json:"connection"`
	SourceTunnels   []models.VPNStatus      `json:"source_tunnels"`
	DestTunnels     []models.VPNStatus      `json:"dest_tunnels"`
	TotalBytesIn    uint64                  `json:"total_bytes_in"`
	TotalBytesOut   uint64                  `json:"total_bytes_out"`
	TotalPacketsIn  uint64                  `json:"total_packets_in"`
	TotalPacketsOut uint64                  `json:"total_packets_out"`
	ThroughputIn    float64                 `json:"throughput_in"`
	ThroughputOut   float64                 `json:"throughput_out"`
	HasFlowData     bool                    `json:"has_flow_data"`
	Phase2Matches   []Phase2Match           `json:"phase2_matches"`
}

// collectDeviceIPs returns all known IPs for a device (management + interface addresses).
func (d *Database) collectDeviceIPs(deviceID uint, device *models.Device) map[string]bool {
	ips := make(map[string]bool)
	if device != nil && device.IPAddress != "" {
		ips[device.IPAddress] = true
	}
	var distinctIPs []string
	d.db.Model(&models.InterfaceAddress{}).
		Where("device_id = ?", deviceID).
		Distinct("ip_address").
		Pluck("ip_address", &distinctIPs)
	for _, ip := range distinctIPs {
		ips[ip] = true
	}
	return ips
}

// GetConnectionDetail returns full detail for a connection with matching tunnels from both sides.
func (d *Database) GetConnectionDetail(connID uint) (*ConnectionDetailResult, error) {
	var conn models.DeviceConnection
	if err := d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return nil, err
	}

	result := &ConnectionDetailResult{Connection: conn}

	// Get latest VPN statuses for both devices
	srcTunnels, _ := d.GetLatestVPNStatuses(conn.SourceDeviceID)
	dstTunnels, _ := d.GetLatestVPNStatuses(conn.DestDeviceID)

	// Collect IPs for the dest device (management + interface addresses)
	destIPs := d.collectDeviceIPs(conn.DestDeviceID, conn.DestDevice)

	// Collect IPs for the source device
	srcIPs := d.collectDeviceIPs(conn.SourceDeviceID, conn.SourceDevice)

	// Build a set of known tunnel names from the connection record (auto-discovery)
	knownTunnels := make(map[string]bool)
	if conn.TunnelNames != "" {
		for _, name := range strings.Split(conn.TunnelNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				knownTunnels[name] = true
			}
		}
	}

	// Filter source tunnels: remote IP matches dest device OR tunnel name in known list
	for _, t := range srcTunnels {
		if destIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			// Avoid duplicates
			alreadyAdded := false
			for _, existing := range result.SourceTunnels {
				if existing.TunnelName == t.TunnelName && existing.DeviceID == t.DeviceID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}
			result.SourceTunnels = append(result.SourceTunnels, t)
			result.TotalBytesIn += t.BytesIn
			result.TotalBytesOut += t.BytesOut
			result.TotalPacketsIn += t.PacketsIn
			result.TotalPacketsOut += t.PacketsOut
		}
	}

	// For indirectly matched connections (NAT'd hub-spoke), dest tunnels' remote IPs
	// are likely source's WAN IPs. Add them to srcIPs so dest tunnels can match.
	// This is safe because the VPN detector already confirmed the connection.
	if conn.MatchMethod == "tunnel_indirect" || conn.MatchMethod == "wan_inferred" {
		for _, t := range dstTunnels {
			if t.RemoteIP != "" {
				srcIPs[t.RemoteIP] = true
			}
		}
	}

	// Filter dest tunnels: remote IP matches source device (including inferred WAN IPs),
	// or tunnel name is in the known list from auto-detection
	for _, t := range dstTunnels {
		if srcIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			// Avoid duplicates
			alreadyAdded := false
			for _, existing := range result.DestTunnels {
				if existing.TunnelName == t.TunnelName && existing.DeviceID == t.DeviceID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}
			result.DestTunnels = append(result.DestTunnels, t)
		}
	}

	// Cross-fill: if one side has empty subnets, infer from the other side (swapped).
	// Hub-side ADVPN tunnels often have empty Phase 2 selectors in SNMP.
	log.Printf("GetConnectionDetail %d: source_tunnels=%d dest_tunnels=%d", connID, len(result.SourceTunnels), len(result.DestTunnels))
	for i, t := range result.SourceTunnels {
		log.Printf("GetConnectionDetail %d: source_tunnel[%d] name=%s local=%s remote=%s", connID, i, t.TunnelName, t.LocalSubnet, t.RemoteSubnet)
	}
	for i, t := range result.DestTunnels {
		log.Printf("GetConnectionDetail %d: dest_tunnel[%d] name=%s local=%s remote=%s", connID, i, t.TunnelName, t.LocalSubnet, t.RemoteSubnet)
	}
	if len(result.SourceTunnels) > 0 && len(result.DestTunnels) > 0 {
		for i := range result.SourceTunnels {
			if result.SourceTunnels[i].LocalSubnet == "" || result.SourceTunnels[i].RemoteSubnet == "" {
				for _, dst := range result.DestTunnels {
					if dst.LocalSubnet != "" && dst.RemoteSubnet != "" {
						if result.SourceTunnels[i].LocalSubnet == "" {
							result.SourceTunnels[i].LocalSubnet = dst.RemoteSubnet
						}
						if result.SourceTunnels[i].RemoteSubnet == "" {
							result.SourceTunnels[i].RemoteSubnet = dst.LocalSubnet
						}
						break
					}
				}
			}
		}
		for i := range result.DestTunnels {
			if result.DestTunnels[i].LocalSubnet == "" || result.DestTunnels[i].RemoteSubnet == "" {
				for _, src := range result.SourceTunnels {
					if src.LocalSubnet != "" && src.RemoteSubnet != "" {
						if result.DestTunnels[i].LocalSubnet == "" {
							result.DestTunnels[i].LocalSubnet = src.RemoteSubnet
						}
						if result.DestTunnels[i].RemoteSubnet == "" {
							result.DestTunnels[i].RemoteSubnet = src.LocalSubnet
						}
						break
					}
				}
			}
		}
	}

	// Cross-fill tunnel uptime: if one side reports 0 uptime, use the paired tunnel's value.
	if len(result.SourceTunnels) > 0 && len(result.DestTunnels) > 0 {
		for i := range result.SourceTunnels {
			if result.SourceTunnels[i].TunnelUptime == 0 {
				for _, dst := range result.DestTunnels {
					if dst.TunnelUptime > 0 {
						result.SourceTunnels[i].TunnelUptime = dst.TunnelUptime
						break
					}
				}
			}
		}
		for i := range result.DestTunnels {
			if result.DestTunnels[i].TunnelUptime == 0 {
				for _, src := range result.SourceTunnels {
					if src.TunnelUptime > 0 {
						result.DestTunnels[i].TunnelUptime = src.TunnelUptime
						break
					}
				}
			}
		}
	}

	// Phase 2 inverse matching: source's local_subnet == dest's remote_subnet (and vice versa)
	for _, src := range result.SourceTunnels {
		if src.LocalSubnet == "" || src.RemoteSubnet == "" {
			continue
		}
		for _, dst := range result.DestTunnels {
			if dst.LocalSubnet == "" || dst.RemoteSubnet == "" {
				continue
			}
			if src.LocalSubnet == dst.RemoteSubnet && src.RemoteSubnet == dst.LocalSubnet {
				result.Phase2Matches = append(result.Phase2Matches, Phase2Match{
					SourceTunnel: src.TunnelName,
					DestTunnel:   dst.TunnelName,
					SourcePhase1: src.Phase1Name,
					DestPhase1:   dst.Phase1Name,
					LocalSubnet:  src.LocalSubnet,
					RemoteSubnet: src.RemoteSubnet,
					SourceStatus: src.Status,
					DestStatus:   dst.Status,
					SrcBytesIn:   src.BytesIn,
					SrcBytesOut:  src.BytesOut,
					DstBytesIn:   dst.BytesIn,
					DstBytesOut:  dst.BytesOut,
					SrcUptime:    src.TunnelUptime,
					DstUptime:    dst.TunnelUptime,
				})
			}
		}
	}

	// Compute live throughput (bytes/sec) from the two most recent VPNStatus samples per source tunnel
	for _, t := range result.SourceTunnels {
		var samples []models.VPNStatus
		d.db.Where("device_id = ? AND tunnel_name = ?", t.DeviceID, t.TunnelName).
			Order("timestamp DESC").Limit(2).Find(&samples)
		if len(samples) == 2 {
			dt := samples[0].Timestamp.Sub(samples[1].Timestamp).Seconds()
			if dt > 0 {
				dIn := float64(samples[0].BytesIn) - float64(samples[1].BytesIn)
				dOut := float64(samples[0].BytesOut) - float64(samples[1].BytesOut)
				// Handle counter resets
				if dIn < 0 {
					dIn = float64(samples[0].BytesIn)
				}
				if dOut < 0 {
					dOut = float64(samples[0].BytesOut)
				}
				result.ThroughputIn += dIn / dt
				result.ThroughputOut += dOut / dt
			}
		}
	}

	// Check if sFlow data exists for either device
	var flowCount int64
	d.db.Model(&models.FlowSample{}).Where("device_id IN ?", []uint{conn.SourceDeviceID, conn.DestDeviceID}).Limit(1).Count(&flowCount)
	result.HasFlowData = flowCount > 0

	return result, nil
}

// getConnectionTunnelNames returns matching tunnel names for a connection's source and dest devices.
func (d *Database) getConnectionTunnelNames(connID uint) (srcDeviceID, dstDeviceID uint, srcTunnelNames, dstTunnelNames []string, err error) {
	var conn models.DeviceConnection
	if err = d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return
	}
	srcDeviceID = conn.SourceDeviceID
	dstDeviceID = conn.DestDeviceID

	srcTunnels, _ := d.GetLatestVPNStatuses(conn.SourceDeviceID)
	dstTunnels, _ := d.GetLatestVPNStatuses(conn.DestDeviceID)

	// Collect IPs for both devices
	destIPs := d.collectDeviceIPs(conn.DestDeviceID, conn.DestDevice)
	srcIPs := d.collectDeviceIPs(conn.SourceDeviceID, conn.SourceDevice)

	// For indirectly matched connections (NAT'd hub-spoke), relax IP matching
	// by adding the peer's tunnel remote IPs — same logic as GetConnectionDetail
	if conn.MatchMethod == "tunnel_indirect" || conn.MatchMethod == "wan_inferred" {
		for _, t := range dstTunnels {
			if t.RemoteIP != "" {
				srcIPs[t.RemoteIP] = true
			}
		}
		for _, t := range srcTunnels {
			if t.RemoteIP != "" {
				destIPs[t.RemoteIP] = true
			}
		}
	}

	// Known tunnel names from auto-discovery
	knownTunnels := make(map[string]bool)
	if conn.TunnelNames != "" {
		for _, name := range strings.Split(conn.TunnelNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				knownTunnels[name] = true
			}
		}
	}

	for _, t := range srcTunnels {
		if destIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			srcTunnelNames = append(srcTunnelNames, t.TunnelName)
		}
	}
	for _, t := range dstTunnels {
		if srcIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			dstTunnelNames = append(dstTunnelNames, t.TunnelName)
		}
	}
	return
}

// GetConnectionTraffic returns aggregated VPN chart data for all matching tunnels in a connection.
func (d *Database) GetConnectionTraffic(connID uint, rangeStr string) ([]VPNChartBucket, error) {
	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	// Determine time params
	var hours int
	var bucketExpr string
	switch rangeStr {
	case "1h":
		hours = 1
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	default:
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Collect all tunnel conditions
	var allNames []string
	var deviceIDs []uint
	for _, n := range srcTunnelNames {
		allNames = append(allNames, n)
	}
	for _, n := range dstTunnelNames {
		allNames = append(allNames, n)
	}
	if len(srcTunnelNames) > 0 {
		deviceIDs = append(deviceIDs, srcDeviceID)
	}
	if len(dstTunnelNames) > 0 {
		deviceIDs = append(deviceIDs, dstDeviceID)
	}

	if len(allNames) == 0 {
		return []VPNChartBucket{}, nil
	}

	// Build explicit placeholders for IN clauses (GORM Raw doesn't reliably expand slices)
	var args []interface{}
	devPH := make([]string, len(deviceIDs))
	for i, id := range deviceIDs {
		devPH[i] = "?"
		args = append(args, id)
	}
	namePH := make([]string, len(allNames))
	for i, n := range allNames {
		namePH[i] = "?"
		args = append(args, n)
	}
	args = append(args, cutoff)

	// Use LAG() window function to compute per-sample deltas from cumulative SNMP counters.
	// First row per partition (LAG is NULL) returns NULL and is filtered by the outer WHERE.
	query := fmt.Sprintf(`
		SELECT bucket, SUM(delta_in) as in_bytes, SUM(delta_out) as out_bytes,
		       SUM(delta_pin) as in_packets, SUM(delta_pout) as out_packets
		FROM (
			SELECT %s as bucket,
				CASE WHEN LAG(bytes_in) OVER w IS NULL THEN NULL
					WHEN bytes_in >= LAG(bytes_in) OVER w THEN bytes_in - LAG(bytes_in) OVER w
					ELSE bytes_in END as delta_in,
				CASE WHEN LAG(bytes_out) OVER w IS NULL THEN NULL
					WHEN bytes_out >= LAG(bytes_out) OVER w THEN bytes_out - LAG(bytes_out) OVER w
					ELSE bytes_out END as delta_out,
				CASE WHEN LAG(packets_in) OVER w IS NULL THEN NULL
					WHEN packets_in >= LAG(packets_in) OVER w THEN packets_in - LAG(packets_in) OVER w
					ELSE packets_in END as delta_pin,
				CASE WHEN LAG(packets_out) OVER w IS NULL THEN NULL
					WHEN packets_out >= LAG(packets_out) OVER w THEN packets_out - LAG(packets_out) OVER w
					ELSE packets_out END as delta_pout
			FROM vpn_status
			WHERE device_id IN (%s) AND tunnel_name IN (%s) AND timestamp > ?
			WINDOW w AS (PARTITION BY device_id, tunnel_name ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`,
		bucketExpr, strings.Join(devPH, ","), strings.Join(namePH, ","))

	var rows []VPNChartBucket
	err = d.db.Raw(query, args...).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// FlowConversation represents a top conversation from flow data.
type FlowConversation struct {
	SrcAddr  string `json:"src_addr"`
	DstAddr  string `json:"dst_addr"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
}

// ConnectionFlowResult holds sFlow traffic analysis for a connection.
type ConnectionFlowResult struct {
	TotalBytes       uint64             `json:"total_bytes"`
	TotalPackets     uint64             `json:"total_packets"`
	TotalFlows       int64              `json:"total_flows"`
	ByProtocol       []KeyCount         `json:"by_protocol"`
	TopSources       []KeyCount         `json:"top_sources"`
	TopDests         []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
}

// cidrToLikePattern converts a CIDR subnet to a SQL LIKE pattern.
// Works for /8, /16, /24 which cover ~99% of real VPN subnets.
// Returns empty string for invalid, too-broad (e.g. 0.0.0.0/0), or unsupported prefix lengths.
func cidrToLikePattern(cidr string) string {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || cidr == "0.0.0.0/0" {
		return ""
	}

	// Handle non-CIDR formats: "10.0.1.0 - 10.0.1.255" or bare IPs
	if !strings.Contains(cidr, "/") {
		// IP range format
		if strings.Contains(cidr, " - ") {
			parts := strings.SplitN(cidr, " - ", 2)
			beginIP := net.ParseIP(strings.TrimSpace(parts[0]))
			if beginIP == nil {
				return ""
			}
			b := beginIP.To4()
			if b == nil {
				return ""
			}
			return fmt.Sprintf("%d.%d.%d.%%", b[0], b[1], b[2])
		}
		// Single IP — exact match
		if net.ParseIP(cidr) != nil {
			return cidr
		}
		return ""
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return ""
	}
	ones, _ := ipNet.Mask.Size()
	switch {
	case ones == 32:
		return fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])
	case ones >= 24:
		return fmt.Sprintf("%d.%d.%d.%%", ip4[0], ip4[1], ip4[2])
	case ones >= 16:
		return fmt.Sprintf("%d.%d.%%", ip4[0], ip4[1])
	case ones >= 8:
		return fmt.Sprintf("%d.%%", ip4[0])
	default:
		return ""
	}
}

// GetConnectionFlowStats returns sFlow traffic analysis for a connection.
// Primary strategy: filter flows by VPN subnet pairs (local/remote).
// Fallback: match tunnel interface indices by name (including Phase1Name).
func (d *Database) GetConnectionFlowStats(connID uint, hours int) (*ConnectionFlowResult, error) {
	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	var tunnelNames []string
	tunnelNames = append(tunnelNames, srcTunnelNames...)
	tunnelNames = append(tunnelNames, dstTunnelNames...)
	if len(tunnelNames) == 0 {
		return &ConnectionFlowResult{}, nil
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	deviceIDs := []uint{srcDeviceID, dstDeviceID}

	// --- Strategy 1: Subnet-based filtering ---
	// Query VPN statuses for these tunnel names to get (local_subnet, remote_subnet) pairs
	type subnetPair struct {
		LocalSubnet  string
		RemoteSubnet string
	}
	var pairs []subnetPair
	d.db.Raw(`SELECT DISTINCT local_subnet, remote_subnet FROM vpn_status
		WHERE device_id IN ? AND tunnel_name IN ? AND local_subnet != '' AND remote_subnet != ''`,
		deviceIDs, tunnelNames).Scan(&pairs)

	// Convert subnet pairs to LIKE patterns
	var subnetConditions []string
	var subnetArgs []interface{}
	for _, p := range pairs {
		localPattern := cidrToLikePattern(p.LocalSubnet)
		remotePattern := cidrToLikePattern(p.RemoteSubnet)
		if localPattern == "" || remotePattern == "" {
			continue
		}
		// Bidirectional: src in local AND dst in remote, OR vice versa
		subnetConditions = append(subnetConditions,
			"(src_addr LIKE ? AND dst_addr LIKE ?)",
			"(src_addr LIKE ? AND dst_addr LIKE ?)")
		subnetArgs = append(subnetArgs, localPattern, remotePattern, remotePattern, localPattern)
	}

	result := &ConnectionFlowResult{}

	var newBase func() *gorm.DB

	if len(subnetConditions) > 0 {
		// Use subnet-based filtering
		subnetWhere := strings.Join(subnetConditions, " OR ")
		newBase = func() *gorm.DB {
			return d.db.Model(&models.FlowSample{}).
				Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
				Where(subnetWhere, subnetArgs...)
		}
	} else {
		// --- Strategy 2 (fallback): Interface index matching with Phase1Names ---
		// Collect Phase1Names alongside tunnel names for better interface matching
		var phase1Names []string
		d.db.Raw(`SELECT DISTINCT phase1_name FROM vpn_status
			WHERE device_id IN ? AND tunnel_name IN ? AND phase1_name != ''`,
			deviceIDs, tunnelNames).Pluck("phase1_name", &phase1Names)

		allNames := make([]string, 0, len(tunnelNames)+len(phase1Names))
		allNames = append(allNames, tunnelNames...)
		allNames = append(allNames, phase1Names...)

		var tunnelIfIndices []int
		ifIndexSet := make(map[int]bool)
		var ifaces []models.InterfaceStats
		d.db.Raw(fmt.Sprintf("SELECT DISTINCT device_id, %s FROM interface_stats WHERE device_id IN ? AND (name IN ? OR description IN ? OR alias IN ?)", d.dialect.QuoteIdent("index")),
			deviceIDs, allNames, allNames, allNames).Scan(&ifaces)
		for _, iface := range ifaces {
			ifIndexSet[iface.Index] = true
		}
		for idx := range ifIndexSet {
			tunnelIfIndices = append(tunnelIfIndices, idx)
		}
		if len(tunnelIfIndices) == 0 {
			return &ConnectionFlowResult{}, nil
		}

		newBase = func() *gorm.DB {
			return d.db.Model(&models.FlowSample{}).
				Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
				Where("input_if_index IN ? OR output_if_index IN ?", tunnelIfIndices, tunnelIfIndices)
		}
	}

	// Total counts from raw samples
	newBase().Count(&result.TotalFlows)
	var totalBytes struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(bytes),0) as sum").Scan(&totalBytes)
	result.TotalBytes = totalBytes.Sum
	var totalPackets struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPackets)
	result.TotalPackets = totalPackets.Sum

	// Supplement with rollup data for historical periods (subnet strategy only)
	if hours > 1 && len(subnetConditions) > 0 {
		rollupInterval := "5m"
		if hours > 48 {
			rollupInterval = "1h"
		}
		if hours > 720 {
			rollupInterval = "1d"
		}
		subnetWhere := strings.Join(subnetConditions, " OR ")
		rollupBase := func() *gorm.DB {
			return d.db.Model(&models.FlowRollup{}).
				Where("device_id IN ? AND timestamp > ? AND interval_type = ?", deviceIDs, cutoff, rollupInterval).
				Where(subnetWhere, subnetArgs...)
		}
		var rollupAgg struct {
			Flows int64
			Bytes uint64
			Pkts  uint64
		}
		rollupBase().Select("COALESCE(SUM(flow_count),0) as flows, COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as pkts").Scan(&rollupAgg)
		result.TotalFlows += rollupAgg.Flows
		result.TotalBytes += rollupAgg.Bytes
		result.TotalPackets += rollupAgg.Pkts
	}

	// Protocol distribution
	var protocols []struct {
		Protocol uint8
		Count    int64
	}
	newBase().Select("protocol, COUNT(*) as count").Group("protocol").Order("count DESC").Limit(10).Scan(&protocols)
	for _, p := range protocols {
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
	}

	// Top sources / destinations by bytes
	result.TopSources = topAddrsByBytes(newBase, "src_addr", 10)
	result.TopDests = topAddrsByBytes(newBase, "dst_addr", 10)

	// Top conversations
	var convos []struct {
		SrcAddr  string
		DstAddr  string
		SrcPort  uint16
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	newBase().Select("src_addr, dst_addr, src_port, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, src_port, dst_port, protocol").Order("bytes DESC").Limit(10).Scan(&convos)
	for _, c := range convos {
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr: c.SrcAddr, DstAddr: c.DstAddr,
			SrcPort: c.SrcPort, DstPort: c.DstPort,
			Protocol: protoName(c.Protocol), Bytes: c.Bytes, Packets: c.Packets,
		})
	}

	// Bytes over time
	var timeSeries []struct {
		Bucket string `json:"bucket"`
		Total  int64  `json:"total"`
	}
	newBase().Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries)
	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

// GetAlertsByDeviceAndHours returns alerts for a specific device within the given hours.
func (d *Database) GetAlertsByDeviceAndHours(deviceID uint, hours int) ([]models.Alert, error) {
	var alerts []models.Alert
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp DESC").Find(&alerts).Error
	return alerts, err
}

// InterfaceTrafficSummary holds aggregated traffic for an interface.
type InterfaceTrafficSummary struct {
	Name       string  `json:"name"`
	Index      int     `json:"index"`
	TotalIn    float64 `json:"total_in"`
	TotalOut   float64 `json:"total_out"`
	TotalBytes float64 `json:"total_bytes"`
}

// GetTopInterfacesByTraffic returns the top N interfaces by total bytes for a device.
func (d *Database) GetTopInterfacesByTraffic(deviceID uint, hours int, limit int) ([]InterfaceTrafficSummary, error) {
	var results []InterfaceTrafficSummary
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	quotedIndex := d.dialect.QuoteIdent("index")
	err := d.db.Model(&models.InterfaceStats{}).
		Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Select(fmt.Sprintf("name, %s as %s, SUM(in_bytes) as total_in, SUM(out_bytes) as total_out, SUM(in_bytes)+SUM(out_bytes) as total_bytes",
			quotedIndex, quotedIndex)).
		Group(fmt.Sprintf("name, %s", quotedIndex)).
		Order("total_bytes DESC").
		Limit(limit).
		Scan(&results).Error
	return results, err
}

// GetDevicePollCount returns the number of system_status rows for a device since the given time.
func (d *Database) GetDevicePollCount(deviceID uint, since time.Time) (int64, error) {
	var count int64
	err := d.db.Model(&models.SystemStatus{}).
		Where("device_id = ? AND timestamp > ?", deviceID, since).
		Count(&count).Error
	return count, err
}

// GetDeviceFirstPoll returns the earliest timestamp from system_status for a device.
func (d *Database) GetDeviceFirstPoll(deviceID uint) (time.Time, error) {
	var result struct {
		MinTS *time.Time
	}
	err := d.db.Model(&models.SystemStatus{}).
		Where("device_id = ?", deviceID).
		Select("MIN(timestamp) as min_ts").
		Scan(&result).Error
	if err != nil {
		return time.Time{}, err
	}
	if result.MinTS == nil {
		return time.Time{}, nil
	}
	return *result.MinTS, nil
}

// --- Alert Policy CRUD ---

func (d *Database) EnsureDefaultPolicy() {
	var policy models.AlertPolicy
	d.db.Where("is_default = ?", true).Attrs(models.AlertPolicy{
		Name:            "Default",
		Description:     "Default alert policy — all notifications use global settings",
		IsDefault:       true,
		CooldownMinutes: 5,
	}).FirstOrCreate(&policy)
}

func (d *Database) GetAlertPolicies() ([]models.AlertPolicy, error) {
	var policies []models.AlertPolicy
	err := d.db.Preload("Rules").Order("is_default DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (d *Database) GetAlertPolicy(id uint) (*models.AlertPolicy, error) {
	var policy models.AlertPolicy
	err := d.db.Preload("Rules").First(&policy, id).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (d *Database) GetDefaultAlertPolicy() (*models.AlertPolicy, error) {
	var policy models.AlertPolicy
	err := d.db.Preload("Rules").Where("is_default = ?", true).First(&policy).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (d *Database) CreateAlertPolicy(policy *models.AlertPolicy) error {
	return d.db.Create(policy).Error
}

func (d *Database) UpdateAlertPolicy(policy *models.AlertPolicy) error {
	return d.db.Save(policy).Error
}

func (d *Database) DeleteAlertPolicy(id uint) error {
	// Prevent deleting default policy
	var policy models.AlertPolicy
	if err := d.db.First(&policy, id).Error; err != nil {
		return err
	}
	if policy.IsDefault {
		return fmt.Errorf("cannot delete the default alert policy")
	}
	// Delete associated rules first
	d.db.Where("policy_id = ?", id).Delete(&models.AlertRule{})
	return d.db.Delete(&models.AlertPolicy{}, id).Error
}

func (d *Database) BatchUpsertAlertRules(policyID uint, rules []models.AlertRule) error {
	// Delete existing rules for this policy
	if err := d.db.Where("policy_id = ?", policyID).Delete(&models.AlertRule{}).Error; err != nil {
		return err
	}
	// Insert new rules
	for i := range rules {
		rules[i].ID = 0
		rules[i].PolicyID = policyID
	}
	if len(rules) > 0 {
		return d.db.Create(&rules).Error
	}
	return nil
}

// --- Device Alert Config CRUD ---

func (d *Database) GetDeviceAlertConfig(deviceID uint) (*models.DeviceAlertConfig, error) {
	var cfg models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", deviceID).First(&cfg).Error
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (d *Database) UpsertDeviceAlertConfig(cfg *models.DeviceAlertConfig) error {
	var existing models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", cfg.DeviceID).First(&existing).Error
	if err == nil {
		cfg.ID = existing.ID
		return d.db.Save(cfg).Error
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	return d.db.Create(cfg).Error
}

func (d *Database) DeleteDeviceAlertConfig(deviceID uint) error {
	return d.db.Where("device_id = ?", deviceID).Delete(&models.DeviceAlertConfig{}).Error
}

func (d *Database) GetAllDeviceAlertConfigs() ([]models.DeviceAlertConfig, error) {
	var configs []models.DeviceAlertConfig
	err := d.db.Find(&configs).Error
	return configs, err
}

// --- Site Alert Config CRUD ---

func (d *Database) GetSiteAlertConfig(siteID uint) (*models.SiteAlertConfig, error) {
	var cfg models.SiteAlertConfig
	err := d.db.Where("site_id = ?", siteID).First(&cfg).Error
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (d *Database) UpsertSiteAlertConfig(cfg *models.SiteAlertConfig) error {
	var existing models.SiteAlertConfig
	err := d.db.Where("site_id = ?", cfg.SiteID).First(&existing).Error
	if err == nil {
		cfg.ID = existing.ID
		return d.db.Save(cfg).Error
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	return d.db.Create(cfg).Error
}

func (d *Database) DeleteSiteAlertConfig(siteID uint) error {
	return d.db.Where("site_id = ?", siteID).Delete(&models.SiteAlertConfig{}).Error
}

func (d *Database) GetAllSiteAlertConfigs() ([]models.SiteAlertConfig, error) {
	var configs []models.SiteAlertConfig
	err := d.db.Find(&configs).Error
	return configs, err
}

// --- Maintenance Window CRUD ---

func (d *Database) GetMaintenanceWindows() ([]models.MaintenanceWindow, error) {
	var windows []models.MaintenanceWindow
	err := d.db.Order("start_time DESC").Find(&windows).Error
	return windows, err
}

func (d *Database) GetActiveMaintenanceWindows() ([]models.MaintenanceWindow, error) {
	var windows []models.MaintenanceWindow
	now := time.Now()
	err := d.db.Where("start_time <= ? AND end_time >= ?", now, now).Find(&windows).Error
	return windows, err
}

func (d *Database) CreateMaintenanceWindow(w *models.MaintenanceWindow) error {
	return d.db.Create(w).Error
}

func (d *Database) UpdateMaintenanceWindow(w *models.MaintenanceWindow) error {
	return d.db.Save(w).Error
}

func (d *Database) DeleteMaintenanceWindow(id uint) error {
	return d.db.Delete(&models.MaintenanceWindow{}, id).Error
}

// --- Enhanced Alert methods ---

func (d *Database) AcknowledgeAlertEnhanced(id uint, notes string) error {
	now := time.Now()
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"acknowledged":    true,
		"acknowledged_at": now,
		"notes":           notes,
	}).Error
}

func (d *Database) UpdateAlertNotes(id uint, notes string) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Update("notes", notes).Error
}

func (d *Database) GetUnacknowledgedAlerts(since time.Time) ([]models.Alert, error) {
	var alerts []models.Alert
	err := d.db.Where("acknowledged = ? AND suppressed = ? AND timestamp > ?", false, false, since).
		Find(&alerts).Error
	return alerts, err
}
