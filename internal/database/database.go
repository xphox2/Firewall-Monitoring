package database

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	db     *gorm.DB
	encKey []byte
}

func (d *Database) Gorm() *gorm.DB {
	return d.db
}

func NewDatabase(cfg *config.Config) (*Database, error) {
	dbPath := cfg.Database.FilePath
	if dbPath == "" {
		dbPath = "/data/firewall-mon.db"
	}

	dir := filepath.Dir(dbPath)
	if dir == "." {
		dir = "/data"
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	// SQLite only supports one writer at a time; MaxOpenConns=1 prevents "database is locked" errors
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	var encKey []byte
	if cfg.Server.JWTSecretKey != "" {
		encKey = deriveKey(cfg.Server.JWTSecretKey)
	}

	d := &Database{db: db, encKey: encKey}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

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
		&models.FlowSample{},
		&models.SiteDatabase{},
		&models.SecurityStats{},
		&models.SDWANHealth{},
		&models.LicenseInfo{},
		&models.InterfaceAddress{},
		&models.IRCServer{},
		&models.IRCChannel{},
		&models.IRCCommand{},
		&models.IRCMessageLog{},
	}

	// Migrate each model individually so one failure doesn't block others.
	// SQLite's limited ALTER TABLE support can cause GORM to attempt
	// table recreation which may fail with "already exists" on upgrades.
	for _, model := range allModels {
		if err := d.db.AutoMigrate(model); err != nil {
			log.Printf("AutoMigrate warning for %T: %v", model, err)
		}
	}

	// Add missing IRC columns - check existence first
	type columnCheck struct {
		Table  string
		Column string
		Type   string
	}
	columnsToAdd := []columnCheck{
		{"irc_servers", "nickserv_identify", "BOOLEAN DEFAULT 0"},
		{"irc_servers", "server_password", "VARCHAR(255)"},
		{"irc_servers", "sasl_enabled", "BOOLEAN DEFAULT 0"},
		{"irc_servers", "sasl_username", "VARCHAR(255)"},
		{"irc_servers", "sasl_password", "VARCHAR(255)"},
		{"irc_servers", "auto_reconnect", "BOOLEAN DEFAULT 1"},
		{"irc_servers", "reconnect_delay", "INTEGER DEFAULT 30"},
		{"irc_servers", "last_connected", "TIMESTAMP"},
		{"irc_servers", "last_error", "TEXT"},
		{"irc_channels", "chanserv_name", "VARCHAR(255)"},
		{"irc_channels", "chanserv_password", "VARCHAR(255)"},
		{"irc_channels", "chan_oper_pass", "VARCHAR(255)"},
		{"irc_channels", "auto_join", "BOOLEAN DEFAULT 1"},
		{"irc_channels", "send_alerts", "BOOLEAN DEFAULT 0"},
		{"irc_channels", "send_status", "BOOLEAN DEFAULT 0"},
	}
	for _, c := range columnsToAdd {
		var count int
		d.db.Raw("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", c.Table, c.Column).Scan(&count)
		if count == 0 {
			d.db.Exec("ALTER TABLE " + c.Table + " ADD COLUMN " + c.Column + " " + c.Type)
		}
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
	
	// Pre-fetch all peer tunnels by name
	peerTunnelsByName := make(map[string]models.VPNStatus) // name -> latest tunnel with subnets
	for peerID := range peerIDs {
		var peerVPNs []models.VPNStatus
		d.db.Where("device_id = ?", peerID).Order("timestamp DESC").Find(&peerVPNs)
		for _, pv := range peerVPNs {
			if pv.LocalSubnet != "" || pv.RemoteSubnet != "" {
				// Store if this has more data than we currently have
				existing, exists := peerTunnelsByName[pv.TunnelName]
				if !exists || (pv.LocalSubnet != "" && existing.LocalSubnet == "") || (pv.RemoteSubnet != "" && existing.RemoteSubnet == "") {
					peerTunnelsByName[pv.TunnelName] = pv
				}
			}
		}
	}
	
	// Now cross-fill using pre-fetched data
	for i := range statuses {
		if statuses[i].LocalSubnet == "" || statuses[i].RemoteSubnet == "" {
			peerTunnel, exists := peerTunnelsByName[statuses[i].TunnelName]
			if exists {
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
	return d.db.Create(trap).Error
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

func (d *Database) GetLatestUptime() (*models.UptimeRecord, error) {
	var record models.UptimeRecord
	err := d.db.Order("timestamp DESC").First(&record).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &record, err
}

func (d *Database) SaveLoginAttempt(attempt *models.LoginAttempt) error {
	return d.db.Create(attempt).Error
}

func (d *Database) GetLoginAttempts(since time.Time, limit int) ([]models.LoginAttempt, error) {
	var attempts []models.LoginAttempt
	err := d.db.Where("timestamp > ?", since).Order("timestamp DESC").Limit(limit).Find(&attempts).Error
	return attempts, err
}

func (d *Database) CleanupOldData(days int) error {
	cutoff := time.Now().AddDate(0, 0, -days)

	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.SystemStatus{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup system_status: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.InterfaceStats{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup interface_stats: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.ProcessorStats{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup processor_stats: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.HardwareSensor{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup hardware_sensors: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.TrapEvent{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup trap_event: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.LoginAttempt{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup login_attempt: %w", err)
	}
	if err := d.db.Where("acknowledged = true AND timestamp < ?", cutoff).Delete(&models.Alert{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup alert: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup syslog_message: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.FlowSample{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup flow_sample: %w", err)
	}
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.InterfaceAddress{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup interface_addresses: %w", err)
	}

	return nil
}

func (d *Database) Close() error {
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

// GetAllLatestVPNStatuses returns the latest VPN tunnel snapshot for every device.
func (d *Database) GetAllLatestVPNStatuses() ([]models.VPNStatus, error) {
	var statuses []models.VPNStatus
	// Subquery: max timestamp per device
	sub := d.db.Model(&models.VPNStatus{}).Select("device_id, MAX(timestamp) as max_ts").Group("device_id")
	err := d.db.Where("(device_id, timestamp) IN (?)", sub).Find(&statuses).Error
	if err != nil {
		// Fallback for SQLite which may not support row-value IN; use a join approach
		statuses = nil
		err = d.db.Raw(`
			SELECT v.* FROM vpn_status v
			INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM vpn_status GROUP BY device_id) latest
			ON v.device_id = latest.device_id AND v.timestamp = latest.max_ts
		`).Scan(&statuses).Error
	}
	return statuses, err
}

// FindConnectionByDevicePair finds a connection between two devices regardless of direction.
func (d *Database) FindConnectionByDevicePair(deviceA, deviceB uint) (*models.DeviceConnection, error) {
	var conn models.DeviceConnection
	err := d.db.Where(
		"(source_device_id = ? AND dest_device_id = ?) OR (source_device_id = ? AND dest_device_id = ?)",
		deviceA, deviceB, deviceB, deviceA,
	).First(&conn).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &conn, err
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

func (d *Database) GetAllProbeApprovals() ([]models.ProbeApproval, error) {
	var approvals []models.ProbeApproval
	err := d.db.Preload("Probe").Order("requested_at DESC").Find(&approvals).Error
	return approvals, err
}

func (d *Database) GetProbeApproval(probeID uint) (*models.ProbeApproval, error) {
	var approval models.ProbeApproval
	err := d.db.Where("probe_id = ?", probeID).First(&approval).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &approval, err
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
	return d.db.Create(result).Error
}

func (d *Database) GetPingResults(deviceID uint, limit int) ([]models.PingResult, error) {
	var results []models.PingResult
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(limit).Find(&results).Error
	return results, err
}

func (d *Database) GetLatestPingStats(deviceID uint, probeID uint) (*models.PingStats, error) {
	var stats models.PingStats
	err := d.db.Where("device_id = ? AND probe_id = ?", deviceID, probeID).First(&stats).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &stats, err
}

func (d *Database) SavePingStats(stats *models.PingStats) error {
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
		Order("`index` ASC").Find(&stats).Error
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
	return d.db.Create(msg).Error
}

func (d *Database) GetSyslogMessages(limit int) ([]models.SyslogMessage, error) {
	var messages []models.SyslogMessage
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&messages).Error
	return messages, err
}

func (d *Database) GetSyslogMessagesByDevice(deviceID uint, limit int) ([]models.SyslogMessage, error) {
	var messages []models.SyslogMessage
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(limit).Find(&messages).Error
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
		bucketExpr = "strftime('%Y-%m-%d %H:00', timestamp)"
	case "30d":
		hours = 720
		bucketExpr = "strftime('%Y-%m-%d %H:00', timestamp)"
	case "90d":
		hours = 2160
		bucketExpr = "strftime('%Y-%m-%d', timestamp)"
	default: // 24h
		hours = 24
		bucketExpr = "strftime('%Y-%m-%d %H:%M', timestamp)"
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	var rows []InterfaceChartBucket
	err := d.db.Model(&models.InterfaceStats{}).
		Where("device_id = ? AND `index` = ? AND timestamp > ?", deviceID, ifIndex, cutoff).
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

// FlowStatsResult holds aggregated flow statistics
type FlowStatsResult struct {
	TotalFlows    int64      `json:"total_flows"`
	TotalBytes    uint64     `json:"total_bytes"`
	UniqueSources int64      `json:"unique_sources"`
	UniqueDests   int64      `json:"unique_dests"`
	ByProtocol    []KeyCount `json:"by_protocol"`
	TopSources    []KeyCount `json:"top_sources"`
	BytesOverTime []TimeBucket `json:"bytes_over_time"`
}

// GetFlowStats returns aggregated flow statistics, optionally filtered by device.
func (d *Database) GetFlowStats(hours int, deviceID uint) (*FlowStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &FlowStatsResult{}

	newBase := func() *gorm.DB {
		q := d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff)
		if deviceID > 0 {
			q = q.Where("device_id = ?", deviceID)
		}
		return q
	}

	newBase().Count(&result.TotalFlows)

	var totalBytes struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(bytes),0) as sum").Scan(&totalBytes)
	result.TotalBytes = totalBytes.Sum

	newBase().Distinct("src_addr").Count(&result.UniqueSources)
	newBase().Distinct("dst_addr").Count(&result.UniqueDests)

	// Protocol distribution
	var protocols []struct {
		Protocol uint8 `json:"protocol"`
		Count    int64 `json:"count"`
	}
	newBase().Select("protocol, COUNT(*) as count").Group("protocol").
		Order("count DESC").Limit(10).Scan(&protocols)
	protoNames := map[uint8]string{0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 8: "EGP", 17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 137: "MPLS-in-IP"}
	for _, p := range protocols {
		name := protoNames[p.Protocol]
		if name == "" {
			name = fmt.Sprintf("Proto %d", p.Protocol)
		}
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: name, Count: p.Count})
	}

	// Top sources by bytes
	var topSrc []struct {
		SrcAddr string `json:"src_addr"`
		Total   int64  `json:"total"`
	}
	newBase().Select("src_addr, SUM(bytes) as total").Group("src_addr").
		Order("total DESC").Limit(10).Scan(&topSrc)
	for _, s := range topSrc {
		result.TopSources = append(result.TopSources, KeyCount{Key: s.SrcAddr, Count: s.Total})
	}

	// Bytes over time (hourly buckets)
	var timeSeries []struct {
		Bucket string `json:"bucket"`
		Total  int64  `json:"total"`
	}
	newBase().Select("strftime('%Y-%m-%d %H:00', timestamp) as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries)
	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
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
		Select("strftime('%Y-%m-%d %H:00', timestamp) as bucket, COUNT(*) as count").
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
	d.db.Model(model).Where("timestamp > ?", cutoff).
		Select(groupCol+" as key, COUNT(*) as count").Group(groupCol).Order("count DESC").Scan(&rows)
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

// GetSyslogStats returns aggregated syslog statistics
func (d *Database) GetSyslogStats(hours int) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff).Count(&result.Total)

	// Syslog severity is numeric, map to human-readable names
	sevNames := map[int]string{0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error", 4: "Warning", 5: "Notice", 6: "Info", 7: "Debug"}
	var bySev []struct {
		Severity int
		Count    int64
	}
	d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff).
		Select("severity, COUNT(*) as count").Group("severity").Order("count DESC").Scan(&bySev)
	for _, s := range bySev {
		name := sevNames[s.Severity]
		if name == "" {
			name = fmt.Sprintf("Severity %d", s.Severity)
		}
		result.BySeverity = append(result.BySeverity, KeyCount{Key: name, Count: s.Count})
	}

	result.OverTime = d.timeSeriesCount(&models.SyslogMessage{}, cutoff)

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

func (d *Database) CreateSiteDatabase(siteID uint, dbPath string, isRemote bool) (*models.SiteDatabase, error) {
	siteDB := &models.SiteDatabase{
		SiteID:       siteID,
		DatabasePath: dbPath,
		IsRemote:     isRemote,
		Status:       "active",
	}
	err := d.db.Create(siteDB).Error
	return siteDB, err
}

func (d *Database) GetSiteDatabase(siteID uint) (*models.SiteDatabase, error) {
	var siteDB models.SiteDatabase
	err := d.db.Where("site_id = ?", siteID).First(&siteDB).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &siteDB, err
}

func (d *Database) GetSiteDatabaseByID(id uint) (*models.SiteDatabase, error) {
	var siteDB models.SiteDatabase
	err := d.db.First(&siteDB, id).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &siteDB, err
}

func (d *Database) UpdateSiteDatabaseSync(siteID uint) error {
	now := time.Now()
	return d.db.Model(&models.SiteDatabase{}).Where("site_id = ?", siteID).Updates(map[string]interface{}{
		"last_sync": now,
		"status":    "active",
	}).Error
}

func (d *Database) SetSiteDatabaseStatus(siteID uint, status string) error {
	return d.db.Model(&models.SiteDatabase{}).Where("site_id = ?", siteID).Update("status", status).Error
}

func (d *Database) DeleteSiteDatabase(siteID uint) error {
	d.CloseSiteDB(siteID)
	siteDB, err := d.GetSiteDatabase(siteID)
	if err != nil {
		return err
	}
	if siteDB != nil && siteDB.DatabasePath != "" {
		if err := os.Remove(siteDB.DatabasePath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove site database file: %v", err)
		}
	}
	return d.db.Where("site_id = ?", siteID).Delete(&models.SiteDatabase{}).Error
}

func (d *Database) ListSiteDatabases() ([]models.SiteDatabase, error) {
	var siteDBs []models.SiteDatabase
	err := d.db.Preload("Site").Find(&siteDBs).Error
	return siteDBs, err
}

func (d *Database) CreateSiteDatabaseFile(siteID uint, basePath string) (*models.SiteDatabase, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	dbPath := filepath.Join(basePath, fmt.Sprintf("site_%d.db", siteID))

	exists, err := pathExists(dbPath)
	if err != nil {
		return nil, err
	}
	if exists {
		siteDB, err := d.GetSiteDatabase(siteID)
		if err != nil {
			return nil, err
		}
		if siteDB != nil {
			return siteDB, nil
		}
	}

	siteDB, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create site database: %w", err)
	}

	siteDB.Exec("PRAGMA journal_mode=WAL")
	siteDB.Exec("PRAGMA busy_timeout=5000")

	sqlDB, err := siteDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	if err := siteDB.AutoMigrate(
		&models.SiteDevice{},
		&models.SiteSystemStatus{},
		&models.SiteInterfaceStats{},
		&models.SiteTrapEvent{},
		&models.SiteAlert{},
		&models.SitePingResult{},
		&models.SitePingStats{},
		&models.SiteSyslogMessage{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate site database: %w", err)
	}

	sqlDB.Close()

	return d.CreateSiteDatabase(siteID, dbPath, false)
}

var (
	siteDBConnections = make(map[uint]*gorm.DB)
	siteDBMu          sync.RWMutex
)

func (d *Database) GetOrCreateSiteDB(siteID uint) (*gorm.DB, error) {
	siteDBMu.RLock()
	if db, ok := siteDBConnections[siteID]; ok {
		sqlDB, err := db.DB()
		if err == nil {
			if err := sqlDB.Ping(); err == nil {
				siteDBMu.RUnlock()
				return db, nil
			}
		}
	}
	siteDBMu.RUnlock()

	siteDB, err := d.GetSiteDatabase(siteID)
	if err != nil {
		return nil, err
	}
	if siteDB == nil {
		return nil, fmt.Errorf("site database not found for site %d", siteID)
	}

	db, err := gorm.Open(sqlite.Open(siteDB.DatabasePath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to site database: %w", err)
	}

	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")

	sqlDB, err := db.DB()
	if err != nil {
		// Close the gorm.DB we just opened to avoid leaking the connection
		if innerDB, innerErr := db.DB(); innerErr == nil {
			innerDB.Close()
		}
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	siteDBMu.Lock()
	// Clean up stale entry if it exists
	if old, ok := siteDBConnections[siteID]; ok {
		if oldSQL, err := old.DB(); err == nil {
			oldSQL.Close()
		}
	}
	siteDBConnections[siteID] = db
	siteDBMu.Unlock()

	return db, nil
}

func (d *Database) CloseSiteDB(siteID uint) {
	siteDBMu.Lock()
	defer siteDBMu.Unlock()
	if db, ok := siteDBConnections[siteID]; ok {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
		delete(siteDBConnections, siteID)
	}
}

func (d *Database) CloseAllSiteDBs() {
	siteDBMu.Lock()
	defer siteDBMu.Unlock()
	for siteID, db := range siteDBConnections {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
		delete(siteDBConnections, siteID)
	}
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (d *Database) SaveSiteDevice(siteID uint, device *models.SiteDevice) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(device).Error
}

func (d *Database) GetSiteDevices(siteID uint) ([]models.SiteDevice, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var devices []models.SiteDevice
	err = db.Find(&devices).Error
	return devices, err
}

func (d *Database) SaveSiteSystemStatus(siteID uint, status *models.SiteSystemStatus) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(status).Error
}

func (d *Database) GetSiteSystemStatus(siteID uint, limit int) ([]models.SiteSystemStatus, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var statuses []models.SiteSystemStatus
	err = db.Order("timestamp DESC").Limit(limit).Find(&statuses).Error
	return statuses, err
}

func (d *Database) SaveSiteInterfaceStats(siteID uint, stats []models.SiteInterfaceStats) error {
	if len(stats) == 0 {
		return nil
	}
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(&stats).Error
}

func (d *Database) GetSiteInterfaceStats(siteID uint, limit int) ([]models.SiteInterfaceStats, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var stats []models.SiteInterfaceStats
	err = db.Order("timestamp DESC").Limit(limit).Find(&stats).Error
	return stats, err
}

func (d *Database) SaveSiteTrapEvent(siteID uint, trap *models.SiteTrapEvent) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(trap).Error
}

func (d *Database) GetSiteTrapEvents(siteID uint, limit int) ([]models.SiteTrapEvent, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var traps []models.SiteTrapEvent
	err = db.Order("timestamp DESC").Limit(limit).Find(&traps).Error
	return traps, err
}

func (d *Database) SaveSiteAlert(siteID uint, alert *models.SiteAlert) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(alert).Error
}

func (d *Database) GetSiteAlerts(siteID uint, limit int) ([]models.SiteAlert, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var alerts []models.SiteAlert
	err = db.Order("timestamp DESC").Limit(limit).Find(&alerts).Error
	return alerts, err
}

func (d *Database) SaveSitePingResult(siteID uint, result *models.SitePingResult) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(result).Error
}

func (d *Database) GetSitePingResults(siteID uint, deviceID uint, limit int) ([]models.SitePingResult, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var results []models.SitePingResult
	err = db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(limit).Find(&results).Error
	return results, err
}

func (d *Database) SaveSitePingStats(siteID uint, stats *models.SitePingStats) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Save(stats).Error
}

func (d *Database) GetSitePingStats(siteID uint, deviceID uint, probeID uint) ([]models.SitePingStats, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var stats []models.SitePingStats
	err = db.Where("device_id = ? AND probe_id = ?", deviceID, probeID).Find(&stats).Error
	return stats, err
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
		bucketExpr = "strftime('%Y-%m-%d %H:%M', timestamp)"
	case "7d":
		hours = 168
		bucketExpr = "strftime('%Y-%m-%d %H:00', timestamp)"
	case "30d":
		hours = 720
		bucketExpr = "strftime('%Y-%m-%d %H:00', timestamp)"
	default: // 24h
		hours = 24
		bucketExpr = "strftime('%Y-%m-%d %H:%M', timestamp)"
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
		) WHERE delta_in IS NOT NULL
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
	SourceTunnel  string `json:"source_tunnel"`
	DestTunnel    string `json:"dest_tunnel"`
	SourcePhase1  string `json:"source_phase1"`
	DestPhase1    string `json:"dest_phase1"`
	LocalSubnet   string `json:"local_subnet"`
	RemoteSubnet  string `json:"remote_subnet"`
	SourceStatus  string `json:"source_status"`
	DestStatus    string `json:"dest_status"`
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
		bucketExpr = "strftime('%Y-%m-%d %H:%M', timestamp)"
	case "7d":
		hours = 168
		bucketExpr = "strftime('%Y-%m-%d %H:00', timestamp)"
	case "30d":
		hours = 720
		bucketExpr = "strftime('%Y-%m-%d %H:00', timestamp)"
	default:
		hours = 24
		bucketExpr = "strftime('%Y-%m-%d %H:%M', timestamp)"
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
		) WHERE delta_in IS NOT NULL
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
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "" // IPv6 not supported
	}
	ones, _ := ipNet.Mask.Size()
	network := ipNet.IP.To4()
	switch {
	case ones >= 24:
		return fmt.Sprintf("%d.%d.%d.%%", network[0], network[1], network[2])
	case ones >= 16:
		return fmt.Sprintf("%d.%d.%%", network[0], network[1])
	case ones >= 8:
		return fmt.Sprintf("%d.%%", network[0])
	default:
		return "" // too broad
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
	protoNames := map[uint8]string{0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 8: "EGP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 132: "SCTP"}

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
		d.db.Raw("SELECT DISTINCT device_id, `index` FROM interface_stats WHERE device_id IN ? AND (name IN ? OR description IN ? OR alias IN ?)",
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

	// Total counts
	newBase().Count(&result.TotalFlows)
	var totalBytes struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(bytes),0) as sum").Scan(&totalBytes)
	result.TotalBytes = totalBytes.Sum
	var totalPackets struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPackets)
	result.TotalPackets = totalPackets.Sum

	// Protocol distribution
	var protocols []struct {
		Protocol uint8 `json:"protocol"`
		Count    int64 `json:"count"`
	}
	newBase().Select("protocol, COUNT(*) as count").Group("protocol").Order("count DESC").Limit(10).Scan(&protocols)
	for _, p := range protocols {
		name := protoNames[p.Protocol]
		if name == "" {
			name = fmt.Sprintf("Proto %d", p.Protocol)
		}
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: name, Count: p.Count})
	}

	// Top sources by bytes
	var topSrc []struct {
		SrcAddr string `json:"src_addr"`
		Total   int64  `json:"total"`
	}
	newBase().Select("src_addr, SUM(bytes) as total").Group("src_addr").Order("total DESC").Limit(10).Scan(&topSrc)
	for _, s := range topSrc {
		result.TopSources = append(result.TopSources, KeyCount{Key: s.SrcAddr, Count: s.Total})
	}

	// Top destinations by bytes
	var topDst []struct {
		DstAddr string `json:"dst_addr"`
		Total   int64  `json:"total"`
	}
	newBase().Select("dst_addr, SUM(bytes) as total").Group("dst_addr").Order("total DESC").Limit(10).Scan(&topDst)
	for _, s := range topDst {
		result.TopDests = append(result.TopDests, KeyCount{Key: s.DstAddr, Count: s.Total})
	}

	// Top conversations
	var convos []struct {
		SrcAddr  string `json:"src_addr"`
		DstAddr  string `json:"dst_addr"`
		SrcPort  uint16 `json:"src_port"`
		DstPort  uint16 `json:"dst_port"`
		Protocol uint8  `json:"protocol"`
		Bytes    uint64 `json:"bytes"`
		Packets  uint64 `json:"packets"`
	}
	newBase().Select("src_addr, dst_addr, src_port, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, src_port, dst_port, protocol").Order("bytes DESC").Limit(10).Scan(&convos)
	for _, c := range convos {
		name := protoNames[c.Protocol]
		if name == "" {
			name = fmt.Sprintf("Proto %d", c.Protocol)
		}
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr: c.SrcAddr, DstAddr: c.DstAddr,
			SrcPort: c.SrcPort, DstPort: c.DstPort,
			Protocol: name, Bytes: c.Bytes, Packets: c.Packets,
		})
	}

	// Bytes over time
	var timeSeries []struct {
		Bucket string `json:"bucket"`
		Total  int64  `json:"total"`
	}
	newBase().Select("strftime('%Y-%m-%d %H:00', timestamp) as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries)
	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

func (d *Database) SaveSiteSyslogMessage(siteID uint, msg *models.SiteSyslogMessage) error {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return err
	}
	return db.Create(msg).Error
}

func (d *Database) GetSiteSyslogMessages(siteID uint, limit int) ([]models.SiteSyslogMessage, error) {
	db, err := d.GetOrCreateSiteDB(siteID)
	if err != nil {
		return nil, err
	}
	var messages []models.SiteSyslogMessage
	err = db.Order("timestamp DESC").Limit(limit).Find(&messages).Error
	return messages, err
}
