package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	db *gorm.DB
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

	d := &Database{db: db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// Backfill vendor for existing devices
	db.Exec("UPDATE devices SET vendor = 'fortigate' WHERE vendor = '' OR vendor IS NULL")

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
	}

	// Migrate each model individually so one failure doesn't block others.
	// SQLite's limited ALTER TABLE support can cause GORM to attempt
	// table recreation which may fail with "already exists" on upgrades.
	for _, model := range allModels {
		if err := d.db.AutoMigrate(model); err != nil {
			log.Printf("AutoMigrate warning for %T: %v", model, err)
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
	return devices, err
}

func (d *Database) GetDevice(id uint) (*models.Device, error) {
	var device models.Device
	err := d.db.Preload("Site").Preload("Probe").First(&device, id).Error
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func (d *Database) CreateDevice(device *models.Device) error {
	return d.db.Create(device).Error
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

// UpsertAutoConnection creates or updates an auto-detected VPN connection.
// Manual connections (AutoDetected=false) are never overwritten.
func (d *Database) UpsertAutoConnection(sourceID, destID uint, status, tunnelNames, name string) error {
	existing, err := d.FindConnectionByDevicePair(sourceID, destID)
	if err != nil {
		return err
	}

	if existing != nil {
		if !existing.AutoDetected {
			return nil // don't touch manual connections
		}
		// Update existing auto-detected connection
		return d.db.Model(existing).Updates(map[string]interface{}{
			"status":       status,
			"tunnel_names": tunnelNames,
			"last_check":   time.Now(),
		}).Error
	}

	// Create new auto-detected connection with normalized direction
	conn := &models.DeviceConnection{
		Name:           name,
		SourceDeviceID: sourceID,
		DestDeviceID:   destID,
		ConnectionType: "ipsec",
		Status:         status,
		AutoDetected:   true,
		TunnelNames:    tunnelNames,
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
		ID:       admin.ID,
		Username: admin.Username,
		Password: admin.Password,
	}, nil
}

func (d *Database) UpdateAdminPassword(id uint, password string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).Update("password", password).Error
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

// GetFlowStats returns aggregated flow statistics
func (d *Database) GetFlowStats(hours int) (*FlowStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &FlowStatsResult{}

	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).Count(&result.TotalFlows)

	var totalBytes struct{ Sum uint64 }
	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
		Select("COALESCE(SUM(bytes),0) as sum").Scan(&totalBytes)
	result.TotalBytes = totalBytes.Sum

	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
		Distinct("src_addr").Count(&result.UniqueSources)
	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
		Distinct("dst_addr").Count(&result.UniqueDests)

	// Protocol distribution
	var protocols []struct {
		Protocol uint8 `json:"protocol"`
		Count    int64 `json:"count"`
	}
	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
		Select("protocol, COUNT(*) as count").Group("protocol").
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
	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
		Select("src_addr, SUM(bytes) as total").Group("src_addr").
		Order("total DESC").Limit(10).Scan(&topSrc)
	for _, s := range topSrc {
		result.TopSources = append(result.TopSources, KeyCount{Key: s.SrcAddr, Count: s.Total})
	}

	// Bytes over time (hourly buckets)
	var timeSeries []struct {
		Bucket string `json:"bucket"`
		Total  int64  `json:"total"`
	}
	d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
		Select("strftime('%Y-%m-%d %H:00', timestamp) as bucket, SUM(bytes) as total").
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
