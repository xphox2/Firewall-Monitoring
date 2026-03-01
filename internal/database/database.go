package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	return d, nil
}

func (d *Database) migrate() error {
	return d.db.AutoMigrate(
		&models.SystemStatus{},
		&models.InterfaceStats{},
		&models.VPNStatus{},
		&models.HAStatus{},
		&models.HardwareSensor{},
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
	)
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

func (d *Database) DeleteDevice(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// Delete all related monitoring data
		for _, model := range []interface{}{
			&models.SystemStatus{},
			&models.InterfaceStats{},
			&models.VPNStatus{},
			&models.HAStatus{},
			&models.HardwareSensor{},
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

var siteDBConnections = make(map[uint]*gorm.DB)

func (d *Database) GetOrCreateSiteDB(siteID uint) (*gorm.DB, error) {
	if db, ok := siteDBConnections[siteID]; ok {
		sqlDB, err := db.DB()
		if err == nil {
			if err := sqlDB.Ping(); err == nil {
				return db, nil
			}
		}
		delete(siteDBConnections, siteID)
	}

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
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	siteDBConnections[siteID] = db

	return db, nil
}

func (d *Database) CloseSiteDB(siteID uint) {
	if db, ok := siteDBConnections[siteID]; ok {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
		delete(siteDBConnections, siteID)
	}
}

func (d *Database) CloseAllSiteDBs() {
	for siteID := range siteDBConnections {
		d.CloseSiteDB(siteID)
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
