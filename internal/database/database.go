package database

import (
	"fmt"
	"os"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"

	"gorm.io/driver/sqlite"
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
		dbPath = "/data/fortigate.db"
	}

	dir := dbPath[:len(dbPath)-len("/fortigate.db")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

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
		&models.FortiGate{},
		&models.FortiGateTunnel{},
		&models.FortiGateConnection{},
		&models.SystemSetting{},
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

	d.db.Where("timestamp < ?", cutoff).Delete(&models.SystemStatus{})
	d.db.Where("timestamp < ?", cutoff).Delete(&models.InterfaceStats{})
	d.db.Where("timestamp < ?", cutoff).Delete(&models.TrapEvent{})
	d.db.Where("timestamp < ?", cutoff).Delete(&models.LoginAttempt{})
	d.db.Where("acknowledged = true AND timestamp < ?", cutoff).Delete(&models.Alert{})

	return nil
}

func (d *Database) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (d *Database) GetAllFortiGates() ([]models.FortiGate, error) {
	var fgs []models.FortiGate
	err := d.db.Find(&fgs).Error
	return fgs, err
}

func (d *Database) GetFortiGate(id uint) (*models.FortiGate, error) {
	var fg models.FortiGate
	err := d.db.First(&fg, id).Error
	if err != nil {
		return nil, err
	}
	return &fg, nil
}

func (d *Database) CreateFortiGate(fg *models.FortiGate) error {
	return d.db.Create(fg).Error
}

func (d *Database) UpdateFortiGate(fg *models.FortiGate) error {
	return d.db.Save(fg).Error
}

func (d *Database) DeleteFortiGate(id uint) error {
	d.db.Where("fortigate_id = ?", id).Delete(&models.FortiGateTunnel{})
	d.db.Where("source_fg_id = ? OR dest_fg_id = ?", id, id).Delete(&models.FortiGateConnection{})
	return d.db.Delete(&models.FortiGate{}, id).Error
}

func (d *Database) GetAllConnections() ([]models.FortiGateConnection, error) {
	var conns []models.FortiGateConnection
	err := d.db.Preload("SourceFG").Preload("DestFG").Find(&conns).Error
	return conns, err
}

func (d *Database) CreateConnection(conn *models.FortiGateConnection) error {
	return d.db.Create(conn).Error
}

func (d *Database) UpdateConnection(conn *models.FortiGateConnection) error {
	return d.db.Save(conn).Error
}

func (d *Database) DeleteConnection(id uint) error {
	return d.db.Delete(&models.FortiGateConnection{}, id).Error
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
