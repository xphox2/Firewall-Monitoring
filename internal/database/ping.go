package database

import (
	"errors"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

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
	if errors.Is(err, gorm.ErrRecordNotFound) {
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
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
