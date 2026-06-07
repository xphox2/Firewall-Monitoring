package database

import (
	"fmt"
	"time"

	"firewall-mon/internal/models"
)

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
