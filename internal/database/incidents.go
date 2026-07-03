package database

import (
	"errors"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Incident persistence (F12). One open incident per device at most: the
// correlator opens it when DEVICE_OFFLINE fires and resolves it when the
// device recovers.

// OpenIncidentForDevice returns the device's open incident, or nil.
func (d *Database) OpenIncidentForDevice(deviceID uint) (*models.Incident, error) {
	var inc models.Incident
	err := d.db.Where("device_id = ? AND resolved_at IS NULL", deviceID).
		Order("id DESC").First(&inc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &inc, nil
}

// CreateIncident opens an incident (idempotent per device: reuses an open one).
func (d *Database) CreateIncident(inc *models.Incident) error {
	existing, err := d.OpenIncidentForDevice(inc.DeviceID)
	if err != nil {
		return err
	}
	if existing != nil {
		*inc = *existing
		return nil
	}
	return d.db.Create(inc).Error
}

// GetOpenIncidents lists every unresolved incident (the poller caches this
// per cycle for fire-path attachment).
func (d *Database) GetOpenIncidents() ([]models.Incident, error) {
	var incs []models.Incident
	err := d.db.Where("resolved_at IS NULL").Find(&incs).Error
	return incs, err
}

// ResolveIncident closes the device's open incident, stamping the final alert
// count. Returns the closed incident (nil when none was open).
func (d *Database) ResolveIncident(deviceID uint) (*models.Incident, error) {
	inc, err := d.OpenIncidentForDevice(deviceID)
	if err != nil || inc == nil {
		return nil, err
	}
	var n int64
	if err := d.db.Model(&models.Alert{}).Where("incident_id = ?", inc.ID).Count(&n).Error; err != nil {
		return nil, err
	}
	now := time.Now()
	inc.ResolvedAt = &now
	inc.AlertCount = int(n)
	if err := d.db.Model(&models.Incident{}).Where("id = ?", inc.ID).
		Updates(map[string]interface{}{"resolved_at": now, "alert_count": n}).Error; err != nil {
		return nil, err
	}
	return inc, nil
}

// ListIncidents returns newest-first incidents with pagination.
func (d *Database) ListIncidents(limit, offset int) ([]models.Incident, int64, error) {
	var total int64
	if err := d.db.Model(&models.Incident{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var incs []models.Incident
	err := d.db.Order("id DESC").Limit(limit).Offset(offset).Find(&incs).Error
	return incs, total, err
}

// GetIncidentAlerts returns the alerts attached to an incident, newest first.
func (d *Database) GetIncidentAlerts(incidentID uint) ([]models.Alert, error) {
	var alerts []models.Alert
	err := d.db.Where("incident_id = ?", incidentID).Order("id DESC").Limit(500).Find(&alerts).Error
	return alerts, err
}
