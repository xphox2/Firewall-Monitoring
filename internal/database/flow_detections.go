package database

import (
	"time"

	"firewall-mon/internal/models"
)

// SaveFlowDetection persists one detection-engine finding. Called by the poller
// after each detection cycle, before the alert engine runs — detections are
// stored regardless of whether they also fire an alert, so the NOC sees
// sub-threshold signal too.
func (d *Database) SaveFlowDetection(det *models.FlowDetection) error {
	return d.db.Create(det).Error
}

// GetRecentDetections returns flow_detections newer than `since`, newest first.
// When unackedOnly is true, acknowledged rows are excluded. limit <= 0 means the
// default cap of 200.
func (d *Database) GetRecentDetections(since time.Time, limit int, unackedOnly bool) ([]models.FlowDetection, error) {
	if limit <= 0 {
		limit = 200
	}
	q := d.db.Where("detected_at >= ?", since.UTC())
	if unackedOnly {
		q = q.Where("acknowledged = ?", false)
	}
	var rows []models.FlowDetection
	err := q.Order("detected_at DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

// AckFlowDetection marks a detection acknowledged (admin dismissed it from the
// active list). Idempotent: acking an already-acked row is a no-op update.
func (d *Database) AckFlowDetection(id uint) error {
	return d.db.Model(&models.FlowDetection{}).
		Where("id = ?", id).
		Update("acknowledged", true).Error
}
