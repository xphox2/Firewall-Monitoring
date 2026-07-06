package database

import (
	"errors"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// SaveFlowDetection persists one detection-engine finding. Called by the poller
// after each detection cycle, before the alert engine runs — detections are
// stored regardless of whether they also fire an alert, so the NOC sees
// sub-threshold signal too.
func (d *Database) SaveFlowDetection(det *models.FlowDetection) error {
	return d.db.Create(det).Error
}

// GetRecentDetections returns flow_detections newer than `since`, newest first.
// When unackedOnly is true, acknowledged rows are excluded. When includeAlerted
// is false (the default for the NOC/sFlow "detections" card), detections that
// were escalated to an alert (alert_id set) are excluded — those live on the
// Alerts page under the "single feed" model. limit <= 0 means the default cap.
func (d *Database) GetRecentDetections(since time.Time, limit int, unackedOnly, includeAlerted bool) ([]models.FlowDetection, error) {
	if limit <= 0 {
		limit = 200
	}
	q := d.db.Where("detected_at >= ?", since.UTC())
	if unackedOnly {
		q = q.Where("acknowledged = ?", false)
	}
	if !includeAlerted {
		q = q.Where("alert_id IS NULL")
	}
	var rows []models.FlowDetection
	err := q.Order("detected_at DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

// LinkFlowDetectionsToAlert stamps every listed detection with the alert that now
// represents it, so they drop off the sFlow detections card (single feed) and so
// the alert-detail view can list the flows/detectors behind the alert. No-op on
// an empty list or zero alert.
func (d *Database) LinkFlowDetectionsToAlert(detectionIDs []uint, alertID uint) error {
	if len(detectionIDs) == 0 || alertID == 0 {
		return nil
	}
	return d.db.Model(&models.FlowDetection{}).
		Where("id IN ?", detectionIDs).
		Update("alert_id", alertID).Error
}

// FindOpenAlertForSource returns the most-recent still-open, unacknowledged alert
// that a recent flow detection for srcAddr was linked to, or nil. This is how the
// consolidation engine locates an sFlow security event's existing alert across
// overlapping detection cycles: it keys on the detection→alert link, which is
// src-discriminating (won't cross-link two sources behind one device) and
// detector-agnostic (survives a change in which detector "wins" the event).
func (d *Database) FindOpenAlertForSource(srcAddr string, since time.Time) (*models.Alert, error) {
	var det models.FlowDetection
	err := d.db.
		Where("src_addr = ? AND alert_id IS NOT NULL AND detected_at >= ?", srcAddr, since.UTC()).
		Order("detected_at DESC").First(&det).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if det.AlertID == nil {
		return nil, nil
	}
	var a models.Alert
	err = d.db.Where("id = ? AND resolved_at IS NULL AND acknowledged = ?", *det.AlertID, false).First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetDetectionsByAlert returns the flow detections linked to an alert (the flows
// and detectors behind it), newest first, for the alert-detail view.
func (d *Database) GetDetectionsByAlert(alertID uint) ([]models.FlowDetection, error) {
	var rows []models.FlowDetection
	err := d.db.Where("alert_id = ?", alertID).Order("detected_at DESC").Limit(200).Find(&rows).Error
	return rows, err
}

// AckFlowDetection marks a detection acknowledged (admin dismissed it from the
// active list). Idempotent: acking an already-acked row is a no-op update.
func (d *Database) AckFlowDetection(id uint) error {
	return d.db.Model(&models.FlowDetection{}).
		Where("id = ?", id).
		Update("acknowledged", true).Error
}

// AckFlowDetections bulk-acknowledges detections (v0.11.46). Used by the poller
// to clear a silenced source's detections from the NOC card so a suppressed
// attacker doesn't flood the 200-row list, and by the suppress-source API. No-op
// on an empty list.
func (d *Database) AckFlowDetections(ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	return d.db.Model(&models.FlowDetection{}).
		Where("id IN ?", ids).
		Update("acknowledged", true).Error
}

// FindOpenDigestAlert returns the still-open, unacknowledged SFLOW_SECURITY_DIGEST
// alert for a per-(site,detector) metric name, or nil (v0.11.46). Unlike
// FindOpenAlertForSource it keys directly on the persisted alert_type+metric_name
// (the digest's cross-cycle identity) rather than a source link, since a digest
// spans many sources. `since` bounds it to the current window (max(lookback,
// cooldown)).
func (d *Database) FindOpenDigestAlert(metricName string, since time.Time) (*models.Alert, error) {
	var a models.Alert
	err := d.db.
		Where("alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND acknowledged = ? AND timestamp >= ?",
			models.AlertTypeSFlowSecurityDigest, metricName, false, since.UTC()).
		Order("timestamp DESC").First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
