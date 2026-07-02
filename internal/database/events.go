package database

import (
	"fmt"
	"time"

	"firewall-mon/internal/models"
)

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
	return batchInsertWithFallback(d.db, "trap_events", traps)
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

// SaveAuditLog appends one admin-action record (AUDIT-078). Append-only — there
// is intentionally no Update/Delete counterpart.
func (d *Database) SaveAuditLog(entry *models.AuditLog) error {
	if err := d.db.Create(entry).Error; err != nil {
		return fmt.Errorf("save audit log: %w", err)
	}
	return nil
}

// GetAuditLogs returns admin-action records newest-first with optional filters
// (actor, action route-template, and a since cutoff) plus pagination. Returns
// the page and the unpaginated total so the caller can render counts.
func (d *Database) GetAuditLogs(actor, action string, since time.Time, limit, offset int) ([]models.AuditLog, int64, error) {
	q := d.db.Model(&models.AuditLog{})
	if actor != "" {
		q = q.Where("actor = ?", actor)
	}
	if action != "" {
		q = q.Where("action = ?", action)
	}
	if !since.IsZero() {
		q = q.Where("created_at >= ?", since)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	var logs []models.AuditLog
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	return logs, total, nil
}

func (d *Database) SaveProcessStats(stats *models.ProcessStats) error {
	return d.db.Create(stats).Error
}

func (d *Database) SaveInterfaceErrors(errs []models.InterfaceErrors) error {
	return batchInsertWithFallback(d.db, "interface_errors", errs)
}
