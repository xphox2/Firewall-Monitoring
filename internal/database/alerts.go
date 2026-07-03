package database

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// --- Alert Policy CRUD ---

func (d *Database) EnsureDefaultPolicy() {
	var policy models.AlertPolicy
	d.db.Where("is_default = ?", true).Attrs(models.AlertPolicy{
		Name:            "Default",
		Description:     "Default alert policy — all notifications use global settings",
		IsDefault:       true,
		CooldownMinutes: 5,
	}).FirstOrCreate(&policy)
}

func (d *Database) GetAlertPolicies() ([]models.AlertPolicy, error) {
	var policies []models.AlertPolicy
	err := d.db.Preload("Rules").Order("is_default DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (d *Database) GetAlertPolicy(id uint) (*models.AlertPolicy, error) {
	var policy models.AlertPolicy
	err := d.db.Preload("Rules").First(&policy, id).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (d *Database) GetDefaultAlertPolicy() (*models.AlertPolicy, error) {
	var policy models.AlertPolicy
	err := d.db.Preload("Rules").Where("is_default = ?", true).First(&policy).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (d *Database) CreateAlertPolicy(policy *models.AlertPolicy) error {
	return d.db.Create(policy).Error
}

func (d *Database) UpdateAlertPolicy(policy *models.AlertPolicy) error {
	return d.db.Save(policy).Error
}

func (d *Database) DeleteAlertPolicy(id uint) error {
	// Prevent deleting default policy
	var policy models.AlertPolicy
	if err := d.db.First(&policy, id).Error; err != nil {
		return fmt.Errorf("delete alert policy %d: load policy: %w", id, err)
	}
	if policy.IsDefault {
		return fmt.Errorf("cannot delete the default alert policy")
	}
	// Delete associated rules first
	d.db.Where("policy_id = ?", id).Delete(&models.AlertRule{})
	return d.db.Delete(&models.AlertPolicy{}, id).Error
}

func (d *Database) BatchUpsertAlertRules(policyID uint, rules []models.AlertRule) error {
	// Delete existing rules for this policy
	if err := d.db.Where("policy_id = ?", policyID).Delete(&models.AlertRule{}).Error; err != nil {
		return fmt.Errorf("batch upsert alert rules for policy %d: delete existing: %w", policyID, err)
	}
	// Insert new rules
	for i := range rules {
		rules[i].ID = 0
		rules[i].PolicyID = policyID
	}
	if len(rules) > 0 {
		return d.db.Create(&rules).Error
	}
	return nil
}

// --- Device Alert Config CRUD ---

func (d *Database) GetDeviceAlertConfig(deviceID uint) (*models.DeviceAlertConfig, error) {
	var cfg models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", deviceID).First(&cfg).Error
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (d *Database) UpsertDeviceAlertConfig(cfg *models.DeviceAlertConfig) error {
	var existing models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", cfg.DeviceID).First(&existing).Error
	if err == nil {
		cfg.ID = existing.ID
		return d.db.Save(cfg).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("upsert device alert config (device %d): lookup existing: %w", cfg.DeviceID, err)
	}
	return d.db.Create(cfg).Error
}

func (d *Database) DeleteDeviceAlertConfig(deviceID uint) error {
	return d.db.Where("device_id = ?", deviceID).Delete(&models.DeviceAlertConfig{}).Error
}

func (d *Database) GetAllDeviceAlertConfigs() ([]models.DeviceAlertConfig, error) {
	var configs []models.DeviceAlertConfig
	err := d.db.Find(&configs).Error
	return configs, err
}

// --- Site Alert Config CRUD ---

func (d *Database) GetSiteAlertConfig(siteID uint) (*models.SiteAlertConfig, error) {
	var cfg models.SiteAlertConfig
	err := d.db.Where("site_id = ?", siteID).First(&cfg).Error
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (d *Database) UpsertSiteAlertConfig(cfg *models.SiteAlertConfig) error {
	var existing models.SiteAlertConfig
	err := d.db.Where("site_id = ?", cfg.SiteID).First(&existing).Error
	if err == nil {
		cfg.ID = existing.ID
		return d.db.Save(cfg).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("upsert site alert config (site %d): lookup existing: %w", cfg.SiteID, err)
	}
	return d.db.Create(cfg).Error
}

func (d *Database) DeleteSiteAlertConfig(siteID uint) error {
	return d.db.Where("site_id = ?", siteID).Delete(&models.SiteAlertConfig{}).Error
}

func (d *Database) GetAllSiteAlertConfigs() ([]models.SiteAlertConfig, error) {
	var configs []models.SiteAlertConfig
	err := d.db.Find(&configs).Error
	return configs, err
}

// --- Maintenance Window CRUD ---

func (d *Database) GetMaintenanceWindows() ([]models.MaintenanceWindow, error) {
	var windows []models.MaintenanceWindow
	err := d.db.Order("start_time DESC").Find(&windows).Error
	return windows, err
}

func (d *Database) GetActiveMaintenanceWindows() ([]models.MaintenanceWindow, error) {
	var windows []models.MaintenanceWindow
	now := time.Now()
	err := d.db.Where("start_time <= ? AND end_time >= ?", now, now).Find(&windows).Error
	return windows, err
}

func (d *Database) CreateMaintenanceWindow(w *models.MaintenanceWindow) error {
	return d.db.Create(w).Error
}

func (d *Database) UpdateMaintenanceWindow(w *models.MaintenanceWindow) error {
	return d.db.Save(w).Error
}

func (d *Database) DeleteMaintenanceWindow(id uint) error {
	return d.db.Delete(&models.MaintenanceWindow{}, id).Error
}

// --- Enhanced Alert methods ---

func (d *Database) AcknowledgeAlertEnhanced(id uint, notes string) error {
	now := time.Now()
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"acknowledged":    true,
		"acknowledged_at": now,
		"notes":           notes,
	}).Error
}

// SnoozeAlert sets SnoozedUntil to the given timestamp (v0.10.218,
// bundle G2). The handler clamps `until` into a 1h..30d window before
// calling here. Audit fields SnoozedBy / SnoozedReason are recorded for
// post-mortem review.
func (d *Database) SnoozeAlert(id uint, until time.Time, by, reason string) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"snoozed_until":  until,
		"snoozed_by":     by,
		"snoozed_reason": reason,
	}).Error
}

// UnsnoozeAlert clears the snooze window (v0.10.218, bundle G2). Used
// when an operator changes their mind, or programmatically from the
// frontend when a snooze duration has obviously elapsed.
func (d *Database) UnsnoozeAlert(id uint) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"snoozed_until":  nil,
		"snoozed_by":     "",
		"snoozed_reason": "",
	}).Error
}

// AcknowledgeAlertsBulk flips acknowledged=true for all rows whose ID is in ids,
// in a single UPDATE statement. Returns the number of rows actually changed
// (already-acked rows are still in the IN list — the UPDATE just rewrites the
// flag, so RowsAffected reflects the WHERE match count, which may exceed the
// number of *transitions*).
//
// Caller is responsible for capping len(ids); a sensible upper bound (e.g. 500)
// is enforced by the handler so we don't send unbounded SQL parameter lists.
func (d *Database) AcknowledgeAlertsBulk(ids []uint, notes string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	now := time.Now()
	res := d.db.Model(&models.Alert{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"acknowledged":    true,
			"acknowledged_at": now,
			"notes":           notes,
		})
	return res.RowsAffected, res.Error
}

// AlertFilter narrows an alert query for bulk ack-by-filter. Empty / zero
// fields are not added to the WHERE clause. Mirrors the query parameters
// accepted by GetAlerts so the client can ack exactly the rows it sees.
type AlertFilter struct {
	DeviceID     uint   // 0 = any
	AlertType    string // "" = any
	Severity     string // "" = any
	Acknowledged *bool  // nil = any (typically the caller passes false to ack only unacked rows)
}

// AcknowledgeAlertsByFilter flips acknowledged=true for all rows matching the
// filter. Used by the admin UI's "Select all N matching" → "Acknowledge"
// flow when the result set is too large to ship as an ID list. Single
// UPDATE; bounded only by the filter, not by client-side IDs.
//
// Returns RowsAffected. Note that already-acked rows in the match set will
// have their notes rewritten by this call.
func (d *Database) AcknowledgeAlertsByFilter(f AlertFilter, notes string) (int64, error) {
	now := time.Now()
	q := d.db.Model(&models.Alert{})
	if f.DeviceID > 0 {
		q = q.Where("device_id = ?", f.DeviceID)
	}
	if f.AlertType != "" {
		q = q.Where("alert_type = ?", f.AlertType)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Acknowledged != nil {
		q = q.Where("acknowledged = ?", *f.Acknowledged)
	}
	res := q.Updates(map[string]interface{}{
		"acknowledged":    true,
		"acknowledged_at": now,
		"notes":           notes,
	})
	return res.RowsAffected, res.Error
}

// SnoozeAlertsBulk sets snoozed_until to `until` (with audit fields
// `by` and `reason`) for every alert whose ID is in `ids`, in a single
// UPDATE. AUDIT-143: the audit complained that bulk-ack had both an
// ID-list form and a filter form, but bulk-snooze only had a single-
// alert form. This brings bulk-snooze to parity.
//
// Caller is responsible for capping len(ids); the handler enforces
// the same 500-row limit that AcknowledgeAlertsBulk uses.
//
// `until` is the snooze-expiry timestamp; the handler clamps the
// `hours` value to [1, 720] before calling here.
func (d *Database) SnoozeAlertsBulk(ids []uint, until time.Time, by, reason string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res := d.db.Model(&models.Alert{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"snoozed_until":  until,
			"snoozed_by":     by,
			"snoozed_reason": reason,
		})
	return res.RowsAffected, res.Error
}

// SnoozeAlertsByFilter sets snoozed_until on every alert matching
// the filter. AUDIT-143: mirror of AcknowledgeAlertsByFilter for
// the snooze flow. Used by the admin UI's "Select all N matching"
// → "Snooze for 4h" flow.
//
// Same filter semantics as AcknowledgeAlertsByFilter (DeviceID,
// AlertType, Severity, Acknowledged). The Acknowledged filter
// is especially useful here — an operator who wants to snooze
// only the unacked alerts can pass `acknowledged=false` to skip
// already-handled rows.
//
// `until` is the snooze-expiry timestamp; the handler clamps
// the `hours` value to [1, 720] before calling here.
func (d *Database) SnoozeAlertsByFilter(f AlertFilter, until time.Time, by, reason string) (int64, error) {
	q := d.db.Model(&models.Alert{})
	if f.DeviceID > 0 {
		q = q.Where("device_id = ?", f.DeviceID)
	}
	if f.AlertType != "" {
		q = q.Where("alert_type = ?", f.AlertType)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Acknowledged != nil {
		q = q.Where("acknowledged = ?", *f.Acknowledged)
	}
	res := q.Updates(map[string]interface{}{
		"snoozed_until":  until,
		"snoozed_by":     by,
		"snoozed_reason": reason,
	})
	return res.RowsAffected, res.Error
}

func (d *Database) UpdateAlertNotes(id uint, notes string) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Update("notes", notes).Error
}

func (d *Database) GetUnacknowledgedAlerts(since time.Time) ([]models.Alert, error) {
	var alerts []models.Alert
	err := d.db.Where("acknowledged = ? AND suppressed = ? AND timestamp > ?", false, false, since).
		Find(&alerts).Error
	return alerts, err
}

// --- Operational response stats (v0.11 Tranche 2, F05/F06) -----------------

// NoiseRow is one row of the noisiest-alerts leaderboard: a (type, device)
// pair with its fire count over the window.
type NoiseRow struct {
	AlertType  string `json:"alert_type"`
	DeviceID   uint   `json:"device_id"`
	DeviceName string `json:"device_name"`
	Count      int64  `json:"count"`
	Suppressed int64  `json:"suppressed"`
}

// GetAlertResponseStats computes MTTA/MTTR over the trailing window (days).
// Durations are averaged in Go for dialect portability. Companion recovery
// rows are excluded everywhere; auto-resolved rows (notes "Auto-resolved: …")
// count toward MTTR (the condition's lifetime) but NOT MTTA — auto-ack would
// fake instant operator response.
func (d *Database) GetAlertResponseStats(days int) (mttaMinutes, mttrMinutes float64, ackedCount, resolvedCount int64, err error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	var rows []models.Alert
	if err = d.db.Select("timestamp, acknowledged_at, resolved_at, notes").
		Where("timestamp > ? AND metric_name <> ? AND (acknowledged_at IS NOT NULL OR resolved_at IS NOT NULL)", cutoff, "recovery").
		Limit(20000).Find(&rows).Error; err != nil {
		return 0, 0, 0, 0, err
	}
	var ackSum, resSum float64
	for i := range rows {
		auto := strings.HasPrefix(rows[i].Notes, "Auto-resolved:")
		if rows[i].AcknowledgedAt != nil && !auto {
			if dur := rows[i].AcknowledgedAt.Sub(rows[i].Timestamp); dur >= 0 {
				ackSum += dur.Minutes()
				ackedCount++
			}
		}
		if rows[i].ResolvedAt != nil {
			if dur := rows[i].ResolvedAt.Sub(rows[i].Timestamp); dur >= 0 {
				resSum += dur.Minutes()
				resolvedCount++
			}
		}
	}
	if ackedCount > 0 {
		mttaMinutes = ackSum / float64(ackedCount)
	}
	if resolvedCount > 0 {
		mttrMinutes = resSum / float64(resolvedCount)
	}
	return mttaMinutes, mttrMinutes, ackedCount, resolvedCount, nil
}

// GetNoisiestAlerts returns the top (alert_type, device) pairs by fire count
// over the trailing window — the F06 noise leaderboard.
func (d *Database) GetNoisiestAlerts(days, limit int) ([]NoiseRow, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	var out []NoiseRow
	err := d.db.Model(&models.Alert{}).
		Select("alerts.alert_type AS alert_type, alerts.device_id AS device_id, COALESCE(devices.name, '') AS device_name, COUNT(*) AS count, SUM(CASE WHEN alerts.suppressed THEN 1 ELSE 0 END) AS suppressed").
		Joins("LEFT JOIN devices ON devices.id = alerts.device_id").
		Where("alerts.timestamp > ? AND alerts.metric_name <> ?", cutoff, "recovery").
		Group("alerts.alert_type, alerts.device_id, devices.name").
		Order("count DESC").
		Limit(limit).
		Scan(&out).Error
	return out, err
}
