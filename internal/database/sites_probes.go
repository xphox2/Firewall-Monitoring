package database

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

func (d *Database) GetAllSettings() ([]models.SystemSetting, error) {
	var settings []models.SystemSetting
	err := d.db.Find(&settings).Error
	return settings, err
}

// GetSettingValue returns the raw string value of one system_settings key, or
// ("", false) if the key is absent. The building block for the typed read-through
// helpers below (v0.11.46 — admin-UI-managed settings; see the "no new env vars"
// configuration principle).
func (d *Database) GetSettingValue(key string) (string, bool) {
	var s models.SystemSetting
	if err := d.db.Where("\"key\" = ?", key).First(&s).Error; err != nil {
		return "", false
	}
	return s.Value, true
}

// GetBoolSetting reads a boolean setting, returning def when the key is absent or
// unparseable. "true"/"1"/"yes"/"on" (case-insensitive) are true; the mirror set
// is false. Used for the threat-feed master switch, where def follows the env
// config until an operator flips it in the UI.
func (d *Database) GetBoolSetting(key string, def bool) bool {
	v, ok := d.GetSettingValue(key)
	if !ok || v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}

// GetIntSetting reads an integer setting, returning def when the key is absent or
// unparseable. Used for the cross-source storm threshold
// (detect_security_storm_sources, default 25).
func (d *Database) GetIntSetting(key string, def int) int {
	v, ok := d.GetSettingValue(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// UpsertSetting persists a system_settings row, creating it if absent.
//
// v0.10.233: was the exact v0.10.226 bug verbatim — FirstOrCreate then
// copied only Value/Label/Category onto the existing struct before Save,
// dropping IsSecret and Type on update. Currently has zero in-tree callers,
// but the function is exported on the public *Database API and would
// silently corrupt any secret persisted through it. Fixed to mirror the
// canonical pattern used in UpdateSettings (handlers_settings.go:228-241):
// copy every field that matters, including IsSecret.
func (d *Database) UpsertSetting(setting *models.SystemSetting) error {
	existing := models.SystemSetting{Key: setting.Key}
	if err := d.db.FirstOrCreate(&existing, models.SystemSetting{Key: setting.Key}).Error; err != nil {
		return fmt.Errorf("upsert setting %q: %w", setting.Key, err)
	}
	existing.Value = setting.Value
	existing.Label = setting.Label
	existing.Category = setting.Category
	existing.Type = setting.Type
	existing.IsSecret = setting.IsSecret
	return d.db.Save(&existing).Error
}

func (d *Database) GetAdmin() (*models.Admin, error) {
	var admin models.Admin
	err := d.db.First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
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

func (d *Database) InitAdmin(username, password string, mustChangePassword bool) error {
	admin, err := d.GetAdmin()
	if err != nil {
		return fmt.Errorf("init admin: load existing admin: %w", err)
	}
	if admin == nil {
		return d.CreateAdmin(&models.Admin{
			Username:           username,
			Password:           password,
			MustChangePassword: mustChangePassword,
			Role:               auth.RoleAdmin,
		})
	}
	log.Printf("Admin user already exists, skipping initialization")
	return nil
}

// SetAdminMustChangePassword sets or clears the forced-password-change flag.
func (d *Database) SetAdminMustChangePassword(id uint, must bool) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).Update("must_change_password", must).Error
}

// GetAdminMustChangePassword reports whether the given admin must change its
// password before using the admin API.
func (d *Database) GetAdminMustChangePassword(id uint) (bool, error) {
	var admin models.Admin
	if err := d.db.Select("must_change_password").Where("id = ?", id).First(&admin).Error; err != nil {
		return false, err
	}
	return admin.MustChangePassword, nil
}

func (d *Database) GetAdminByUsername(username string) (*auth.AdminAuth, error) {
	var admin models.Admin
	err := d.db.Where("username = ?", username).First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &auth.AdminAuth{
		ID:                 admin.ID,
		Username:           admin.Username,
		Password:           admin.Password,
		TokenVersion:       admin.TokenVersion,
		MustChangePassword: admin.MustChangePassword,
		Role:               admin.Role,
		Disabled:           admin.Disabled,
		TOTPEnabled:        admin.TOTPEnabled,
		// Decrypted like device secrets; fail-closed "" if the key is gone —
		// an empty secret validates no code (P0-3).
		TOTPSecret: d.DecryptField(admin.TOTPSecret),
	}, nil
}

func (d *Database) UpdateAdminPassword(id uint, password string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).Update("password", password).Error
}

func (d *Database) GetAdminTokenVersion(id uint) (uint, error) {
	var admin models.Admin
	err := d.db.Select("token_version").First(&admin, id).Error
	if err != nil {
		return 0, err
	}
	return admin.TokenVersion, nil
}

func (d *Database) IncrementAdminTokenVersion(id uint) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
}

// --- UserStore (RBAC, P0-1) ------------------------------------------------

func (d *Database) ListAdmins() ([]models.Admin, error) {
	var admins []models.Admin
	err := d.db.Order("username").Find(&admins).Error
	return admins, err
}

func (d *Database) GetAdminByID(id uint) (*models.Admin, error) {
	var admin models.Admin
	err := d.db.First(&admin, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &admin, nil
}

// UpdateAdminRole sets the role and bumps the token version in one shot so a
// live session carrying the old role dies on its next request (the JWT
// version check fails closed). Callers validate the role string.
func (d *Database) UpdateAdminRole(id uint, role string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).
		UpdateColumns(map[string]interface{}{
			"role":          role,
			"token_version": gorm.Expr("token_version + 1"),
		}).Error
}

// SetAdminDisabled flips the disabled flag; disabling also bumps the token
// version to kill live sessions immediately (re-enable doesn't need a bump,
// but one more is harmless and keeps the UPDATE shape uniform). Disabling
// additionally revokes the account's API tokens in the same transaction
// (LC-15) so both credential types die together; re-enabling does NOT
// resurrect them — token revocation is final by design.
func (d *Database) SetAdminDisabled(id uint, disabled bool) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.Admin{}).Where("id = ?", id).
			UpdateColumns(map[string]interface{}{
				"disabled":      disabled,
				"token_version": gorm.Expr("token_version + 1"),
			}).Error; err != nil {
			return err
		}
		if disabled {
			return revokeAPITokensForAdmin(tx, id)
		}
		return nil
	})
}

// UpdateAdminProfile writes exactly the self-service profile columns (v28).
// A column-targeted UPDATE, never Save — a full-struct write here would
// clobber password/role/TOTP state from a stale in-memory row.
func (d *Database) UpdateAdminProfile(id uint, email, fullName string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).
		UpdateColumns(map[string]interface{}{
			"email":     email,
			"full_name": fullName,
		}).Error
}

// GetAdminDashboardPrefs returns the account's saved system-health dashboard
// layout JSON ("" when never customized).
func (d *Database) GetAdminDashboardPrefs(id uint) (string, error) {
	var prefs string
	err := d.db.Model(&models.Admin{}).Where("id = ?", id).
		Select("dashboard_prefs").Scan(&prefs).Error
	return prefs, err
}

// SetAdminDashboardPrefs persists the account's system-health dashboard layout
// JSON (self-service; writes only this one column).
func (d *Database) SetAdminDashboardPrefs(id uint, prefs string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).
		UpdateColumn("dashboard_prefs", prefs).Error
}

// SetAdminMFAPromptDismissed records the user's explicit decline of the MFA
// onboarding wizard. The WHERE guard keeps the FIRST decline timestamp — the
// audit-relevant moment the risk was accepted — across repeat calls.
func (d *Database) SetAdminMFAPromptDismissed(id uint) error {
	now := time.Now()
	return d.db.Model(&models.Admin{}).
		Where("id = ? AND mfa_prompt_dismissed_at IS NULL", id).
		UpdateColumn("mfa_prompt_dismissed_at", &now).Error
}

// DeleteAdmin removes the account and revokes its API tokens in the same
// transaction (LC-15). The token rows are kept (soft revoke) for the audit
// trail; the auth middleware also rejects any token whose creator row is
// gone, so the revoke is belt-and-braces.
func (d *Database) DeleteAdmin(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := revokeAPITokensForAdmin(tx, id); err != nil {
			return err
		}
		return tx.Delete(&models.Admin{}, id).Error
	})
}

func (d *Database) CountOtherEnabledAdmins(excludeID uint) (int64, error) {
	var n int64
	err := d.db.Model(&models.Admin{}).
		Where("role = ? AND disabled = ? AND id <> ?", "admin", false, excludeID).
		Count(&n).Error
	return n, err
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
	if errors.Is(err, gorm.ErrRecordNotFound) {
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
			return fmt.Errorf("delete site %d: delete probes: %w", id, err)
		}
		if err := tx.Where("site_id = ?", id).Delete(&models.Device{}).Error; err != nil {
			return fmt.Errorf("delete site %d: delete devices: %w", id, err)
		}
		return tx.Delete(&models.Site{}, id).Error
	})
}

func (d *Database) GetAllProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Preload("Site").Find(&probes).Error
	return probes, err
}

// MarkStaleProbesOffline flips probes still marked "online" to "offline" when
// their last heartbeat (last_seen) predates staleThreshold. Mirrors
// MarkStaleProbeDevicesOffline for devices: without this, a probe whose
// collector stopped checking in (crashed, restarted into a bad state, network
// cut) stayed "online" forever because probe status was stored and never
// re-derived. Returns the transitioned probes so the caller can log/alert.
func (d *Database) MarkStaleProbesOffline(staleThreshold time.Time) ([]models.Probe, error) {
	var stale []models.Probe
	if err := d.db.
		Where("status = ? AND last_seen < ?", "online", staleThreshold).
		Find(&stale).Error; err != nil {
		return nil, err
	}
	if len(stale) == 0 {
		return nil, nil
	}
	ids := make([]uint, len(stale))
	for i := range stale {
		ids[i] = stale[i].ID
		stale[i].Status = "offline"
	}
	if err := d.db.Model(&models.Probe{}).Where("id IN ?", ids).Update("status", "offline").Error; err != nil {
		return nil, err
	}
	return stale, nil
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
	if errors.Is(err, gorm.ErrRecordNotFound) {
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

// ErrProbeHasDevices is returned by DeleteProbe when the probe still has
// devices assigned to it. Deleting it anyway would violate the
// devices.probe_id foreign key (and silently orphan monitored devices), so the
// caller must reassign or remove those devices first.
var ErrProbeHasDevices = errors.New("probe has assigned devices")

// DeleteProbe removes a probe along with the rows that hold a foreign key back
// to it (probe_approvals, probe_heartbeats) and its registration SystemSetting.
//
// The pre-fix version was a bare `DELETE FROM probes`, which Postgres rejects
// with a foreign-key violation whenever ANY dependent row exists — and a probe
// that was ever approved always has a probe_approvals row and probe_heartbeats
// rows. The result was that an in-use probe could never be deleted ("Failed to
// delete probe"). Devices are deliberately NOT deleted here: they may be in the
// middle of being reassigned, so we refuse the delete with ErrProbeHasDevices
// and let the operator move them first.
func (d *Database) DeleteProbe(id uint) error {
	var deviceCount int64
	if err := d.db.Model(&models.Device{}).Where("probe_id = ?", id).Count(&deviceCount).Error; err != nil {
		return fmt.Errorf("delete probe %d: count assigned devices: %w", id, err)
	}
	if deviceCount > 0 {
		return fmt.Errorf("%w: %d device(s) still assigned", ErrProbeHasDevices, deviceCount)
	}

	return d.db.Transaction(func(tx *gorm.DB) error {
		// Remove the registration-key SystemSetting (keyed by the hashed key) so
		// a deleted probe's row doesn't leak and the key can't be reused.
		var probe models.Probe
		if err := tx.First(&probe, id).Error; err != nil {
			return fmt.Errorf("delete probe %d: load probe: %w", id, err)
		}
		if probe.RegistrationKey != "" {
			if err := tx.Where("key = ?", "probe_registration_"+probe.RegistrationKey).
				Delete(&models.SystemSetting{}).Error; err != nil {
				return fmt.Errorf("delete probe %d: delete registration setting: %w", id, err)
			}
		}
		// FK-referencing child rows must go before the probe row itself.
		for _, model := range []interface{}{
			&models.ProbeApproval{},
			&models.ProbeHeartbeat{},
		} {
			if err := tx.Where("probe_id = ?", id).Delete(model).Error; err != nil {
				return fmt.Errorf("delete probe %d: delete related %T: %w", id, model, err)
			}
		}
		return tx.Delete(&models.Probe{}, id).Error
	})
}

// DecommissionProbe retires a probe (decommissioned/replaced) WITHOUT deleting
// its row or any telemetry, so historical running totals still include it. Like
// DeleteProbe it refuses while devices are still assigned (ErrProbeHasDevices):
// the operator must first reassign those devices to the replacement probe. Use
// this — not DeleteProbe — for an in-service probe, so no data is ever lost.
func (d *Database) DecommissionProbe(id uint) error {
	var deviceCount int64
	if err := d.db.Model(&models.Device{}).Where("probe_id = ?", id).Count(&deviceCount).Error; err != nil {
		return fmt.Errorf("decommission probe %d: count assigned devices: %w", id, err)
	}
	if deviceCount > 0 {
		return fmt.Errorf("%w: %d device(s) still assigned", ErrProbeHasDevices, deviceCount)
	}
	now := time.Now().UTC()
	return d.db.Model(&models.Probe{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"decommissioned_at": now,
			"enabled":           false,
			"status":            "offline",
		}).Error
}

// RecommissionProbe reverses DecommissionProbe (clears decommissioned_at and
// re-enables the probe). The probe must still re-register/heartbeat to come
// back online.
func (d *Database) RecommissionProbe(id uint) error {
	return d.db.Model(&models.Probe{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"decommissioned_at": nil,
			"enabled":           true,
		}).Error
}

// TelemetryTotals is the orphan-safe, probe-independent running total of
// ingested telemetry rows. Counts are over ALL rows regardless of whether the
// probe that collected them still exists, so the dashboard "Data Totals" never
// drop when a probe is decommissioned or deleted.
type TelemetryTotals struct {
	Syslog       int64 `json:"syslog"`
	Traps        int64 `json:"traps"`
	Flows        int64 `json:"flows"`
	Pings        int64 `json:"pings"`
	SyslogLastHr int64 `json:"syslog_last_hour"`
	TrapsLastHr  int64 `json:"traps_last_hour"`
	FlowsLastHr  int64 `json:"flows_last_hour"`
	PingsLastHr  int64 `json:"pings_last_hour"`
}

// GetTelemetryTotals returns all-time and last-hour counts across every probe's
// telemetry with NO probe filter (see TelemetryTotals).
func (d *Database) GetTelemetryTotals() (*TelemetryTotals, error) {
	hourAgo := time.Now().UTC().Add(-1 * time.Hour)
	t := &TelemetryTotals{}
	type spec struct {
		model    interface{}
		total    *int64
		lastHour *int64
	}
	for _, s := range []spec{
		{&models.SyslogMessage{}, &t.Syslog, &t.SyslogLastHr},
		{&models.TrapEvent{}, &t.Traps, &t.TrapsLastHr},
		{&models.FlowSample{}, &t.Flows, &t.FlowsLastHr},
		{&models.PingResult{}, &t.Pings, &t.PingsLastHr},
	} {
		if err := d.db.Model(s.model).Count(s.total).Error; err != nil {
			return nil, fmt.Errorf("telemetry totals: count %T: %w", s.model, err)
		}
		if err := d.db.Model(s.model).Where("timestamp > ?", hourAgo).Count(s.lastHour).Error; err != nil {
			return nil, fmt.Errorf("telemetry totals: last-hour count %T: %w", s.model, err)
		}
	}
	return t, nil
}

func (d *Database) GetProbesBySite(siteID uint) ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("site_id = ?", siteID).Find(&probes).Error
	return probes, err
}

func (d *Database) GetProbeByRegistrationKey(key string) (*models.Probe, error) {
	var probe models.Probe
	// AUDIT-017: keys are stored hashed; hash the supplied plaintext to match.
	err := d.db.Where("registration_key = ?", HashProbeKey(key)).First(&probe).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
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
		return fmt.Errorf("approve probe %d: update probe row: %w", probeID, err)
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
		return fmt.Errorf("reject probe %d: update probe row: %w", probeID, err)
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

func (d *Database) GetApprovedProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("approval_status = ?", "approved").Find(&probes).Error
	return probes, err
}

func (d *Database) UpdateProbeHeartbeat(heartbeat *models.ProbeHeartbeat) error {
	var existing models.ProbeHeartbeat
	err := d.db.Where("probe_id = ?", heartbeat.ProbeID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
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

func (d *Database) GetDevicesByProbe(probeID uint) ([]models.Device, error) {
	var devices []models.Device
	err := d.db.Where("probe_id = ?", probeID).Preload("Site").Find(&devices).Error
	for i := range devices {
		d.DecryptDeviceSecrets(&devices[i])
	}
	return devices, err
}

// GetDeviceIDsByProbe returns just the IDs of the devices assigned to a probe.
// It is the hot-path counterpart to GetDevicesByProbe for the ingestion
// allow-list check (probeDeviceIDs), which only needs the ID set: it skips the
// `Preload("Site")` JOIN and the per-device AES-GCM secret decryption that
// GetDevicesByProbe performs on every call (~18 ingestion handlers invoke it).
func (d *Database) GetDeviceIDsByProbe(probeID uint) ([]uint, error) {
	var ids []uint
	err := d.db.Model(&models.Device{}).Where("probe_id = ?", probeID).Pluck("id", &ids).Error
	return ids, err
}
