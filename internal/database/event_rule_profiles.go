package database

import (
	"errors"
	"fmt"
	"log"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// event_rule_profiles.go — persistence for Event Rule Profiles (v48): the
// named bundles of per-alert-type toggles + EventRules resolved along the
// Default > Site > Device chain. This file carries the seeder and the
// engine-facing loaders; the handler-facing CRUD ships with the profile API.

// EnsureDefaultEventProfile guarantees the Default profile exists. Idempotent
// (FirstOrCreate on is_default). Called from NewDatabase after
// EnsureDefaultPolicy AND from migration v48 (which needs it for backfill) —
// fresh installs and upgrades both end up with exactly one Default profile.
func (d *Database) EnsureDefaultEventProfile() {
	var p models.EventRuleProfile
	if err := d.db.Where("is_default = ?", true).Attrs(models.EventRuleProfile{
		Name:        "Default",
		Description: "Applies to everything without a site or device profile. Other profiles inherit from it.",
		IsDefault:   true,
	}).FirstOrCreate(&p).Error; err != nil {
		log.Printf("EnsureDefaultEventProfile: %v", err)
	}
}

// GetDefaultEventRuleProfile loads the Default profile.
func (d *Database) GetDefaultEventRuleProfile() (*models.EventRuleProfile, error) {
	var p models.EventRuleProfile
	if err := d.db.Where("is_default = ?", true).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// GetAllEventRuleProfiles returns every profile (Default first) for the
// resolver cache and the admin list.
func (d *Database) GetAllEventRuleProfiles() ([]models.EventRuleProfile, error) {
	var profiles []models.EventRuleProfile
	err := d.db.Order("is_default DESC, name ASC").Find(&profiles).Error
	return profiles, err
}

// GetAllEventRuleProfileToggles returns every explicit toggle row. The matrix
// is sparse — absence of a (profile, alert_type) row means Inherit — so this
// is a small table by construction.
func (d *Database) GetAllEventRuleProfileToggles() ([]models.EventRuleProfileToggle, error) {
	var toggles []models.EventRuleProfileToggle
	err := d.db.Find(&toggles).Error
	return toggles, err
}

// GetEventRuleProfile loads one profile by id.
func (d *Database) GetEventRuleProfile(id uint) (*models.EventRuleProfile, error) {
	var p models.EventRuleProfile
	if err := d.db.First(&p, id).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateEventRuleProfile inserts a new (never-default) profile.
func (d *Database) CreateEventRuleProfile(p *models.EventRuleProfile) error {
	p.IsDefault = false // exactly one Default exists, created by the seeder
	return d.db.Create(p).Error
}

// UpdateEventRuleProfile persists name/description edits. IsDefault is
// immutable (the Default profile is the chain anchor).
func (d *Database) UpdateEventRuleProfile(p *models.EventRuleProfile) error {
	return d.db.Model(&models.EventRuleProfile{}).Where("id = ?", p.ID).
		Updates(map[string]any{"name": p.Name, "description": p.Description}).Error
}

// DeleteEventRuleProfile removes a profile ATOMICALLY: refuse the Default
// profile; NULL every device/site assignment pointing at it; reassign its
// rules to the Default profile; delete its toggles and the profile row.
// One transaction — a half-deleted profile would leave rules evaluating in a
// vanished layer (they'd fall through as dangling, but the editor would show
// orphans). Deliberately NOT modeled on DeleteAlertPolicy, which is
// non-atomic.
func (d *Database) DeleteEventRuleProfile(id uint) error {
	var p models.EventRuleProfile
	if err := d.db.First(&p, id).Error; err != nil {
		return fmt.Errorf("delete event rule profile %d: load: %w", id, err)
	}
	if p.IsDefault {
		return fmt.Errorf("cannot delete the Default event rule profile")
	}
	def, err := d.GetDefaultEventRuleProfile()
	if err != nil {
		return fmt.Errorf("delete event rule profile %d: load default: %w", id, err)
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.DeviceAlertConfig{}).Where("event_profile_id = ?", id).
			Update("event_profile_id", nil).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.SiteAlertConfig{}).Where("event_profile_id = ?", id).
			Update("event_profile_id", nil).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.EventRule{}).Where("profile_id = ?", id).
			Update("profile_id", def.ID).Error; err != nil {
			return err
		}
		if err := tx.Where("profile_id = ?", id).Delete(&models.EventRuleProfileToggle{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.EventRuleProfile{}, id).Error
	})
}

// CloneEventRuleProfile deep-copies a profile's toggles AND rules under a new
// name. Assignments are deliberately NOT copied (a clone must be inert until
// assigned). One transaction — a half-clone (toggles without rules) is a
// support ticket.
func (d *Database) CloneEventRuleProfile(id uint, newName string) (*models.EventRuleProfile, error) {
	src, err := d.GetEventRuleProfile(id)
	if err != nil {
		return nil, fmt.Errorf("clone event rule profile %d: load: %w", id, err)
	}
	clone := models.EventRuleProfile{Name: newName, Description: src.Description}
	err = d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&clone).Error; err != nil {
			return err
		}
		var toggles []models.EventRuleProfileToggle
		if err := tx.Where("profile_id = ?", id).Find(&toggles).Error; err != nil {
			return err
		}
		for i := range toggles {
			t := models.EventRuleProfileToggle{ProfileID: clone.ID, AlertType: toggles[i].AlertType, Enabled: toggles[i].Enabled}
			if err := tx.Create(&t).Error; err != nil {
				return err
			}
		}
		var rules []models.EventRule
		if err := tx.Where("profile_id = ?", id).Find(&rules).Error; err != nil {
			return err
		}
		for i := range rules {
			r := rules[i]
			r.ID = 0
			r.ProfileID = clone.ID
			r.SeedVersion = 0 // a cloned seed is operator-owned
			r.HitCount = 0
			r.LastHitAt = nil
			if err := tx.Create(&r).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &clone, nil
}

// GetProfileToggles returns one profile's explicit toggle rows.
func (d *Database) GetProfileToggles(profileID uint) ([]models.EventRuleProfileToggle, error) {
	var toggles []models.EventRuleProfileToggle
	err := d.db.Where("profile_id = ?", profileID).Order("alert_type asc").Find(&toggles).Error
	return toggles, err
}

// ReplaceProfileToggles swaps a profile's full SPARSE toggle set in one
// transaction (the UI renders every type from the registry and sends only the
// non-Inherit rows, so full-replace cannot lose unknown types the way the
// AlertRule batch upsert could).
func (d *Database) ReplaceProfileToggles(profileID uint, toggles []models.EventRuleProfileToggle) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("profile_id = ?", profileID).Delete(&models.EventRuleProfileToggle{}).Error; err != nil {
			return err
		}
		for i := range toggles {
			t := models.EventRuleProfileToggle{ProfileID: profileID, AlertType: toggles[i].AlertType, Enabled: toggles[i].Enabled}
			if err := tx.Create(&t).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// SetDeviceEventProfile assigns (or, with nil, clears) a device's event
// profile. COLUMN-TARGETED on an existing config row (never a full Save — a
// stale struct would clobber sibling fields, the classic GORM FK write-back
// trap); creates a minimal row when none exists.
func (d *Database) SetDeviceEventProfile(deviceID uint, profileID *uint) error {
	var existing models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", deviceID).First(&existing).Error
	if err == nil {
		return d.db.Model(&models.DeviceAlertConfig{}).Where("device_id = ?", deviceID).
			Update("event_profile_id", profileID).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("set device event profile (device %d): lookup: %w", deviceID, err)
	}
	cfg := models.DeviceAlertConfig{DeviceID: deviceID, AlertsEnabled: true, EventProfileID: profileID}
	return d.db.Create(&cfg).Error
}

// SetSiteEventProfile assigns (or clears) a site's event profile — same
// column-targeted discipline as the device variant.
func (d *Database) SetSiteEventProfile(siteID uint, profileID *uint) error {
	var existing models.SiteAlertConfig
	err := d.db.Where("site_id = ?", siteID).First(&existing).Error
	if err == nil {
		return d.db.Model(&models.SiteAlertConfig{}).Where("site_id = ?", siteID).
			Update("event_profile_id", profileID).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("set site event profile (site %d): lookup: %w", siteID, err)
	}
	cfg := models.SiteAlertConfig{SiteID: siteID, EventProfileID: profileID}
	return d.db.Create(&cfg).Error
}

// EventProfileCounts is the per-profile summary for the profile list.
type EventProfileCounts struct {
	RuleCount     int64 `json:"rule_count"`
	TempRuleCount int64 `json:"temp_rule_count"`
	ToggleCount   int64 `json:"toggle_count"`
	ToggleOff     int64 `json:"toggle_off_count"`
	SiteCount     int64 `json:"site_count"`
	DeviceCount   int64 `json:"device_count"`
}

// GetEventProfileCounts returns profileID → counts. Assignment counts JOIN
// live sites/devices — DeleteDevice/DeleteSite orphan their config rows, so a
// raw config-row count would keep counting ghosts. Rules with the profile_id=0
// Default sentinel fold into defaultID.
func (d *Database) GetEventProfileCounts(defaultID uint) (map[uint]*EventProfileCounts, error) {
	out := map[uint]*EventProfileCounts{}
	get := func(id uint) *EventProfileCounts {
		if out[id] == nil {
			out[id] = &EventProfileCounts{}
		}
		return out[id]
	}

	var ruleRows []struct {
		ProfileID uint
		N         int64
		Temp      int64
	}
	if err := d.db.Model(&models.EventRule{}).
		Select("profile_id, COUNT(*) as n, SUM(CASE WHEN expires_at IS NOT NULL THEN 1 ELSE 0 END) as temp").
		Group("profile_id").Scan(&ruleRows).Error; err != nil {
		return nil, err
	}
	for _, r := range ruleRows {
		pid := r.ProfileID
		if pid == 0 {
			pid = defaultID
		}
		c := get(pid)
		c.RuleCount += r.N
		c.TempRuleCount += r.Temp
	}

	var togRows []struct {
		ProfileID uint
		N         int64
		Off       int64
	}
	if err := d.db.Model(&models.EventRuleProfileToggle{}).
		Select("profile_id, COUNT(*) as n, SUM(CASE WHEN enabled THEN 0 ELSE 1 END) as off").
		Group("profile_id").Scan(&togRows).Error; err != nil {
		return nil, err
	}
	for _, r := range togRows {
		c := get(r.ProfileID)
		c.ToggleCount = r.N
		c.ToggleOff = r.Off
	}

	var devRows []struct {
		EventProfileID uint
		N              int64
	}
	if err := d.db.Model(&models.DeviceAlertConfig{}).
		Select("device_alert_configs.event_profile_id, COUNT(*) as n").
		Joins("JOIN devices ON devices.id = device_alert_configs.device_id").
		Where("device_alert_configs.event_profile_id IS NOT NULL").
		Group("device_alert_configs.event_profile_id").Scan(&devRows).Error; err != nil {
		return nil, err
	}
	for _, r := range devRows {
		get(r.EventProfileID).DeviceCount = r.N
	}

	var siteRows []struct {
		EventProfileID uint
		N              int64
	}
	if err := d.db.Model(&models.SiteAlertConfig{}).
		Select("site_alert_configs.event_profile_id, COUNT(*) as n").
		Joins("JOIN sites ON sites.id = site_alert_configs.site_id").
		Where("site_alert_configs.event_profile_id IS NOT NULL").
		Group("site_alert_configs.event_profile_id").Scan(&siteRows).Error; err != nil {
		return nil, err
	}
	for _, r := range siteRows {
		get(r.EventProfileID).SiteCount = r.N
	}
	return out, nil
}
