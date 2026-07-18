package database

import (
	"log"

	"firewall-mon/internal/models"
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
