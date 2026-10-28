package database

import (
	"errors"
	"testing"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// failProfileWrites makes the column-targeted event_profile_id UPDATE fail.
//
// UpsertDevice/SiteAlertConfigWithProfile write the config row with Save (a
// struct), then the profile with Update("event_profile_id", ...), whose
// destination is a map. Failing only the map-shaped update lets the config
// write succeed and the profile write fail INSIDE the same transaction - the
// exact split the transaction exists to make impossible.
func failProfileWrites(t *testing.T, d *Database) {
	t.Helper()
	err := d.db.Callback().Update().Before("gorm:update").Register("test:fail_profile_write", func(tx *gorm.DB) {
		if m, ok := tx.Statement.Dest.(map[string]interface{}); ok {
			if _, has := m["event_profile_id"]; has {
				_ = tx.AddError(errors.New("injected: profile write failed"))
			}
		}
	})
	if err != nil {
		t.Fatalf("register the failing callback: %v", err)
	}
}

// TestUpsertAlertConfigWithProfile_RollsBackAsAWhole pins the headline of the
// change: when the profile write fails, the config write is rolled back with
// it. Half an override - new thresholds, old profile - must never persist.
func TestUpsertAlertConfigWithProfile_RollsBackAsAWhole(t *testing.T) {
	d := NewDatabaseForTesting(t)
	profile := &models.EventRuleProfile{Name: "strict"}
	if err := d.db.Create(profile).Error; err != nil {
		t.Fatalf("create the profile: %v", err)
	}
	// Existing rows, so the UPDATE path (Save, then the targeted Update) runs.
	if err := d.UpsertDeviceAlertConfig(&models.DeviceAlertConfig{DeviceID: 1, AlertsEnabled: true, CPUThreshold: 50}); err != nil {
		t.Fatalf("seed the device override: %v", err)
	}
	if err := d.UpsertSiteAlertConfig(&models.SiteAlertConfig{SiteID: 1, CPUThreshold: 50}); err != nil {
		t.Fatalf("seed the site override: %v", err)
	}
	failProfileWrites(t, d)

	devErr := d.UpsertDeviceAlertConfigWithProfile(
		&models.DeviceAlertConfig{DeviceID: 1, AlertsEnabled: true, CPUThreshold: 90}, &profile.ID)
	if devErr == nil {
		t.Fatal("the device upsert reported success although the profile write failed")
	}
	dev, err := d.GetDeviceAlertConfig(1)
	if err != nil {
		t.Fatalf("read the device override back: %v", err)
	}
	if dev.CPUThreshold != 50 || dev.EventProfileID != nil {
		t.Errorf("half a device override persisted: cpu=%v profile=%v, want cpu=50 profile=nil", dev.CPUThreshold, dev.EventProfileID)
	}

	siteErr := d.UpsertSiteAlertConfigWithProfile(
		&models.SiteAlertConfig{SiteID: 1, CPUThreshold: 90}, &profile.ID)
	if siteErr == nil {
		t.Fatal("the site upsert reported success although the profile write failed")
	}
	site, err := d.GetSiteAlertConfig(1)
	if err != nil {
		t.Fatalf("read the site override back: %v", err)
	}
	if site.CPUThreshold != 50 || site.EventProfileID != nil {
		t.Errorf("half a site override persisted: cpu=%v profile=%v, want cpu=50 profile=nil", site.CPUThreshold, site.EventProfileID)
	}
}
