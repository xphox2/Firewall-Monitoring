//go:build integration

package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestPostgresEventRuleProfiles exercises the v48 profile stack on real
// Postgres (CI lane): migration-created tables, transactional delete
// (NULLed assignments + rule reassignment must commit atomically), sparse
// toggle replace, and the live-join counts — the paths where PG behavior
// (booleans in SUM CASE, JOIN plans, transactions) can diverge from the
// SQLite dev backend.
func TestPostgresEventRuleProfiles(t *testing.T) {
	d := newPGForTest(t) // skips if TEST_PG_DSN is unset

	d.EnsureDefaultEventProfile()
	def, err := d.GetDefaultEventRuleProfile()
	if err != nil {
		t.Fatalf("default profile after migrations: %v", err)
	}

	p := models.EventRuleProfile{Name: "PG Branch"}
	if err := d.CreateEventRuleProfile(&p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.ReplaceProfileToggles(p.ID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeCPUHigh, Enabled: false},
		{AlertType: models.AlertTypeDiskHigh, Enabled: true},
	}); err != nil {
		t.Fatalf("toggles: %v", err)
	}
	r := models.EventRule{Name: "pg-rule", Enabled: true, Source: "syslog", Action: "suppress",
		ProfileID: p.ID, MatchJSON: `{"op":"exists","field":"message"}`}
	if err := d.CreateEventRule(&r); err != nil {
		t.Fatalf("rule: %v", err)
	}
	if err := d.Gorm().Create(&models.Device{Name: "pgdev", IPAddress: "10.1.1.1"}).Error; err != nil {
		t.Fatalf("device: %v", err)
	}
	var dev models.Device
	d.Gorm().Where("name = ?", "pgdev").First(&dev)
	if err := d.SetDeviceEventProfile(dev.ID, &p.ID); err != nil {
		t.Fatalf("assign: %v", err)
	}

	counts, err := d.GetEventProfileCounts(def.ID)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	pc := counts[p.ID]
	if pc == nil || pc.RuleCount != 1 || pc.ToggleCount != 2 || pc.ToggleOff != 1 || pc.DeviceCount != 1 {
		t.Fatalf("counts wrong on PG: %+v", pc)
	}

	if err := d.DeleteEventRuleProfile(p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var rule models.EventRule
	d.Gorm().Where("name = ?", "pg-rule").First(&rule)
	if rule.ProfileID != def.ID {
		t.Errorf("rule must be reassigned to Default on delete, got %d", rule.ProfileID)
	}
	var cfg models.DeviceAlertConfig
	d.Gorm().Where("device_id = ?", dev.ID).First(&cfg)
	if cfg.EventProfileID != nil {
		t.Errorf("assignment must be NULLed on delete, got %v", cfg.EventProfileID)
	}
}
