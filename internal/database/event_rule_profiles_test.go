package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// CRUD + lifecycle semantics for Event Rule Profiles (v48 API release).

func seedProfileWorld(t *testing.T, db *Database) (defID uint, profID uint) {
	t.Helper()
	db.EnsureDefaultEventProfile()
	def, err := db.GetDefaultEventRuleProfile()
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	p := models.EventRuleProfile{Name: "Branch", Description: "branch offices"}
	if err := db.CreateEventRuleProfile(&p); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	return def.ID, p.ID
}

func TestEventRuleProfile_DeleteReassignsAndUnassigns(t *testing.T) {
	db := NewDatabaseForTesting(t)
	defID, profID := seedProfileWorld(t, db)

	// Content: a rule in the profile, toggles, and site+device assignments.
	r := models.EventRule{Name: "in-branch", Enabled: true, Source: "syslog", Action: "suppress",
		ProfileID: profID, MatchJSON: `{"op":"exists","field":"message"}`}
	if err := db.CreateEventRule(&r); err != nil {
		t.Fatal(err)
	}
	if err := db.ReplaceProfileToggles(profID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeCPUHigh, Enabled: false},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.Device{ID: 9, Name: "d9", IPAddress: "10.0.0.9"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.Site{ID: 5, Name: "s5"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetDeviceEventProfile(9, &profID); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSiteEventProfile(5, &profID); err != nil {
		t.Fatal(err)
	}

	// Default profile is undeletable.
	if err := db.DeleteEventRuleProfile(defID); err == nil {
		t.Fatal("deleting the Default profile must be refused")
	}

	if err := db.DeleteEventRuleProfile(profID); err != nil {
		t.Fatalf("delete profile: %v", err)
	}
	// Rules reassigned to Default; toggles gone; assignments NULLed.
	var rule models.EventRule
	db.Gorm().Where("name = ?", "in-branch").First(&rule)
	if rule.ProfileID != defID {
		t.Errorf("rule must be reassigned to Default (%d), got %d", defID, rule.ProfileID)
	}
	var togN int64
	db.Gorm().Model(&models.EventRuleProfileToggle{}).Where("profile_id = ?", profID).Count(&togN)
	if togN != 0 {
		t.Errorf("toggles must be deleted with the profile, %d remain", togN)
	}
	var dc models.DeviceAlertConfig
	db.Gorm().Where("device_id = ?", 9).First(&dc)
	if dc.EventProfileID != nil {
		t.Errorf("device assignment must be NULLed, got %v", dc.EventProfileID)
	}
	var sc models.SiteAlertConfig
	db.Gorm().Where("site_id = ?", 5).First(&sc)
	if sc.EventProfileID != nil {
		t.Errorf("site assignment must be NULLed, got %v", sc.EventProfileID)
	}
}

func TestEventRuleProfile_CloneCopiesTogglesAndRulesNotAssignments(t *testing.T) {
	db := NewDatabaseForTesting(t)
	_, profID := seedProfileWorld(t, db)

	if err := db.ReplaceProfileToggles(profID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeVPNTunnelDown, Enabled: false},
		{AlertType: models.AlertTypeCPUHigh, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(2 * time.Hour)
	r := models.EventRule{Name: "temp-mute", Enabled: true, Source: "flow_security", Action: "suppress",
		ProfileID: profID, MatchJSON: `{"op":"eq","field":"source_ip","value":"203.0.113.9"}`,
		ExpiresAt: &exp, HitCount: 42, SeedVersion: 2}
	if err := db.CreateEventRule(&r); err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.Site{ID: 6, Name: "s6"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetSiteEventProfile(6, &profID); err != nil {
		t.Fatal(err)
	}

	clone, err := db.CloneEventRuleProfile(profID, "Branch Copy")
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	var togN int64
	db.Gorm().Model(&models.EventRuleProfileToggle{}).Where("profile_id = ?", clone.ID).Count(&togN)
	if togN != 2 {
		t.Errorf("clone must copy toggles, got %d", togN)
	}
	var cr models.EventRule
	if err := db.Gorm().Where("profile_id = ? AND name = ?", clone.ID, "temp-mute").First(&cr).Error; err != nil {
		t.Fatalf("clone must copy rules: %v", err)
	}
	if cr.HitCount != 0 || cr.SeedVersion != 0 {
		t.Errorf("cloned rule must reset hit_count/seed_version, got %d/%d", cr.HitCount, cr.SeedVersion)
	}
	if cr.ExpiresAt == nil {
		t.Error("cloned temp rule must keep its expiry")
	}
	var assigned int64
	db.Gorm().Model(&models.SiteAlertConfig{}).Where("event_profile_id = ?", clone.ID).Count(&assigned)
	if assigned != 0 {
		t.Errorf("clone must NOT copy assignments (inert until assigned), got %d", assigned)
	}
	// Duplicate name refused.
	if _, err := db.CloneEventRuleProfile(profID, "Branch Copy"); err == nil {
		t.Error("clone with a taken name must fail (unique index)")
	}
}

func TestSetDeviceEventProfile_ColumnTargeted(t *testing.T) {
	db := NewDatabaseForTesting(t)
	_, profID := seedProfileWorld(t, db)

	// Existing config row with sibling fields — the assignment write must not
	// touch them (the GORM full-Save clobber trap).
	if err := db.Gorm().Create(&models.DeviceAlertConfig{
		DeviceID: 3, AlertsEnabled: true, CPUThreshold: 91, CooldownMinutes: 7,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetDeviceEventProfile(3, &profID); err != nil {
		t.Fatal(err)
	}
	var cfg models.DeviceAlertConfig
	db.Gorm().Where("device_id = ?", 3).First(&cfg)
	if cfg.EventProfileID == nil || *cfg.EventProfileID != profID {
		t.Fatalf("assignment not written: %v", cfg.EventProfileID)
	}
	if cfg.CPUThreshold != 91 || cfg.CooldownMinutes != 7 || !cfg.AlertsEnabled {
		t.Errorf("sibling fields clobbered: %+v", cfg)
	}
	// Clear. Fresh structs per query — a populated primary key would leak into
	// GORM's WHERE clause and read the wrong row.
	if err := db.SetDeviceEventProfile(3, nil); err != nil {
		t.Fatal(err)
	}
	cfg = models.DeviceAlertConfig{}
	db.Gorm().Where("device_id = ?", 3).First(&cfg)
	if cfg.EventProfileID != nil {
		t.Errorf("clear must NULL the column, got %v", cfg.EventProfileID)
	}
	// No config row yet → created minimal with AlertsEnabled true.
	if err := db.SetDeviceEventProfile(4, &profID); err != nil {
		t.Fatal(err)
	}
	cfg = models.DeviceAlertConfig{}
	db.Gorm().Where("device_id = ?", 4).First(&cfg)
	if cfg.EventProfileID == nil || !cfg.AlertsEnabled {
		t.Errorf("fresh config must carry the assignment and AlertsEnabled=true: %+v", cfg)
	}
}

func TestGetEventProfileCounts_LiveJoinExcludesOrphans(t *testing.T) {
	db := NewDatabaseForTesting(t)
	defID, profID := seedProfileWorld(t, db)

	// Live device + orphaned config row (device deleted → config remains).
	if err := db.Gorm().Create(&models.Device{ID: 1, Name: "live", IPAddress: "10.0.0.1"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetDeviceEventProfile(1, &profID); err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.DeviceAlertConfig{DeviceID: 777, AlertsEnabled: true, EventProfileID: &profID}).Error; err != nil {
		t.Fatal(err) // no device 777 — an orphan
	}
	// Rules: one stamped, one 0-sentinel (folds into Default), one temporary.
	exp := time.Now().Add(time.Hour)
	for _, r := range []models.EventRule{
		{Name: "a", Enabled: true, Source: "syslog", Action: "alert", ProfileID: profID, MatchJSON: `{"op":"exists","field":"message"}`},
		{Name: "b", Enabled: true, Source: "syslog", Action: "suppress", ProfileID: 0, MatchJSON: `{"op":"exists","field":"message"}`},
		{Name: "c", Enabled: true, Source: "flow_security", Action: "suppress", ProfileID: profID, ExpiresAt: &exp, MatchJSON: `{"op":"exists","field":"detector"}`},
	} {
		rr := r
		if err := db.Gorm().Create(&rr).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.ReplaceProfileToggles(profID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeCPUHigh, Enabled: false},
		{AlertType: models.AlertTypeDiskHigh, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}

	counts, err := db.GetEventProfileCounts(defID)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	pc := counts[profID]
	if pc == nil {
		t.Fatal("profile counts missing")
	}
	if pc.RuleCount != 2 || pc.TempRuleCount != 1 {
		t.Errorf("rule counts = %d/%d temp, want 2/1", pc.RuleCount, pc.TempRuleCount)
	}
	if pc.ToggleCount != 2 || pc.ToggleOff != 1 {
		t.Errorf("toggle counts = %d/%d off, want 2/1", pc.ToggleCount, pc.ToggleOff)
	}
	if pc.DeviceCount != 1 {
		t.Errorf("device count = %d, want 1 (orphaned config row must not count)", pc.DeviceCount)
	}
	dc := counts[defID]
	if dc == nil || dc.RuleCount != 1 {
		t.Errorf("0-sentinel rule must fold into the Default profile's count, got %+v", dc)
	}
}

func TestGetEventProfileAssignments_LiveJoin(t *testing.T) {
	db := NewDatabaseForTesting(t)
	_, profID := seedProfileWorld(t, db)

	if err := db.Gorm().Create(&models.Site{ID: 8, Name: "s8"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.Device{ID: 2, Name: "d2", IPAddress: "10.0.0.2"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetSiteEventProfile(8, &profID); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDeviceEventProfile(2, &profID); err != nil {
		t.Fatal(err)
	}
	// Orphan: config row whose device no longer exists — must not list.
	if err := db.Gorm().Create(&models.DeviceAlertConfig{DeviceID: 999, AlertsEnabled: true, EventProfileID: &profID}).Error; err != nil {
		t.Fatal(err)
	}

	sites, devices, err := db.GetEventProfileAssignments(profID)
	if err != nil {
		t.Fatalf("assignments: %v", err)
	}
	if len(sites) != 1 || sites[0].Name != "s8" {
		t.Errorf("sites = %+v, want [s8]", sites)
	}
	if len(devices) != 1 || devices[0].Name != "d2" {
		t.Errorf("devices = %+v, want [d2] (orphaned config must not list)", devices)
	}
}

func TestReplaceProfileToggles_FullSparseReplace(t *testing.T) {
	db := NewDatabaseForTesting(t)
	_, profID := seedProfileWorld(t, db)
	if err := db.ReplaceProfileToggles(profID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeCPUHigh, Enabled: false},
		{AlertType: models.AlertTypeDiskHigh, Enabled: false},
	}); err != nil {
		t.Fatal(err)
	}
	// New set drops CPU (back to Inherit) and adds VPN.
	if err := db.ReplaceProfileToggles(profID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeVPNTunnelDown, Enabled: false},
	}); err != nil {
		t.Fatal(err)
	}
	toggles, err := db.GetProfileToggles(profID)
	if err != nil {
		t.Fatal(err)
	}
	if len(toggles) != 1 || toggles[0].AlertType != models.AlertTypeVPNTunnelDown {
		t.Errorf("replace must swap the full sparse set, got %+v", toggles)
	}
}
