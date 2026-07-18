package database

import (
	"testing"

	"firewall-mon/internal/models"
)

func uintPtr(v uint) *uint { return &v }

// v48 fidelity: AlertRule.Enabled=false state in REFERENCED policies becomes
// dense-over-D profile toggles (including the Default profile), assignments
// are mirrored (default-policy pins included — the refutation case), dangling
// pins are skipped, unreferenced policies contribute nothing, and re-running
// is idempotent.
func TestMigrateEventRuleProfiles_Fidelity(t *testing.T) {
	db := NewDatabaseForTesting(t)

	// Policies: default (disables DEVICE_OFFLINE), site policy (disables
	// SFLOW_SECURITY), a clean device policy, and an unreferenced policy whose
	// disable (CPU_HIGH) must NOT enter D.
	defPol := models.AlertPolicy{Name: "Default", IsDefault: true}
	sitePol := models.AlertPolicy{Name: "SiteNoisy"}
	cleanPol := models.AlertPolicy{Name: "CleanQ"}
	orphanPol := models.AlertPolicy{Name: "Orphan"}
	for _, p := range []*models.AlertPolicy{&defPol, &sitePol, &cleanPol, &orphanPol} {
		if err := db.db.Create(p).Error; err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}
	// Enabled:false is the Go zero value and AlertRule carries default:true —
	// GORM writes TRUE on Create regardless (even under an explicit Select),
	// so seed disabled state with a post-create UPDATE, which is also how the
	// production edit path persists an uncheck.
	for _, r := range []models.AlertRule{
		{PolicyID: defPol.ID, AlertType: models.AlertTypeDeviceOffline},
		{PolicyID: sitePol.ID, AlertType: models.AlertTypeSFlowSecurity},
		{PolicyID: orphanPol.ID, AlertType: models.AlertTypeCPUHigh},
	} {
		if err := db.db.Create(&r).Error; err != nil {
			t.Fatalf("seed alert rule: %v", err)
		}
		if err := db.db.Model(&models.AlertRule{}).Where("id = ?", r.ID).Update("enabled", false).Error; err != nil {
			t.Fatalf("disable alert rule: %v", err)
		}
	}
	// Enabled rows never enter D.
	if err := db.db.Create(&models.AlertRule{PolicyID: sitePol.ID, AlertType: models.AlertTypeVPNTunnelDown, Enabled: true}).Error; err != nil {
		t.Fatalf("seed enabled alert rule: %v", err)
	}

	// Assignments: site 10 → SiteNoisy; device 1 → CleanQ (shadows the site);
	// device 2 → EXPLICIT default-policy pin (the refuted divergence case);
	// device 4 → dangling policy id.
	if err := db.db.Create(&models.SiteAlertConfig{SiteID: 10, PolicyID: &sitePol.ID}).Error; err != nil {
		t.Fatalf("seed site cfg: %v", err)
	}
	for _, c := range []models.DeviceAlertConfig{
		{DeviceID: 1, PolicyID: &cleanPol.ID, AlertsEnabled: true},
		{DeviceID: 2, PolicyID: &defPol.ID, AlertsEnabled: true},
		{DeviceID: 4, PolicyID: uintPtr(999), AlertsEnabled: true},
		{DeviceID: 5, PolicyID: nil, AlertsEnabled: true}, // inherit — must stay nil
	} {
		if err := db.db.Create(&c).Error; err != nil {
			t.Fatalf("seed device cfg: %v", err)
		}
	}

	// A pre-existing flat rule: must land in the Default profile.
	if err := db.db.Create(&models.EventRule{Name: "legacy", Source: "syslog", Action: "alert",
		MatchJSON: `{"op":"eq","field":"severity","value":"0"}`}).Error; err != nil {
		t.Fatalf("seed event rule: %v", err)
	}

	if err := db.migrateEventRuleProfiles(); err != nil {
		t.Fatalf("migration: %v", err)
	}

	defProf, err := db.GetDefaultEventRuleProfile()
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}

	toggleState := func(profileID uint, at models.AlertType) (bool, bool) {
		var tg models.EventRuleProfileToggle
		if err := db.db.Where("profile_id = ? AND alert_type = ?", profileID, at).First(&tg).Error; err != nil {
			return false, false
		}
		return tg.Enabled, true
	}
	profileByName := func(name string) *models.EventRuleProfile {
		var p models.EventRuleProfile
		if err := db.db.Where("name = ?", name).First(&p).Error; err != nil {
			return nil
		}
		return &p
	}

	// D = {DEVICE_OFFLINE, SFLOW_SECURITY}. Orphan's CPU_HIGH must be absent
	// everywhere; VPN_TUNNEL_DOWN (enabled row) must be absent everywhere.
	var cpuRows int64
	db.db.Model(&models.EventRuleProfileToggle{}).Where("alert_type = ?", models.AlertTypeCPUHigh).Count(&cpuRows)
	if cpuRows != 0 {
		t.Errorf("unreferenced policy's disable leaked into toggles (%d CPU_HIGH rows)", cpuRows)
	}
	var vpnRows int64
	db.db.Model(&models.EventRuleProfileToggle{}).Where("alert_type = ?", models.AlertTypeVPNTunnelDown).Count(&vpnRows)
	if vpnRows != 0 {
		t.Errorf("enabled AlertRule rows must not enter D (%d VPN_TUNNEL_DOWN rows)", vpnRows)
	}

	// Default profile: dense over D — DEVICE_OFFLINE Off (default policy
	// disables it), SFLOW_SECURITY explicit On (the row that lets an explicit
	// default-policy pin shadow the site's Off at the device layer).
	if on, ok := toggleState(defProf.ID, models.AlertTypeDeviceOffline); !ok || on {
		t.Errorf("Default profile DEVICE_OFFLINE: want explicit Off row, got on=%v present=%v", on, ok)
	}
	if on, ok := toggleState(defProf.ID, models.AlertTypeSFlowSecurity); !ok || !on {
		t.Errorf("Default profile SFLOW_SECURITY: want explicit On row (dense-over-D), got on=%v present=%v", on, ok)
	}

	// SiteNoisy profile: SFLOW_SECURITY Off, DEVICE_OFFLINE explicit On.
	siteProf := profileByName("SiteNoisy")
	if siteProf == nil {
		t.Fatal("SiteNoisy profile not created")
	}
	if on, ok := toggleState(siteProf.ID, models.AlertTypeSFlowSecurity); !ok || on {
		t.Errorf("SiteNoisy SFLOW_SECURITY: want Off, got on=%v present=%v", on, ok)
	}
	if on, ok := toggleState(siteProf.ID, models.AlertTypeDeviceOffline); !ok || !on {
		t.Errorf("SiteNoisy DEVICE_OFFLINE: want explicit On (dense), got on=%v present=%v", on, ok)
	}

	// CleanQ profile exists (clean policies still need shadowing rows) with
	// explicit On for the whole of D.
	cleanProf := profileByName("CleanQ")
	if cleanProf == nil {
		t.Fatal("CleanQ profile not created (clean referenced policies must still get a shadowing profile)")
	}
	for _, at := range []models.AlertType{models.AlertTypeDeviceOffline, models.AlertTypeSFlowSecurity} {
		if on, ok := toggleState(cleanProf.ID, at); !ok || !on {
			t.Errorf("CleanQ %s: want explicit On, got on=%v present=%v", at, on, ok)
		}
	}
	if profileByName("Orphan") != nil {
		t.Error("unreferenced policy must not get a profile")
	}

	// Assignment mirroring.
	var d1, d2, d4 models.DeviceAlertConfig
	db.db.Where("device_id = ?", 1).First(&d1)
	db.db.Where("device_id = ?", 2).First(&d2)
	db.db.Where("device_id = ?", 4).First(&d4)
	if d1.EventProfileID == nil || *d1.EventProfileID != cleanProf.ID {
		t.Errorf("device 1 must mirror CleanQ, got %v", d1.EventProfileID)
	}
	if d2.EventProfileID == nil || *d2.EventProfileID != defProf.ID {
		t.Errorf("device 2 (explicit default-policy pin) must mirror the Default profile, got %v", d2.EventProfileID)
	}
	if d4.EventProfileID != nil {
		t.Errorf("dangling policy pin must stay nil, got %v", d4.EventProfileID)
	}
	var d5 models.DeviceAlertConfig
	db.db.Where("device_id = ?", 5).First(&d5)
	if d5.EventProfileID != nil {
		t.Errorf("nil-PolicyID config must keep event_profile_id NULL (inherit), got %v", d5.EventProfileID)
	}
	var s10 models.SiteAlertConfig
	db.db.Where("site_id = ?", 10).First(&s10)
	if s10.EventProfileID == nil || *s10.EventProfileID != siteProf.ID {
		t.Errorf("site 10 must mirror SiteNoisy, got %v", s10.EventProfileID)
	}

	// Backfill: the legacy rule joined the Default profile.
	var legacy models.EventRule
	db.db.Where("name = ?", "legacy").First(&legacy)
	if legacy.ProfileID != defProf.ID {
		t.Errorf("legacy rule must be backfilled to Default profile %d, got %d", defProf.ID, legacy.ProfileID)
	}

	// Idempotency: re-run changes nothing.
	var profBefore, togBefore int64
	db.db.Model(&models.EventRuleProfile{}).Count(&profBefore)
	db.db.Model(&models.EventRuleProfileToggle{}).Count(&togBefore)
	if err := db.migrateEventRuleProfiles(); err != nil {
		t.Fatalf("migration re-run: %v", err)
	}
	var profAfter, togAfter int64
	db.db.Model(&models.EventRuleProfile{}).Count(&profAfter)
	db.db.Model(&models.EventRuleProfileToggle{}).Count(&togAfter)
	if profBefore != profAfter || togBefore != togAfter {
		t.Errorf("re-run must be idempotent: profiles %d→%d toggles %d→%d", profBefore, profAfter, togBefore, togAfter)
	}
}

// v48 on an install that never used AlertRule.Enabled=false (or has no
// policies at all — fresh DB where the migration runs before
// EnsureDefaultPolicy): only the Default profile is created, zero toggles,
// zero profiles for policies — provably inert.
func TestMigrateEventRuleProfiles_EmptyDInert(t *testing.T) {
	db := NewDatabaseForTesting(t)
	// Referenced policy with only ENABLED rules.
	pol := models.AlertPolicy{Name: "Default", IsDefault: true}
	if err := db.db.Create(&pol).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := db.db.Create(&models.AlertRule{PolicyID: pol.ID, AlertType: models.AlertTypeCPUHigh, Enabled: true}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	if err := db.migrateEventRuleProfiles(); err != nil {
		t.Fatalf("migration: %v", err)
	}
	var profiles, toggles int64
	db.db.Model(&models.EventRuleProfile{}).Count(&profiles)
	db.db.Model(&models.EventRuleProfileToggle{}).Count(&toggles)
	if profiles != 1 || toggles != 0 {
		t.Errorf("empty-D must be inert: want 1 profile (Default) + 0 toggles, got %d/%d", profiles, toggles)
	}

	// Truly fresh DB (no policies at all).
	db2 := NewDatabaseForTesting(t)
	if err := db2.migrateEventRuleProfiles(); err != nil {
		t.Fatalf("migration on fresh DB: %v", err)
	}
	if _, err := db2.GetDefaultEventRuleProfile(); err != nil {
		t.Errorf("fresh DB must still get the Default profile: %v", err)
	}
}

// Seeds are stamped into the Default profile, and the 0-sentinel keeps any
// unstamped row attached to the Default layer semantics (compile-time mapping
// is pinned in the alerts package tests).
func TestEnsureDefaultRules_StampsProfileID(t *testing.T) {
	db := NewDatabaseForTesting(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()

	defProf, err := db.GetDefaultEventRuleProfile()
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	var rules []models.EventRule
	db.db.Where("seed_version > 0").Find(&rules)
	if len(rules) == 0 {
		t.Fatal("expected seeded rules")
	}
	for _, r := range rules {
		if r.ProfileID != defProf.ID {
			t.Errorf("seed %q not stamped with Default profile: got %d want %d", r.Name, r.ProfileID, defProf.ID)
		}
	}
}
