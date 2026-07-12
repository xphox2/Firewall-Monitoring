package database

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// Phase 2 seed guarantees: metric templates ship, but they are INERT — the
// metric event types must NOT be in the state_engine_owns flag (the legacy
// CheckSystemStatus path still owns them until Phase 4).

func TestEnsureDefaultRules_MetricTemplatesInert(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.EnsureDefaultRules()

	rules, err := d.ListEventRules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	metricByType := map[models.AlertType]bool{}
	for _, r := range rules {
		if r.Source == "metric" {
			metricByType[r.AlertType] = true
			if r.SeedVersion != seedVerMetric {
				t.Errorf("metric seed %q has SeedVersion %d, want %d", r.Name, r.SeedVersion, seedVerMetric)
			}
		}
	}
	for _, at := range []models.AlertType{
		models.AlertTypeCPUHigh, models.AlertTypeMemoryHigh,
		models.AlertTypeDiskHigh, models.AlertTypeSessionsHigh,
	} {
		if !metricByType[at] {
			t.Errorf("missing seeded metric template for %s", at)
		}
	}

	// Ownership flag must NOT include any metric event type — they stay inert.
	owned, _ := d.GetSettingValue("state_engine_owns")
	for _, ev := range []string{"cpu_high", "memory_high", "disk_high", "sessions_high"} {
		if strings.Contains(owned, ev) {
			t.Errorf("state_engine_owns %q must NOT contain metric type %q (Phase 2 is inert)", owned, ev)
		}
	}
	// It SHOULD still own the Phase 1 state types.
	if !strings.Contains(owned, "interface_down") || !strings.Contains(owned, "vpn_tunnel_down") {
		t.Errorf("state_engine_owns %q lost the Phase 1 state types", owned)
	}
}

// TestEnsureDefaultRules_SpikeTrapTemplatesInert (Phase 3): the spike + trap
// templates ship but must NOT be owned — the legacy poller/ProcessTrap paths
// still drive them until Phase 4.
func TestEnsureDefaultRules_SpikeTrapTemplatesInert(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.EnsureDefaultRules()

	var spikeCount, trapCount int64
	d.db.Model(&models.EventRule{}).Where("source = ?", "spike").Count(&spikeCount)
	d.db.Model(&models.EventRule{}).Where("source = ?", "trap").Count(&trapCount)
	if spikeCount != 1 {
		t.Errorf("want 1 spike template, got %d", spikeCount)
	}
	if trapCount != 4 {
		t.Errorf("want 4 trap templates, got %d", trapCount)
	}

	// Ownership flag must NOT include traffic_spike or any trap type (compared
	// case-insensitively — the flag holds event_type-style tokens, so guard against
	// either casing sneaking in).
	owned, _ := d.GetSettingValue("state_engine_owns")
	lowerOwned := strings.ToLower(owned)
	for _, ev := range []string{"traffic_spike", "ha_member_down", "link_down"} {
		if strings.Contains(lowerOwned, ev) {
			t.Errorf("state_engine_owns %q must NOT contain %q (Phase 3 is inert)", owned, ev)
		}
	}
}

// TestEnsureDefaultRules_UpgradeMarker3To4 exercises the real Phase-2→Phase-3
// upgrade: a marker at "3" with the gen 1-3 rows already present must seed ONLY
// the gen-4 spike/trap rules, leave a deleted older seed dead, advance the marker
// to 4, and not touch the existing ownership flag.
func TestEnsureDefaultRules_UpgradeMarker3To4(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.EnsureDefaultRules() // fresh: seeds all gens, marker=4, flag set
	// Simulate a machine that last ran at gen 3 (Phase 2): roll the marker back and
	// remove the gen-4 rows so the "upgrade" re-seeds them.
	if err := d.db.Where("source IN ?", []string{"spike", "trap"}).Delete(&models.EventRule{}).Error; err != nil {
		t.Fatalf("clear gen-4 rows: %v", err)
	}
	// Operator had deleted a gen-2 state seed before upgrading.
	if err := d.db.Where("name = ?", "VPN tunnel down").Delete(&models.EventRule{}).Error; err != nil {
		t.Fatalf("delete state seed: %v", err)
	}
	// Operator edited the ownership flag before upgrading.
	if err := d.UpsertSetting(&models.SystemSetting{Key: "state_engine_owns", Value: "interface_down"}); err != nil {
		t.Fatalf("edit flag: %v", err)
	}
	if err := d.UpsertSetting(&models.SystemSetting{Key: "event_rules_seed_version", Value: "3"}); err != nil {
		t.Fatalf("set marker 3: %v", err)
	}

	d.EnsureDefaultRules() // upgrade 3→4

	var spikeCount, trapCount, vpnCount int64
	d.db.Model(&models.EventRule{}).Where("source = ?", "spike").Count(&spikeCount)
	d.db.Model(&models.EventRule{}).Where("source = ?", "trap").Count(&trapCount)
	d.db.Model(&models.EventRule{}).Where("name = ?", "VPN tunnel down").Count(&vpnCount)
	if spikeCount != 1 || trapCount != 4 {
		t.Errorf("gen-4 rules not seeded on 3→4 upgrade: spike=%d trap=%d", spikeCount, trapCount)
	}
	if vpnCount != 0 {
		t.Error("operator-deleted gen-2 state seed was resurrected on the 3→4 upgrade")
	}
	if v, _ := d.GetSettingValue("event_rules_seed_version"); v != "4" {
		t.Errorf("marker not advanced to 4, got %q", v)
	}
	if v, _ := d.GetSettingValue("state_engine_owns"); v != "interface_down" {
		t.Errorf("ownership flag clobbered on upgrade: got %q", v)
	}
}

// TestEnsureDefaultRules_NoResurrectOnBump verifies the seed-generation guard: an
// operator-deleted OLDER-generation seed is not recreated when a newer generation
// is applied. Simulated by pre-setting the marker to the state generation and
// deleting a syslog (gen 1) seed, then running EnsureDefaultRules (which applies
// the newer generations 3+4): the deleted gen-1 rule must stay gone; the gen-3
// metric rules appear.
func TestEnsureDefaultRules_NoResurrectOnBump(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// Seed everything once (fresh install → marker = current).
	d.EnsureDefaultRules()
	// Operator deletes a gen-1 syslog seed, then we pretend an older marker so a
	// bump re-runs the seed loop.
	if err := d.db.Where("name = ?", "Syslog Emergency (severity 0)").Delete(&models.EventRule{}).Error; err != nil {
		t.Fatalf("delete syslog seed: %v", err)
	}
	if err := d.UpsertSetting(&models.SystemSetting{Key: "event_rules_seed_version", Value: "2"}); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	d.EnsureDefaultRules() // applies gen 3

	var syslogCount, metricCount int64
	d.db.Model(&models.EventRule{}).Where("name = ?", "Syslog Emergency (severity 0)").Count(&syslogCount)
	d.db.Model(&models.EventRule{}).Where("source = ?", "metric").Count(&metricCount)
	if syslogCount != 0 {
		t.Error("deleted gen-1 syslog seed was resurrected on the gen-3 bump")
	}
	if metricCount != 4 {
		t.Errorf("want 4 metric seeds after bump, got %d", metricCount)
	}
}

// TestUpdateEventRule_PersistsDampenJSON is the regression guard for the review's
// HIGH finding: UpdateEventRule dropped dampen_json from its column Select, so
// every threshold / flap edit through the editor was silently lost.
func TestUpdateEventRule_PersistsDampenJSON(t *testing.T) {
	d := NewDatabaseForTesting(t)
	r := &models.EventRule{
		Name: "CPU high (test)", Enabled: true, Source: "metric", Action: "alert",
		AlertType: models.AlertTypeCPUHigh, DampenJSON: `{"mode":"static"}`,
	}
	if err := d.CreateEventRule(r); err != nil {
		t.Fatalf("create: %v", err)
	}
	r.DampenJSON = `{"mode":"zscore","threshold":88,"clear_threshold":80,"zscore_k":3}`
	if err := d.UpdateEventRule(r); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := d.GetEventRule(r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DampenJSON != r.DampenJSON {
		t.Errorf("dampen_json not persisted on update: got %q want %q", got.DampenJSON, r.DampenJSON)
	}
}

// TestEnsureDefaultRules_OwnershipFlagNotClobbered guards the review's MEDIUM
// finding: a version bump must NOT overwrite an operator-edited state_engine_owns
// (e.g. a type reverted to the legacy path), or alerting silently changes on
// upgrade.
func TestEnsureDefaultRules_OwnershipFlagNotClobbered(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.EnsureDefaultRules()
	// Operator reverts interface_down to legacy by editing the flag.
	if err := d.UpsertSetting(&models.SystemSetting{Key: "state_engine_owns", Value: "vpn_tunnel_down"}); err != nil {
		t.Fatalf("edit flag: %v", err)
	}
	// Simulate an older marker so a "bump" re-runs the seed body.
	if err := d.UpsertSetting(&models.SystemSetting{Key: "event_rules_seed_version", Value: "2"}); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	d.EnsureDefaultRules()
	if v, _ := d.GetSettingValue("state_engine_owns"); v != "vpn_tunnel_down" {
		t.Errorf("ownership flag clobbered on bump: got %q, want operator's %q", v, "vpn_tunnel_down")
	}
}
