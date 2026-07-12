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

	// Ownership flag must NOT include traffic_spike or any trap type.
	owned, _ := d.GetSettingValue("state_engine_owns")
	for _, ev := range []string{"traffic_spike", "HA_MEMBER_DOWN", "LINK_DOWN"} {
		if strings.Contains(owned, ev) {
			t.Errorf("state_engine_owns %q must NOT contain %q (Phase 3 is inert)", owned, ev)
		}
	}
}

// TestEnsureDefaultRules_NoResurrectOnBump verifies the seed-generation guard: an
// operator-deleted OLDER-generation seed is not recreated when a newer generation
// is applied. Simulated by pre-setting the marker to the state generation and
// deleting a syslog (gen 1) seed, then running EnsureDefaultRules (which applies
// gen 3): the deleted gen-1 rule must stay gone; the gen-3 metric rules appear.
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
