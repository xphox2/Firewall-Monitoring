package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestResolveAlertConfig_CooldownFloor_M3 pins the 2026-07-01 audit M3 fix:
// a policy (or rule) with CooldownMinutes=0 must NOT zero the effective
// cooldown — that made now.Sub(last) > 0 always true, a per-cycle alert storm.
// 0 now inherits the per-type default; SFLOW_* types default to >= the 15-min
// detection window so overlapping re-detections and persistent conditions don't
// re-notify every cycle.
func TestResolveAlertConfig_CooldownFloor_M3(t *testing.T) {
	am, db := newTestManager(t)

	// Before any policy cache is loaded, SFLOW_* types resolve to the per-type
	// default (>= the 15-min detection window). Deterministic — no policy can
	// override it on this path.
	sf := am.resolveAlertConfig(0, nil, "SFLOW_PORTSCAN")
	if sf.CooldownMinutes < 15 {
		t.Errorf("SFLOW_PORTSCAN cooldown = %d, want >= 15 (>= the 15-min detection window)", sf.CooldownMinutes)
	}

	// A default policy whose cooldown is 0 (the storm-enabling misconfig). The
	// model has a `default:5` column tag, so a plain Create can't persist 0 —
	// force it with an explicit Update (mirrors the real misconfig where the
	// column ends up 0).
	pol := &models.AlertPolicy{Name: "p0", IsDefault: true}
	if err := db.Gorm().Create(pol).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := db.Gorm().Model(pol).Update("cooldown_minutes", 0).Error; err != nil {
		t.Fatalf("force cooldown 0: %v", err)
	}
	am.RefreshThresholds(db.Gorm())

	// A CooldownMinutes=0 policy must not produce a 0 effective cooldown
	// (pre-fix: 0 → now.Sub(last) > 0 always true → per-cycle storm).
	got := am.resolveAlertConfig(0, nil, "CPU_HIGH")
	if got.CooldownMinutes <= 0 {
		t.Errorf("CPU_HIGH cooldown = %d, want > 0 (a 0-policy must inherit the default, not disable the cooldown)", got.CooldownMinutes)
	}
}

// TestDefaultCooldownForType_M3 is a focused unit check of the per-type default.
func TestDefaultCooldownForType_M3(t *testing.T) {
	if got := defaultCooldownForType("SFLOW_CLEARTEXT"); got < 15 {
		t.Errorf("SFLOW cooldown default = %d, want >= 15", got)
	}
	if got := defaultCooldownForType("CPU_HIGH"); got != 5 {
		t.Errorf("non-SFLOW cooldown default = %d, want 5", got)
	}
}
