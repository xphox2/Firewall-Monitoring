package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestCheckProbeDataFlow_SkipsDecommissioned_M28 pins the 2026-07-01 audit M28
// fix: DecommissionProbe deliberately keeps approval_status='approved' (to
// preserve telemetry attribution), so GetApprovedProbes still returns retired
// probes — whose LastDataReceived is frozen by design. Pre-fix, the documented
// soft-decommission path fired PROBE_DATA_LAG on every cooldown expiry,
// forever. An active lagging probe (the positive control) must still alert.
func TestCheckProbeDataFlow_SkipsDecommissioned_M28(t *testing.T) {
	am, db := newTestManager(t)
	am.config.Alerts.ProbeDataLagAlertMinutes = 60

	stale := time.Now().Add(-3 * time.Hour) // far past the 60-min threshold
	now := time.Now().UTC()

	// Decommissioned probe: approved (by design) but retired — must be skipped.
	// Distinct registration keys — the column has a unique index.
	dec := &models.Probe{Name: "retired-probe", RegistrationKey: "m28-key-retired", ApprovalStatus: "approved", LastDataReceived: stale}
	if err := db.Gorm().Create(dec).Error; err != nil {
		t.Fatalf("seed decommissioned: %v", err)
	}
	if err := db.Gorm().Model(dec).Updates(map[string]interface{}{
		"decommissioned_at": now, "enabled": false, "status": "offline",
	}).Error; err != nil {
		t.Fatalf("decommission: %v", err)
	}

	// Active lagging probe: the positive control that must still alert.
	act := &models.Probe{Name: "lagging-probe", RegistrationKey: "m28-key-lagging", ApprovalStatus: "approved", LastDataReceived: stale}
	if err := db.Gorm().Create(act).Error; err != nil {
		t.Fatalf("seed active: %v", err)
	}

	if err := am.CheckProbeDataFlow(); err != nil {
		t.Fatalf("CheckProbeDataFlow: %v", err)
	}

	var alerts []models.Alert
	if err := db.Gorm().Where("alert_type = ?", "PROBE_DATA_LAG").Find(&alerts).Error; err != nil {
		t.Fatalf("query alerts: %v", err)
	}
	for _, a := range alerts {
		if a.ProbeID != nil && *a.ProbeID == dec.ID {
			t.Errorf("PROBE_DATA_LAG fired for the decommissioned probe — the retired-probe alert storm is back")
		}
	}
	found := false
	for _, a := range alerts {
		if a.ProbeID != nil && *a.ProbeID == act.ID {
			found = true
		}
	}
	if !found {
		t.Error("PROBE_DATA_LAG did not fire for the active lagging probe — the check itself broke")
	}
}
