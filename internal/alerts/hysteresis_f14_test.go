package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// setHysteresisPolicy installs a minimal policy cache whose default policy has
// one CPU rule with the given fire/clear thresholds.
func setHysteresisPolicy(am *AlertManager, threshold, clear float64) {
	policy := models.AlertPolicy{
		ID:        1,
		Name:      "test",
		IsDefault: true,
		Rules: []models.AlertRule{{
			PolicyID:       1,
			AlertType:      models.AlertTypeCPUHigh,
			Enabled:        true,
			Threshold:      threshold,
			ClearThreshold: clear,
		}},
	}
	am.policyCache = PolicyCache{
		policies:      []models.AlertPolicy{policy},
		policyByID:    map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		defaultPolicy: &policy,
		loaded:        true,
	}
}

// cpuStatus builds the minimal SystemStatus for a CPU reading.
func cpuStatus(deviceID uint, cpu float64) *models.SystemStatus {
	return &models.SystemStatus{DeviceID: deviceID, CPUUsage: cpu}
}

// openCPUAlerts counts unresolved CPU alerts for the device.
func openCPUAlerts(t *testing.T, am *AlertManager, deviceID uint) int64 {
	t.Helper()
	var n int64
	if err := am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND resolved_at IS NULL AND metric_name <> ?",
			deviceID, models.AlertTypeCPUHigh, "recovery").
		Count(&n).Error; err != nil {
		t.Fatalf("count open alerts: %v", err)
	}
	return n
}

// TestHysteresis_ClearBand_F14 pins the recovery band: with threshold 90 and
// clear 80, a fired alert stays open while the value hovers between the two
// and only resolves below the clear band.
func TestHysteresis_ClearBand_F14(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 80)
	const dev = 42

	// Fire at 95.
	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("CheckSystemStatus fire: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("after fire: %d open alerts, want 1", n)
	}

	// Hovering at 85 — below fire threshold, above the clear band: pre-F14
	// this auto-resolved (flap); now it must stay open.
	if err := am.CheckSystemStatus(cpuStatus(dev, 85), nil); err != nil {
		t.Fatalf("CheckSystemStatus hover: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("hovering in the band resolved the alert (flap not suppressed): %d open, want 1", n)
	}

	// Dropping to 79 — below the clear band: resolves.
	if err := am.CheckSystemStatus(cpuStatus(dev, 79), nil); err != nil {
		t.Fatalf("CheckSystemStatus recover: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("below clear band: %d open alerts, want 0", n)
	}
}

// TestHysteresis_Disabled_LegacyBehavior: ClearThreshold=0 recovers at the
// fire threshold exactly as before F14.
func TestHysteresis_Disabled_LegacyBehavior(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	const dev = 43

	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("after fire: %d open, want 1", n)
	}
	// 85 < 90 → legacy behavior resolves immediately.
	if err := am.CheckSystemStatus(cpuStatus(dev, 85), nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("legacy recovery at threshold broken: %d open, want 0", n)
	}
}

// TestHysteresis_ClearAboveThreshold_Ignored: a misconfigured clear band AT or
// ABOVE the fire threshold is ignored (never widens recovery upward).
func TestHysteresis_ClearAboveThreshold_Ignored(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 95) // nonsensical: clear above fire
	const dev = 44

	if err := am.CheckSystemStatus(cpuStatus(dev, 92), nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	// 89 < 90 (threshold) but 89 < 95 too — the band must clamp to the
	// threshold, so this RESOLVES (clear band never raises the recovery bar
	// above the fire threshold).
	if err := am.CheckSystemStatus(cpuStatus(dev, 89), nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("misconfigured clear band blocked recovery: %d open, want 0", n)
	}
}
