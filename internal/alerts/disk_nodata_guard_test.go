package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

func setDiskPolicy(am *AlertManager, threshold, clear float64) {
	policy := models.AlertPolicy{
		ID: 1, Name: "test", IsDefault: true,
		Rules: []models.AlertRule{{
			PolicyID: 1, AlertType: models.AlertTypeDiskHigh,
			Enabled: true, Threshold: threshold, ClearThreshold: clear,
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

func openDiskAlerts(t *testing.T, am *AlertManager, deviceID uint) int64 {
	t.Helper()
	var n int64
	if err := am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND resolved_at IS NULL AND metric_name <> ?",
			deviceID, models.AlertTypeDiskHigh, "recovery").
		Count(&n).Error; err != nil {
		t.Fatalf("count open disk alerts: %v", err)
	}
	return n
}

// TestCheckSystemStatus_ZeroDiskDoesNotAutoResolve pins the no-data guard: a
// system_status row with disk_usage=0 — the FortiGate SSH `diagnose sys
// performance` row never carries disk — must NOT auto-resolve a genuine open
// DISK_HIGH when it lands as the newest sample. Recovery only fires on a real
// (>0) reading below the clear band.
func TestCheckSystemStatus_ZeroDiskDoesNotAutoResolve(t *testing.T) {
	am, _ := newTestManager(t)
	setDiskPolicy(am, 90, 80)
	const dev = 7

	// Fire DISK_HIGH at 95%.
	if err := am.CheckSystemStatus(&models.SystemStatus{DeviceID: dev, DiskUsage: 95}, nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	if n := openDiskAlerts(t, am, dev); n != 1 {
		t.Fatalf("after fire: %d open disk alert(s), want 1", n)
	}

	// A partial row (disk_usage=0, other metrics healthy) must NOT resolve it.
	if err := am.CheckSystemStatus(&models.SystemStatus{DeviceID: dev, DiskUsage: 0, CPUUsage: 20, MemoryUsage: 40}, nil); err != nil {
		t.Fatalf("zero-disk row: %v", err)
	}
	if n := openDiskAlerts(t, am, dev); n != 1 {
		t.Fatalf("after zero-disk row: %d open, want 1 (no-data must not auto-resolve)", n)
	}

	// A genuine recovery (40% < clear band) resolves it.
	if err := am.CheckSystemStatus(&models.SystemStatus{DeviceID: dev, DiskUsage: 40}, nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n := openDiskAlerts(t, am, dev); n != 0 {
		t.Fatalf("after genuine recovery: %d open, want 0", n)
	}
}
