package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestCheckEscalations_RetiredDeviceNotEscalated: retiring a device
// acknowledges its open alerts (database.RetireDevice), so the escalation
// engine — which re-notifies every unacknowledged alert of the last 24h —
// stops for that device. The control alert on a live device escalates as
// before, proving the pass ran.
func TestCheckEscalations_RetiredDeviceNotEscalated(t *testing.T) {
	am, db := newTestManager(t)

	policy := models.AlertPolicy{
		ID: 1, Name: "chain", IsDefault: true,
		EscalationSteps: `[{"after_minutes":5,"channels":["slack"]}]`,
	}
	am.policyCache = PolicyCache{
		policies:      []models.AlertPolicy{policy},
		policyByID:    map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		defaultPolicy: &policy,
		loaded:        true,
	}

	retired := &models.Device{Name: "retired-fw", IPAddress: "10.0.0.1", Enabled: true}
	live := &models.Device{Name: "live-fw", IPAddress: "10.0.0.2", Enabled: true}
	for _, d := range []*models.Device{retired, live} {
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}
	pid := uint(1)
	retiredAlert := models.Alert{
		Timestamp: time.Now().Add(-20 * time.Minute), DeviceID: retired.ID,
		AlertType: "DEVICE_OFFLINE", Severity: "critical", MetricName: "device_status",
		Message: "Device retired-fw (10.0.0.1) is offline", PolicyID: &pid,
	}
	liveAlert := models.Alert{
		Timestamp: time.Now().Add(-20 * time.Minute), DeviceID: live.ID,
		AlertType: "DEVICE_OFFLINE", Severity: "critical", MetricName: "device_status",
		Message: "Device live-fw (10.0.0.2) is offline", PolicyID: &pid,
	}
	seedAlert(t, db, &retiredAlert)
	seedAlert(t, db, &liveAlert)

	if err := db.RetireDevice(retired.ID); err != nil {
		t.Fatalf("RetireDevice: %v", err)
	}

	am.CheckEscalations()

	if got := getAlert(t, db, retiredAlert.ID); got.EscalationCount != 0 || !got.Acknowledged {
		t.Errorf("retired device's alert escalated: count=%d acknowledged=%v", got.EscalationCount, got.Acknowledged)
	}
	if got := getAlert(t, db, liveAlert.ID); got.EscalationCount != 1 {
		t.Errorf("control alert on the live device: EscalationCount = %d, want 1", got.EscalationCount)
	}
}
