package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestCheckSSHHostKeyChanged verifies the alert is CRITICAL, device-scoped, and
// cooldown-gated to fire once per change window.
func TestCheckSSHHostKeyChanged(t *testing.T) {
	am, db := newTestManager(t)
	dev := &models.Device{Name: "fw1", IPAddress: "10.0.0.1"}
	dev.ID = 1

	if err := am.CheckSSHHostKeyChanged(dev, "SHA256:old", "SHA256:new"); err != nil {
		t.Fatalf("CheckSSHHostKeyChanged: %v", err)
	}

	var alerts []models.Alert
	if err := db.Gorm().Where("alert_type = ?", "SSH_HOST_KEY_CHANGED").Find(&alerts).Error; err != nil {
		t.Fatalf("query alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d SSH_HOST_KEY_CHANGED alerts, want 1", len(alerts))
	}
	if alerts[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", alerts[0].Severity)
	}
	if alerts[0].DeviceID != 1 {
		t.Errorf("device id = %d, want 1", alerts[0].DeviceID)
	}

	// A second change within the cooldown window is gated (the server also
	// re-pins, so in practice it fires once; this pins the cooldown guard too).
	if err := am.CheckSSHHostKeyChanged(dev, "SHA256:old", "SHA256:new"); err != nil {
		t.Fatalf("CheckSSHHostKeyChanged (2): %v", err)
	}
	if err := db.Gorm().Where("alert_type = ?", "SSH_HOST_KEY_CHANGED").Find(&alerts).Error; err != nil {
		t.Fatalf("query alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("after second call within cooldown: %d alerts, want still 1", len(alerts))
	}
}
