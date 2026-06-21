package handlers

import (
	"testing"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestProcessObservedHostKeys characterizes the server-side SSH host-key
// change-detection rule: first observation pins (no alert), an unchanged key is
// a no-op, a changed key fires exactly one critical alert and re-pins, and a
// device not assigned to the reporting probe is ignored.
func TestProcessObservedHostKeys(t *testing.T) {
	h, db := setupTestHandler(t)
	cfg := &config.Config{}
	h.SetAlertManager(alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db))
	probe, device := setupProbeAndDevice(t, db)

	reload := func() models.Device {
		t.Helper()
		var d models.Device
		if err := db.Gorm().First(&d, device.ID).Error; err != nil {
			t.Fatalf("reload device: %v", err)
		}
		return d
	}
	countAlerts := func() int64 {
		t.Helper()
		var n int64
		db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SSH_HOST_KEY_CHANGED").Count(&n)
		return n
	}

	// 1. First observation pins the fingerprint, no alert.
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:aaa"})
	if got := reload().SSHHostKey; got != "SHA256:aaa" {
		t.Fatalf("after first observation SSHHostKey = %q, want SHA256:aaa", got)
	}
	if countAlerts() != 0 {
		t.Errorf("first observation must not alert, got %d", countAlerts())
	}

	// 2. Same fingerprint is a no-op.
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:aaa"})
	if countAlerts() != 0 {
		t.Errorf("unchanged key must not alert, got %d", countAlerts())
	}

	// 3. Changed fingerprint fires exactly one alert and re-pins.
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:bbb"})
	if got := reload().SSHHostKey; got != "SHA256:bbb" {
		t.Errorf("after change SSHHostKey = %q, want SHA256:bbb (re-pinned)", got)
	}
	if countAlerts() != 1 {
		t.Errorf("changed key must fire exactly one alert, got %d", countAlerts())
	}

	// 4. A device not assigned to this probe is ignored.
	other := &models.Device{Name: "other", IPAddress: "10.9.9.9"} // no ProbeID
	if err := db.Gorm().Create(other).Error; err != nil {
		t.Fatalf("create other device: %v", err)
	}
	h.processObservedHostKeys(probe.ID, map[uint]string{other.ID: "SHA256:xxx"})
	var od models.Device
	if err := db.Gorm().First(&od, other.ID).Error; err != nil {
		t.Fatalf("reload other: %v", err)
	}
	if od.SSHHostKey != "" {
		t.Errorf("device not owned by the probe must be ignored, but SSHHostKey = %q", od.SSHHostKey)
	}
}
