package handlers

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestProcessObservedHostKeys characterizes the server-side SSH host-key rule:
// first key pins silently; a known key is a no-op; an unexplained new key is
// CRITICAL and added to the set; a key already in the set (e.g. an HA failover
// back to a previously-seen member) is silent; a new key correlated with a
// recent HA failover is WARNING; and a device not owned by the probe is ignored.
func TestProcessObservedHostKeys(t *testing.T) {
	h, db := setupTestHandler(t)
	cfg := &config.Config{}
	h.SetAlertManager(alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db))
	probe, device := setupProbeAndDevice(t, db)

	keys := func() string {
		t.Helper()
		var d models.Device
		if err := db.Gorm().First(&d, device.ID).Error; err != nil {
			t.Fatalf("reload device: %v", err)
		}
		return d.SSHHostKeys
	}
	count := func(severity string) int64 {
		t.Helper()
		var n int64
		db.Gorm().Model(&models.Alert{}).
			Where("alert_type = ? AND severity = ?", "SSH_HOST_KEY_CHANGED", severity).Count(&n)
		return n
	}

	// 1. First observation pins silently (TOFU).
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:aaa"})
	if got := keys(); got != "SHA256:aaa" {
		t.Fatalf("after first observation keys = %q, want SHA256:aaa", got)
	}
	if count("critical")+count("warning") != 0 {
		t.Errorf("first observation must not alert")
	}

	// 2. Same key -> no-op.
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:aaa"})
	if count("critical")+count("warning") != 0 {
		t.Errorf("known key must not alert")
	}

	// 3. New key, no HA failover -> CRITICAL, added to the set.
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:bbb"})
	if got := keys(); !strings.Contains(got, "SHA256:aaa") || !strings.Contains(got, "SHA256:bbb") {
		t.Errorf("set = %q, want both aaa and bbb", got)
	}
	if count("critical") != 1 {
		t.Errorf("unexplained new key: critical = %d, want 1", count("critical"))
	}

	// 4. Failover back to a previously-learned key -> silent (in the set).
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:aaa"})
	if count("critical") != 1 {
		t.Errorf("returning to a known key must not alert: critical = %d, want 1", count("critical"))
	}

	// 5. A new key correlated with a recent HA failover -> WARNING.
	//    Seed two distinct master serials within the window.
	db.Gorm().Create(&models.HAStatus{DeviceID: device.ID, Timestamp: time.Now().Add(-30 * time.Minute), MasterSerial: "FGT-A"})
	db.Gorm().Create(&models.HAStatus{DeviceID: device.ID, Timestamp: time.Now().Add(-5 * time.Minute), MasterSerial: "FGT-B"})
	h.processObservedHostKeys(probe.ID, map[uint]string{device.ID: "SHA256:ccc"})
	if count("warning") != 1 {
		t.Errorf("HA-correlated new key: warning = %d, want 1", count("warning"))
	}
	if count("critical") != 1 {
		t.Errorf("critical should be unchanged at 1, got %d", count("critical"))
	}

	// 6. A device not owned by the reporting probe is ignored.
	other := &models.Device{Name: "other", IPAddress: "10.9.9.9"}
	if err := db.Gorm().Create(other).Error; err != nil {
		t.Fatalf("create other device: %v", err)
	}
	h.processObservedHostKeys(probe.ID, map[uint]string{other.ID: "SHA256:xxx"})
	var od models.Device
	if err := db.Gorm().First(&od, other.ID).Error; err != nil {
		t.Fatalf("reload other: %v", err)
	}
	if od.SSHHostKeys != "" {
		t.Errorf("device not owned by the probe must be ignored, but keys = %q", od.SSHHostKeys)
	}
}
