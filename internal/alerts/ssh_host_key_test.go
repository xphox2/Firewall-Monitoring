package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestCheckSSHHostKeyChanged verifies severity classification: an unexplained
// new key is CRITICAL, a key correlated with an HA failover is WARNING, and the
// per-(device,fingerprint) cooldown gates a repeat of the same key.
func TestCheckSSHHostKeyChanged(t *testing.T) {
	am, db := newTestManager(t)
	dev := &models.Device{Name: "fw1", IPAddress: "10.0.0.1"}
	dev.ID = 1

	alertsFor := func(severity string) int64 {
		t.Helper()
		var n int64
		db.Gorm().Model(&models.Alert{}).
			Where("alert_type = ? AND severity = ?", "SSH_HOST_KEY_CHANGED", severity).Count(&n)
		return n
	}

	// Unexplained new key -> CRITICAL.
	if err := am.CheckSSHHostKeyChanged(dev, "SHA256:aaa", false); err != nil {
		t.Fatalf("CheckSSHHostKeyChanged: %v", err)
	}
	if got := alertsFor("critical"); got != 1 {
		t.Fatalf("critical alerts = %d, want 1", got)
	}

	// Same fingerprint again within cooldown -> gated.
	if err := am.CheckSSHHostKeyChanged(dev, "SHA256:aaa", false); err != nil {
		t.Fatalf("CheckSSHHostKeyChanged (repeat): %v", err)
	}
	if got := alertsFor("critical"); got != 1 {
		t.Errorf("after repeat within cooldown: critical alerts = %d, want still 1", got)
	}

	// A different new key correlated with an HA failover -> WARNING.
	if err := am.CheckSSHHostKeyChanged(dev, "SHA256:bbb", true); err != nil {
		t.Fatalf("CheckSSHHostKeyChanged (ha): %v", err)
	}
	if got := alertsFor("warning"); got != 1 {
		t.Errorf("warning alerts = %d, want 1 (HA failover)", got)
	}
	if got := alertsFor("critical"); got != 1 {
		t.Errorf("critical alerts = %d, want still 1", got)
	}
}
