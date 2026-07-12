package alerts

import (
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestCheckInterfaceStatus_FiresSavesAndCooldown characterizes the batch
// fire→dispatch→cooldown path that dispatchFired refactors: a down interface
// fires exactly one INTERFACE_DOWN alert (saved via the post-unlock dispatch
// loop), and an identical check within the cooldown window is gated so no
// second alert is written.
func TestCheckInterfaceStatus_FiresSavesAndCooldown(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Alerts.InterfaceDownAlert = true // legacy toggle; required when the policy cache is unloaded
	am := NewAlertManager(cfg, notifier.NewNotifier(cfg), db)

	// The interface must have been observed UP before a down is treated as an
	// outage (ever-up gate) — otherwise it's an enabled-but-never-cabled port.
	am.everUp[ifaceDownKey(1, "port1")] = true

	ifaces := []models.InterfaceStats{
		{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: "up"},
	}

	count := func() int64 {
		t.Helper()
		var n int64
		if err := db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "INTERFACE_DOWN").Count(&n).Error; err != nil {
			t.Fatalf("count INTERFACE_DOWN: %v", err)
		}
		return n
	}

	if err := am.CheckInterfaceStatus(ifaces, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus (1): %v", err)
	}
	if got := count(); got != 1 {
		t.Fatalf("after first check: %d INTERFACE_DOWN alerts, want 1", got)
	}

	// Second identical check is inside the 5-minute cooldown → gated, no new row.
	if err := am.CheckInterfaceStatus(ifaces, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus (2): %v", err)
	}
	if got := count(); got != 1 {
		t.Fatalf("after second check within cooldown: %d alerts, want still 1", got)
	}
}
