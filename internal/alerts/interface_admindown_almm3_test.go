package alerts

import (
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestCheckInterfaceStatus_AdminDownResolvesStuckAlert is the AUDIT AL-M3
// regression: an INTERFACE_DOWN fires on an oper-down/admin-up link, then an
// operator administratively disables the port (admin=down). Previously neither
// the fire path (needs admin=up) nor the up-recovery path (needs oper=up) would
// touch it, so the alert stayed stuck open forever. The admin-down branch must
// resolve the open alert.
func TestCheckInterfaceStatus_AdminDownResolvesStuckAlert(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Alerts.InterfaceDownAlert = true
	am := NewAlertManager(cfg, notifier.NewNotifier(cfg), db)

	am.everUp[ifaceDownKey(1, "port1")] = true

	openCount := func() int64 {
		t.Helper()
		var n int64
		if err := db.Gorm().Model(&models.Alert{}).
			Where("alert_type = ? AND resolved_at IS NULL", "INTERFACE_DOWN").
			Count(&n).Error; err != nil {
			t.Fatalf("count open INTERFACE_DOWN: %v", err)
		}
		return n
	}

	// 1. Link is oper-down / admin-up → fires and stays open.
	down := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: "up"}}
	if err := am.CheckInterfaceStatus(down, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus (down): %v", err)
	}
	if got := openCount(); got != 1 {
		t.Fatalf("after down: %d open INTERFACE_DOWN, want 1", got)
	}

	// 2. A partial SNMP walk returns oper-down but leaves AdminStatus empty.
	// This must NOT be read as "administratively disabled" — resolving here
	// would false-clear a genuine ongoing outage. The alert stays open.
	partial := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: ""}}
	if err := am.CheckInterfaceStatus(partial, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus (partial): %v", err)
	}
	if got := openCount(); got != 1 {
		t.Fatalf("after empty-AdminStatus: %d open INTERFACE_DOWN, want 1 (must not false-resolve)", got)
	}

	// 3. Operator admin-disables the port (admin=down, oper=down) → resolve.
	adminDown := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: "down"}}
	if err := am.CheckInterfaceStatus(adminDown, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus (admin-down): %v", err)
	}
	if got := openCount(); got != 0 {
		t.Fatalf("after admin-down: %d open INTERFACE_DOWN, want 0 (stuck-alert bug)", got)
	}
}
