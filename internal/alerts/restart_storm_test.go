package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// Regression suite for the 2026-06-23 audit H7 finding: AlertManager cooldown
// state (lastAlert/activeAlerts) is in-memory only, so a poller/API restart used
// to re-fire a fresh notification for every still-breaching condition. The fix
// is a DB-backed cooldown check (dbCooldownActive) at the send chokepoints that
// makes a restart transparent (Option A): within-cooldown duplicates suppressed,
// periodic reminders preserved.

func openAlert(deviceID uint, atype models.AlertType, metric string, ts time.Time) *models.Alert {
	return &models.Alert{DeviceID: deviceID, AlertType: atype, MetricName: metric, Timestamp: ts, Acknowledged: false}
}

func TestDBCooldownActive_WindowAndScope(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	seedAlert(t, db, openAlert(1, "DEVICE_OFFLINE", "device_status", now.Add(-2*time.Minute)))

	if !am.dbCooldownActive(1, "DEVICE_OFFLINE", "device_status", now, 5*time.Minute) {
		t.Error("want active: an open alert 2m old is within a 5m cooldown")
	}
	if am.dbCooldownActive(1, "DEVICE_OFFLINE", "device_status", now, 1*time.Minute) {
		t.Error("want inactive: an open alert 2m old is outside a 1m cooldown (reminder allowed)")
	}
	if am.dbCooldownActive(2, "DEVICE_OFFLINE", "device_status", now, 5*time.Minute) {
		t.Error("scope: a different device must not match")
	}
	if am.dbCooldownActive(1, "VPN_TUNNEL_DOWN", "device_status", now, 5*time.Minute) {
		t.Error("scope: a different alert_type must not match")
	}
	if am.dbCooldownActive(1, "DEVICE_OFFLINE", "iface_x", now, 5*time.Minute) {
		t.Error("scope: a different metric must not match")
	}
	if am.dbCooldownActive(1, "DEVICE_OFFLINE", "device_status", now, 0) {
		t.Error("a zero cooldown must be inactive (no suppression)")
	}
}

func TestDBCooldownActive_IgnoresResolved(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	a := openAlert(1, "DEVICE_OFFLINE", "device_status", now.Add(-1*time.Minute))
	ra := now
	a.ResolvedAt = &ra
	seedAlert(t, db, a)
	if am.dbCooldownActive(1, "DEVICE_OFFLINE", "device_status", now, 5*time.Minute) {
		t.Error("a resolved alert must not count as an active cooldown")
	}
}

// TestDispatchFired_SuppressesRestartStorm drives the end-to-end batch path
// (CheckInterfaceStatus → dispatchFired) with a fresh AlertManager (empty
// in-memory cooldown = a restart) while a still-open alert exists in the DB
// within the cooldown window. No second row may be written.
func TestDispatchFired_SuppressesRestartStorm(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Alerts.InterfaceDownAlert = true // legacy toggle; required when the policy cache is unloaded
	am := NewAlertManager(cfg, notifier.NewNotifier(cfg), db)

	now := time.Now()
	seedAlert(t, db, openAlert(1, "INTERFACE_DOWN", "interface_port1", now)) // pre-restart, fresh
	am.everUp[ifaceDownKey(1, "port1")] = true                               // seed models SeedEverUpFromDB: this link was up before the restart

	ifaces := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: "up"}}
	count := func() int64 {
		var n int64
		db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "INTERFACE_DOWN").Count(&n)
		return n
	}

	if err := am.CheckInterfaceStatus(ifaces, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus: %v", err)
	}
	if got := count(); got != 1 {
		t.Fatalf("restart storm not suppressed: %d INTERFACE_DOWN rows, want 1 (only the pre-existing open alert)", got)
	}
}

// TestDispatchFired_ReminderFiresAfterCooldown is the Option-A guard: once the
// cooldown elapses the reminder must still fire even across a restart, so a
// long-running issue is not silently forgotten.
func TestDispatchFired_ReminderFiresAfterCooldown(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Alerts.InterfaceDownAlert = true
	am := NewAlertManager(cfg, notifier.NewNotifier(cfg), db)

	now := time.Now()
	seedAlert(t, db, openAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-10*time.Minute))) // older than 5m cooldown
	am.everUp[ifaceDownKey(1, "port1")] = true                                                    // seed models SeedEverUpFromDB: this link was up before the restart

	ifaces := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: "up"}}
	if err := am.CheckInterfaceStatus(ifaces, nil); err != nil {
		t.Fatalf("CheckInterfaceStatus: %v", err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "INTERFACE_DOWN").Count(&n)
	if n != 2 {
		t.Fatalf("reminder did not fire after cooldown: %d rows, want 2 (old open + new reminder)", n)
	}
}
