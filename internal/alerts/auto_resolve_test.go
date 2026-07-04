package alerts

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// newTestManager builds an AlertManager backed by an in-memory SQLite DB and a
// no-op notifier (empty config → SendAlert sends nothing). The policy cache is
// left unloaded, so resolveAlertConfig falls back to global defaults.
func newTestManager(t *testing.T) (*AlertManager, *database.Database) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	am := NewAlertManager(cfg, notifier.NewNotifier(cfg), db)
	return am, db
}

func seedAlert(t *testing.T, db *database.Database, a *models.Alert) {
	t.Helper()
	if err := db.Gorm().Create(a).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
}

func getAlert(t *testing.T, db *database.Database, id uint) models.Alert {
	t.Helper()
	var got models.Alert
	if err := db.Gorm().First(&got, id).Error; err != nil {
		t.Fatalf("query alert id=%d: %v", id, err)
	}
	return got
}

// countResolvedCompanions counts the companion recovery records. Every companion
// is created with MetricName "recovery" (an exact discriminator, unlike a LIKE on
// the _RESOLVED suffix), so this is unambiguous.
func countResolvedCompanions(t *testing.T, db *database.Database) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.Alert{}).
		Where("metric_name = ?", "recovery").
		Count(&n).Error; err != nil {
		t.Fatalf("count companions: %v", err)
	}
	return n
}

// TestSendRecovery_PreciseLinking is the headline guard for this feature: a
// recovery for ONE interface must resolve only that interface's alert, never
// every INTERFACE_DOWN alert on the device. Pre-fix the WHERE clause scoped by
// device_id + alert_type only, so both rows resolved — the "wrong grouping" bug.
func TestSendRecovery_PreciseLinking(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()

	port1 := models.Alert{
		DeviceID: 1, AlertType: "INTERFACE_DOWN", MetricName: "interface_port1",
		Message: "Interface port1 is down", Timestamp: now, Acknowledged: false,
	}
	port2 := models.Alert{
		DeviceID: 1, AlertType: "INTERFACE_DOWN", MetricName: "interface_port2",
		Message: "Interface port2 is down", Timestamp: now, Acknowledged: false,
	}
	seedAlert(t, db, &port1)
	seedAlert(t, db, &port2)

	// port1 recovers. Mark it active (simulating it fired this process), then
	// drive the recovery exactly as CheckInterfaceStatus does.
	am.activeAlerts["iface_down_1_port1"] = true
	am.sendRecovery("iface_down_1_port1", "INTERFACE_DOWN", "interface_port1",
		"Interface port1 is back up", 1, nil)

	got1 := getAlert(t, db, port1.ID)
	if got1.ResolvedAt == nil {
		t.Errorf("port1: resolved_at is nil, want set")
	}
	if !got1.Acknowledged {
		t.Errorf("port1: acknowledged = false, want true")
	}

	got2 := getAlert(t, db, port2.ID)
	if got2.ResolvedAt != nil {
		t.Errorf("port2: resolved_at = %v, want nil (port2 is still down — must NOT be resolved by port1's recovery)", got2.ResolvedAt)
	}
	if got2.Acknowledged {
		t.Errorf("port2: acknowledged = true, want false (must be untouched)")
	}
}

// TestSendRecovery_AutoAcknowledge verifies the auto-clear semantics: on
// resolution the original alert is acknowledged (so it leaves the NOC's default
// open queue) with an "Auto-resolved:" note, while resolved_at is retained.
func TestSendRecovery_AutoAcknowledge(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()

	off := models.Alert{
		DeviceID: 5, AlertType: "DEVICE_OFFLINE", MetricName: "device_status",
		Message: "Device r1 is offline", Timestamp: now, Acknowledged: false,
	}
	seedAlert(t, db, &off)

	am.activeAlerts["device_offline_5"] = true
	am.sendRecovery("device_offline_5", "DEVICE_OFFLINE", "device_status",
		"Device r1 (10.0.0.1) is back online", 5, nil)

	got := getAlert(t, db, off.ID)
	if got.ResolvedAt == nil {
		t.Errorf("resolved_at is nil, want set")
	}
	if !got.Acknowledged {
		t.Errorf("acknowledged = false, want true")
	}
	if got.AcknowledgedAt == nil {
		t.Errorf("acknowledged_at is nil, want set")
	}
	if !strings.HasPrefix(got.Notes, "Auto-resolved:") {
		t.Errorf("notes = %q, want prefix %q", got.Notes, "Auto-resolved:")
	}

	// A companion DEVICE_OFFLINE_RESOLVED record should exist (was active).
	if n := countResolvedCompanions(t, db); n != 1 {
		t.Errorf("companion _RESOLVED rows = %d, want 1", n)
	}
}

// TestCheckDeviceOnline_RestartOrphan verifies restart robustness: even when the
// poller lost its in-memory activeAlerts (e.g. it restarted), an orphaned open
// DEVICE_OFFLINE alert is still auto-resolved in the DB. But because the alert
// was NOT active in this process, NO companion _RESOLVED record / notification
// is emitted (a cold resolve clears the ticket silently).
func TestCheckDeviceOnline_RestartOrphan(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()

	off := models.Alert{
		DeviceID: 7, AlertType: "DEVICE_OFFLINE", MetricName: "device_status",
		Message: "Device r2 is offline", Timestamp: now, Acknowledged: false,
	}
	seedAlert(t, db, &off)

	// activeAlerts is empty — simulates a poller that restarted after the
	// offline alert was raised.
	am.CheckDeviceOnline(&models.Device{ID: 7, Name: "r2", IPAddress: "10.0.0.2"})

	got := getAlert(t, db, off.ID)
	if got.ResolvedAt == nil {
		t.Errorf("resolved_at is nil, want set (orphaned alert must still auto-resolve after restart)")
	}
	if !got.Acknowledged {
		t.Errorf("acknowledged = false, want true")
	}
	if n := countResolvedCompanions(t, db); n != 0 {
		t.Errorf("companion _RESOLVED rows = %d, want 0 (cold resolve must not notify or record a companion)", n)
	}
}

// TestSendRecovery_Idempotent verifies a repeated up-signal (recovery loops run
// every poll) does not re-resolve or create duplicate companions.
func TestSendRecovery_Idempotent(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()

	off := models.Alert{
		DeviceID: 9, AlertType: "DEVICE_OFFLINE", MetricName: "device_status",
		Message: "Device r3 is offline", Timestamp: now, Acknowledged: false,
	}
	seedAlert(t, db, &off)

	am.activeAlerts["device_offline_9"] = true
	am.sendRecovery("device_offline_9", "DEVICE_OFFLINE", "device_status", "back online", 9, nil)
	// Second call: activeAlerts was cleared by the first call, and the row is
	// already resolved+acked, so the DB update matches nothing.
	am.sendRecovery("device_offline_9", "DEVICE_OFFLINE", "device_status", "back online", 9, nil)

	if n := countResolvedCompanions(t, db); n != 1 {
		t.Errorf("companion _RESOLVED rows = %d, want 1 (second recovery must not create another)", n)
	}
}

// TestSendRecovery_PerDeviceBackwardCompat confirms per-device alert types
// (metric_name=device_status) still resolve exactly their own row after the
// metric_name discriminator was added.
func TestSendRecovery_PerDeviceBackwardCompat(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()

	off := models.Alert{
		DeviceID: 3, AlertType: "DEVICE_OFFLINE", MetricName: "device_status",
		Message: "Device offline", Timestamp: now, Acknowledged: false,
	}
	seedAlert(t, db, &off)

	am.activeAlerts["device_offline_3"] = true
	am.sendRecovery("device_offline_3", "DEVICE_OFFLINE", "device_status", "back online", 3, nil)

	got := getAlert(t, db, off.ID)
	if got.ResolvedAt == nil || !got.Acknowledged {
		t.Errorf("device_status recovery did not resolve+ack its own row: resolved_at=%v acked=%v", got.ResolvedAt, got.Acknowledged)
	}
}
