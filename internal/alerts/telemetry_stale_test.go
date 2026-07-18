package alerts

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestCheckTelemetryStale_MaintenanceSuppresses: inside a maintenance window
// the alert row is still written (visibility) but saved Suppressed — no 3am
// notification for planned work.
func TestCheckTelemetryStale_MaintenanceSuppresses(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	installPolicyCache(am, nil, []models.MaintenanceWindow{{
		Name: "planned", StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour), SuppressAll: true,
	}})

	dev := &models.Device{Name: "fw-m", IPAddress: "10.9.1.1"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := am.CheckTelemetryStale(dev, "no system vitals for 90m"); err != nil {
		t.Fatalf("CheckTelemetryStale: %v", err)
	}

	var alert models.Alert
	if err := db.Gorm().Where("alert_type = ? AND device_id = ?", "TELEMETRY_STALE", dev.ID).First(&alert).Error; err != nil {
		t.Fatalf("alert row missing: %v", err)
	}
	if !alert.Suppressed {
		t.Error("TELEMETRY_STALE inside a maintenance window must be saved Suppressed")
	}
	if !strings.Contains(alert.Message, "no system vitals for 90m") {
		t.Errorf("detail not embedded in message: %s", alert.Message)
	}
}

// TestCheckTelemetryStale_DisabledPolicyNoRecoveryNoise (LC-12 parity with
// CheckDeviceOffline; re-pinned on the v48 toggle chain): with TELEMETRY_STALE
// toggled Off in the Default event profile, the check must produce NO alert
// row, NO in-memory active state, and NO "recovered" companion when the
// condition later clears.
func TestCheckTelemetryStale_DisabledPolicyNoRecoveryNoise(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{ID: 1, Name: "p", IsDefault: true}
	installPolicyCache(am, &policy, nil)
	installDefaultProfileToggles(am, map[models.AlertType]bool{models.AlertTypeTelemetryStale: false})

	dev := &models.Device{Name: "fw-d", IPAddress: "10.9.1.4"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := am.CheckTelemetryStale(dev, "no system vitals for 90m"); err != nil {
		t.Fatalf("CheckTelemetryStale: %v", err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Count(&n)
	if n != 0 {
		t.Fatalf("disabled TELEMETRY_STALE saved %d alert rows, want 0", n)
	}
	am.mu.RLock()
	active := am.activeAlerts[fmt.Sprintf("telemetry_stale_%d", dev.ID)]
	am.mu.RUnlock()
	if active {
		t.Fatal("disabled TELEMETRY_STALE must not mark the key active")
	}

	am.CheckTelemetryRecovered(dev)
	var companions int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ?", "TELEMETRY_STALE_RESOLVED").Count(&companions)
	if companions != 0 {
		t.Fatalf("companion rows = %d, want 0 (no 'recovered' noise for a disabled type)", companions)
	}
}

// TestCheckTelemetryStale_RestartSafeDedup: an open row from a previous
// process blocks a re-fire inside the cooldown even with empty in-memory
// state (dbCooldownActive).
func TestCheckTelemetryStale_RestartSafeDedup(t *testing.T) {
	am, db := newTestManager(t)
	installPolicyCache(am, nil, nil)

	dev := &models.Device{Name: "fw-r", IPAddress: "10.9.1.2"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := am.CheckTelemetryStale(dev, "no system vitals for 90m"); err != nil {
		t.Fatalf("first fire: %v", err)
	}

	// Simulate a poller restart: fresh manager, same DB.
	am2, _ := newTestManager(t)
	am2.db = am.db
	installPolicyCache(am2, nil, nil)
	if err := am2.CheckTelemetryStale(dev, "no system vitals for 95m"); err != nil {
		t.Fatalf("post-restart fire: %v", err)
	}

	var n int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ?", "TELEMETRY_STALE", dev.ID).Count(&n)
	if n != 1 {
		t.Errorf("TELEMETRY_STALE rows after restart re-check = %d, want 1 (dbCooldownActive dedup)", n)
	}
}

// TestCheckTelemetryRecovered_GatesDBWork: for a device with no active alert
// the recovery runs its one-shot cold sweep, then subsequent calls are free —
// the healthy steady state must not add per-cycle UPDATEs.
func TestCheckTelemetryRecovered_GatesDBWork(t *testing.T) {
	am, db := newTestManager(t)
	installPolicyCache(am, nil, nil)

	dev := &models.Device{Name: "fw-g", IPAddress: "10.9.1.3"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Seed an open row as if left over from before a restart.
	open := models.Alert{
		DeviceID: dev.ID, AlertType: "TELEMETRY_STALE", MetricName: "telemetry",
		Message: "stale", Timestamp: time.Now().Add(-time.Hour),
	}
	if err := db.Gorm().Create(&open).Error; err != nil {
		t.Fatalf("seed open alert: %v", err)
	}

	// First call: cold sweep resolves the leftover row, silently (no companion —
	// the alert was never active in this process).
	am.CheckTelemetryRecovered(dev)
	var reloaded models.Alert
	db.Gorm().First(&reloaded, open.ID)
	if reloaded.ResolvedAt == nil {
		t.Error("cold sweep must resolve the leftover open row")
	}
	var companions int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ?", "TELEMETRY_STALE_RESOLVED", dev.ID).Count(&companions)
	if companions != 0 {
		t.Errorf("cold sweep wrote %d _RESOLVED companions, want 0", companions)
	}

	// Second call with nothing active: must be a pure no-op (gate short-circuits).
	swept := am.telemetryColdSwept[dev.ID]
	if !swept {
		t.Fatal("cold-sweep marker not set")
	}
	am.CheckTelemetryRecovered(dev) // would re-run 2 UPDATEs if ungated; behaviorally a no-op
}
