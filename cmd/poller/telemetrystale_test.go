package main

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// Shared fixture: an enabled, online, probe-assigned device — the only shape
// eligible for TELEMETRY_STALE. Rows are seeded per test.
func newStaleTestDevice(t *testing.T, p *Poller) *models.Device {
	t.Helper()
	_, db := p, p.db
	site := &models.Site{Name: "stale-site"}
	mustCreate(t, db, site)
	probe := &models.Probe{Name: "stale-probe", SiteID: site.ID, RegistrationKey: "k", ApprovalStatus: "approved"}
	mustCreate(t, db, probe)
	dev := &models.Device{Name: "fw-stale", IPAddress: "10.9.0.1", Enabled: true, Status: "online", ProbeID: &probe.ID}
	mustCreate(t, db, dev)
	return dev
}

// runCycles invokes checkRelayedTelemetry n times (each call = one monitoring
// cycle for the debounce counter).
func runCycles(p *Poller, devices []models.Device, n int, justFlipped map[uint]struct{}) {
	for i := 0; i < n; i++ {
		p.checkRelayedTelemetry(devices, telemetryStaleAfter, justFlipped)
	}
}

// TestTelemetryStale_FiresAfterDebounce: stale vitals + stale interfaces on an
// online probe device fire exactly one TELEMETRY_STALE after the 3-cycle
// debounce (not on cycles 1-2), and the message names both signals.
func TestTelemetryStale_FiresAfterDebounce(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	old := time.Now().Add(-2 * time.Hour) // > 60m default threshold, < 24h lookback
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: old, CPUUsage: 10})
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: old, Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})

	runCycles(p, []models.Device{*dev}, telemetryStaleCycles-1, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
		t.Fatalf("fired before debounce: %d alerts after %d cycles", got, telemetryStaleCycles-1)
	}

	runCycles(p, []models.Device{*dev}, 1, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("TELEMETRY_STALE alerts = %d, want 1", got)
	}

	var alert models.Alert
	if err := db.Gorm().Where("alert_type = ? AND device_id = ?", "TELEMETRY_STALE", dev.ID).First(&alert).Error; err != nil {
		t.Fatalf("load alert: %v", err)
	}
	for _, want := range []string{"system vitals", "interface stats", "still reachable"} {
		if !strings.Contains(alert.Message, want) {
			t.Errorf("alert message missing %q: %s", want, alert.Message)
		}
	}

	// Further cycles inside the 30-min cooldown must not duplicate.
	runCycles(p, []models.Device{*dev}, 2, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Errorf("cooldown dedup failed: %d alerts", got)
	}
}

// TestTelemetryStale_SignalBOnly: fresh vitals but stale interface stats (the
// FortiGate SSH-perf-alive/SNMP-dead case) still fires, naming only the
// interface signal.
func TestTelemetryStale_SignalBOnly(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Now().Add(-2 * time.Hour), Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})

	runCycles(p, []models.Device{*dev}, telemetryStaleCycles, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("TELEMETRY_STALE alerts = %d, want 1 (interface signal alone must fire)", got)
	}
	var alert models.Alert
	db.Gorm().Where("alert_type = ? AND device_id = ?", "TELEMETRY_STALE", dev.ID).First(&alert)
	if strings.Contains(alert.Message, "system vitals") {
		t.Errorf("message wrongly blames vitals (they are fresh): %s", alert.Message)
	}
	if !strings.Contains(alert.Message, "interface stats") {
		t.Errorf("message missing the stale interface signal: %s", alert.Message)
	}
}

// TestTelemetryStale_NotEligible: devices that must never fire — no telemetry
// rows at all (ping-only), disabled, offline, not probe-assigned, staleness
// under threshold, just flipped offline this cycle, and setting=0.
func TestTelemetryStale_NotEligible(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	seedStaleRows := func(p *Poller, devID uint) {
		mustCreate(t, p.db, &models.SystemStatus{DeviceID: devID, Timestamp: old, CPUUsage: 10})
		mustCreate(t, p.db, &models.InterfaceStats{DeviceID: devID, Timestamp: old, Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})
	}

	t.Run("ping-only-no-rows", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, nil)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired for a device with no telemetry rows: %d", got)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		seedStaleRows(p, dev.ID)
		dev.Enabled = false
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, nil)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired for a disabled device: %d", got)
		}
	})
	t.Run("offline", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		seedStaleRows(p, dev.ID)
		dev.Status = "offline"
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, nil)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired for an offline device: %d", got)
		}
	})
	t.Run("no-probe", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		seedStaleRows(p, dev.ID)
		dev.ProbeID = nil
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, nil)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired for a non-probe device: %d", got)
		}
	})
	t.Run("under-threshold", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		// 30 min stale: past the 5-min cutoff but under the 60-min default threshold.
		ts := time.Now().Add(-30 * time.Minute)
		mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: ts, CPUUsage: 10})
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, nil)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired under threshold: %d", got)
		}
	})
	t.Run("just-flipped-offline", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		seedStaleRows(p, dev.ID)
		flipped := map[uint]struct{}{dev.ID: {}}
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, flipped)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired for a device the sweep just flipped offline: %d", got)
		}
	})
	t.Run("setting-zero-disables", func(t *testing.T) {
		p, db := newTelemetryTestPoller(t)
		dev := newStaleTestDevice(t, p)
		seedStaleRows(p, dev.ID)
		mustCreate(t, db, &models.SystemSetting{Key: "telemetry_stale_minutes", Value: "0", Category: "alerts", Type: "string"})
		runCycles(p, []models.Device{*dev}, telemetryStaleCycles+1, nil)
		if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
			t.Errorf("fired with the check disabled (setting=0): %d", got)
		}
	})
}

// TestTelemetryStale_DebounceResetOnFreshRow: a fresh row mid-run resets the
// consecutive-cycle counter, so intermittent staleness never accumulates to a
// fire.
func TestTelemetryStale_DebounceResetOnFreshRow(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	old := time.Now().Add(-2 * time.Hour)
	stale := &models.SystemStatus{DeviceID: dev.ID, Timestamp: old, CPUUsage: 10}
	mustCreate(t, db, stale)

	runCycles(p, []models.Device{*dev}, telemetryStaleCycles-1, nil)

	// Fresh vitals arrive → condition false → counter reset.
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	runCycles(p, []models.Device{*dev}, 1, nil)

	// Vitals go stale again: the counter must start over, so two more cycles
	// still don't fire.
	db.Gorm().Where("device_id = ? AND timestamp > ?", dev.ID, old).Delete(&models.SystemStatus{})
	runCycles(p, []models.Device{*dev}, telemetryStaleCycles-1, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
		t.Errorf("debounce did not reset on fresh row: %d alerts", got)
	}
}

// TestTelemetryStale_RecoveryResolves: after a fire, fresh rows resolve the
// open alert (auto-ack + resolved_at) and write a _RESOLVED companion.
func TestTelemetryStale_RecoveryResolves(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	old := time.Now().Add(-2 * time.Hour)
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: old, CPUUsage: 10})
	runCycles(p, []models.Device{*dev}, telemetryStaleCycles, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("precondition: TELEMETRY_STALE = %d, want 1", got)
	}

	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	runCycles(p, []models.Device{*dev}, 1, nil)

	var open int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ? AND resolved_at IS NULL", "TELEMETRY_STALE", dev.ID).
		Count(&open)
	if open != 0 {
		t.Errorf("open TELEMETRY_STALE rows after recovery = %d, want 0", open)
	}
	if got := countAlerts(t, db, "TELEMETRY_STALE_RESOLVED", dev.ID); got != 1 {
		t.Errorf("TELEMETRY_STALE_RESOLVED companions = %d, want 1", got)
	}
}

// TestTelemetryStale_OfflineSupersedes: when the device transitions to fully
// offline, AutoResolveTelemetryStale closes the open alert silently — resolved
// row, NO _RESOLVED companion, no recovery notification.
func TestTelemetryStale_OfflineSupersedes(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	old := time.Now().Add(-2 * time.Hour)
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: old, CPUUsage: 10})
	runCycles(p, []models.Device{*dev}, telemetryStaleCycles, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("precondition: TELEMETRY_STALE = %d, want 1", got)
	}

	// The sweep path: device flips offline → silent supersede.
	p.alertManager.AutoResolveTelemetryStale(dev.ID)

	var open int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ? AND resolved_at IS NULL", "TELEMETRY_STALE", dev.ID).
		Count(&open)
	if open != 0 {
		t.Errorf("open TELEMETRY_STALE rows after supersede = %d, want 0", open)
	}
	if got := countAlerts(t, db, "TELEMETRY_STALE_RESOLVED", dev.ID); got != 0 {
		t.Errorf("silent supersede wrote a _RESOLVED companion: %d (must be 0)", got)
	}
}

// TestTelemetryStale_ThresholdSettingRespected: a lower admin-set threshold
// (clamped at 2×staleAfter) brings a 30-min-stale device into scope.
func TestTelemetryStale_ThresholdSettingRespected(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	mustCreate(t, db, &models.SystemSetting{Key: "telemetry_stale_minutes", Value: "15", Category: "alerts", Type: "string"})
	// 30 min stale: over the 15-min setting (clamped to max(15m, 2×5m)=15m).
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now().Add(-30 * time.Minute), CPUUsage: 10})

	runCycles(p, []models.Device{*dev}, telemetryStaleCycles, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Errorf("TELEMETRY_STALE with 15-min setting = %d, want 1", got)
	}
}
