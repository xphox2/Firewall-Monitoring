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
	db := p.db
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

// TestTelemetryStale_SSHFreshDoesNotRecoverIfaceStale (AUDIT-189): an alert
// fired by the INTERFACE signal alone (SNMP dead, SSH perf keeping vitals
// fresh — the fleet's primary failure mode) must NOT auto-resolve when the
// dead interface rows age out of the 24h lookback while vitals stay fresh.
// The old gate closed on ANY fresh signal, so exactly this scenario sent a
// false "recovered" notification while SNMP was still broken.
func TestTelemetryStale_SSHFreshDoesNotRecoverIfaceStale(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	// Fire via iface-only staleness (vitals fresh throughout).
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Now().Add(-2 * time.Hour), Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})
	runCycles(p, []models.Device{*dev}, telemetryStaleCycles, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("precondition: TELEMETRY_STALE = %d, want 1", got)
	}

	// The dead interface rows age past the lookback; vitals keep flowing.
	if err := db.Gorm().Model(&models.InterfaceStats{}).Where("device_id = ?", dev.ID).
		Update("timestamp", time.Now().Add(-telemetryStaleLookback-time.Hour)).Error; err != nil {
		t.Fatalf("age interface rows: %v", err)
	}
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	runCycles(p, []models.Device{*dev}, 2, nil)

	var open int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ? AND resolved_at IS NULL", "TELEMETRY_STALE", dev.ID).
		Count(&open)
	if open != 1 {
		t.Errorf("open rows after iface aged out = %d, want 1 — fresh vitals must not recover an iface-stale alert", open)
	}
	if got := countAlerts(t, db, "TELEMETRY_STALE_RESOLVED", dev.ID); got != 0 {
		t.Errorf("false recovery: %d TELEMETRY_STALE_RESOLVED companions, want 0", got)
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

// TestTelemetryStale_QueryFailureFreezes: a failed signal query must freeze
// the evaluation — neither firing NOR recovering. The killer scenario: an
// alert held open by a stale interface signal while vitals are fresh (the
// FortiGate SSH case) must not send a false "recovered" notification on a
// cycle where the interface query errored.
func TestTelemetryStale_QueryFailureFreezes(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)

	// Fire via the interface signal (vitals fresh throughout).
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Now().Add(-2 * time.Hour), Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})
	runCycles(p, []models.Device{*dev}, telemetryStaleCycles, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("precondition: TELEMETRY_STALE = %d, want 1", got)
	}

	// Simulate a cycle where the interface query failed: fresh vitals visible,
	// iface signal absent, ifaceQueryOK=false. Must not resolve the open row.
	p.evaluateTelemetryStale(telemetryStaleInputs{
		devByID:       map[uint]*models.Device{dev.ID: dev},
		freshStatus:   map[uint]bool{dev.ID: true},
		staleVitals:   map[uint]time.Time{},
		latestIface:   map[uint]time.Time{},
		statusQueryOK: true,
		ifaceQueryOK:  false,
		staleAfter:    telemetryStaleAfter,
		now:           time.Now(),
	})

	var open int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ? AND resolved_at IS NULL", "TELEMETRY_STALE", dev.ID).
		Count(&open)
	if open != 1 {
		t.Errorf("open rows after iface-query failure = %d, want 1 (false recovery)", open)
	}
	if got := countAlerts(t, db, "TELEMETRY_STALE_RESOLVED", dev.ID); got != 0 {
		t.Errorf("query failure sent a recovery companion: %d, want 0", got)
	}
	// The streak must survive the frozen cycle so the condition doesn't need
	// to re-debounce from zero once the query heals.
	if p.telemetryStaleStreak[dev.ID] < telemetryStaleCycles {
		t.Errorf("streak reset by frozen cycle: %d", p.telemetryStaleStreak[dev.ID])
	}
}

// TestTelemetryStale_StreakPrunedForGoneDevices: entries for devices no longer
// in devByID (deleted/disabled) are pruned — no leak, and a re-enabled device
// re-debounces from zero instead of firing on its first cycle back.
func TestTelemetryStale_StreakPrunedForGoneDevices(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := newStaleTestDevice(t, p)
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now().Add(-2 * time.Hour), CPUUsage: 10})

	// Build up a partial streak, then disable the device.
	runCycles(p, []models.Device{*dev}, telemetryStaleCycles-1, nil)
	if p.telemetryStaleStreak[dev.ID] != telemetryStaleCycles-1 {
		t.Fatalf("precondition: streak = %d", p.telemetryStaleStreak[dev.ID])
	}
	dev.Enabled = false
	runCycles(p, []models.Device{*dev}, 1, nil)
	if _, ok := p.telemetryStaleStreak[dev.ID]; ok {
		t.Error("streak entry not pruned for a device absent from devByID")
	}

	// Re-enable: the first cycle back must NOT fire (debounce restarts).
	dev.Enabled = true
	runCycles(p, []models.Device{*dev}, 1, nil)
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 0 {
		t.Errorf("fired on first post-re-enable cycle: %d alerts", got)
	}
}

// TestTelemetryStale_DefaultPinnedToAlertingPage: tripwire — the Alerting
// page's read-through default in handlers_alert_policies.go
// (alertGlobalDefaults) hardcodes 60 because handlers cannot import package
// main. If this constant changes, update that map in the same commit.
func TestTelemetryStale_DefaultPinnedToAlertingPage(t *testing.T) {
	if telemetryStaleDefaultMinutes != 60 {
		t.Fatalf("telemetryStaleDefaultMinutes = %d; update alertGlobalDefaults in internal/api/handlers/handlers_alert_policies.go to match, then this pin", telemetryStaleDefaultMinutes)
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
