package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestRunMonitoringCycle_StaleSweepsStillRun pins blocker B1 of the v0.11.74
// direct-poll retirement behaviorally: with the SNMP loop gone, the cycle must
// still flip stale probe-assigned devices offline (with a DEVICE_OFFLINE
// alert) and stale probes offline.
func TestRunMonitoringCycle_StaleSweepsStillRun(t *testing.T) {
	p, db := newTestPoller(t)
	cfg := &config.Config{}
	p.cfg = cfg
	notif := notifier.NewNotifier(cfg)
	p.alertManager = alerts.NewAlertManager(cfg, notif, db)
	p.notifier = notif

	probe := &models.Probe{Name: "edge-1", RegistrationKey: "k1", Status: "online", LastSeen: time.Now().Add(-time.Hour)}
	mustCreate(t, db, probe)
	dev := &models.Device{Name: "fw-stale", IPAddress: "10.1.0.1", Enabled: true, ProbeID: &probe.ID, Status: "online", LastPolled: time.Now().Add(-time.Hour)}
	mustCreate(t, db, dev)

	p.runMonitoringCycle()

	var gotDev models.Device
	if err := db.Gorm().First(&gotDev, dev.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if gotDev.Status != "offline" {
		t.Errorf("stale probe device status = %q, want offline (MarkStaleProbeDevicesOffline sweep)", gotDev.Status)
	}
	if got := countAlerts(t, db, "DEVICE_OFFLINE", dev.ID); got != 1 {
		t.Errorf("DEVICE_OFFLINE alerts = %d, want 1", got)
	}

	var gotProbe models.Probe
	if err := db.Gorm().First(&gotProbe, probe.ID).Error; err != nil {
		t.Fatalf("reload probe: %v", err)
	}
	if gotProbe.Status != "offline" {
		t.Errorf("stale probe status = %q, want offline (MarkStaleProbesOffline sweep)", gotProbe.Status)
	}
}

// TestRunMonitoringCycle_UnassignedDeviceNotAlerted: an enabled device with no
// collector assignment is a configuration gap, not an outage — the cycle must
// not fire DEVICE_OFFLINE for it.
func TestRunMonitoringCycle_UnassignedDeviceNotAlerted(t *testing.T) {
	p, db := newTestPoller(t)
	cfg := &config.Config{}
	p.cfg = cfg
	notif := notifier.NewNotifier(cfg)
	p.alertManager = alerts.NewAlertManager(cfg, notif, db)
	p.notifier = notif

	dev := &models.Device{Name: "fw-unassigned", IPAddress: "10.1.0.2", Enabled: true, Status: "online", LastPolled: time.Now().Add(-time.Hour)}
	mustCreate(t, db, dev)

	p.runMonitoringCycle()

	if got := countAlerts(t, db, "DEVICE_OFFLINE", dev.ID); got != 0 {
		t.Errorf("DEVICE_OFFLINE alerts for unassigned device = %d, want 0", got)
	}
	var gotDev models.Device
	if err := db.Gorm().First(&gotDev, dev.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if gotDev.Status != "online" {
		t.Errorf("unassigned device status = %q, want untouched online", gotDev.Status)
	}
}

// TestRunMonitoringCycle_KeepsAlertEngineCalls is the cheap source-level
// guardrail for blocker B1: the per-tick cycle body must keep invoking every
// piece of the alert/health engine that survived the direct-poll retirement.
// Behavioral coverage exists for the sweeps above and for the telemetry checks
// in checkrelayed_test.go; this pins the rest (escalations, probe data-flow,
// detectors, threshold refresh, baseline pruning) against accidental deletion.
func TestRunMonitoringCycle_KeepsAlertEngineCalls(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	start := strings.Index(string(src), "func (p *Poller) runMonitoringCycle()")
	if start < 0 {
		t.Fatalf("runMonitoringCycle not found in main.go")
	}
	rest := string(src)[start:]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		end = len(rest)
	}
	body := rest[:end]

	for _, call := range []string{
		"RefreshThresholds(",
		"GetAllDevices()",
		"pruneStaleIfaceStats(",
		"MarkStaleProbeDevicesOffline(",
		"CheckDeviceOffline(",
		"MarkStaleProbesOffline(",
		"CheckDeviceOnline(",
		"checkRelayedTelemetry(",
		"detectVPNConnections(",
		"detectOverlayConnections(",
		"detectL2Links(",
		"CheckEscalations()",
		"CheckProbeDataFlow()",
	} {
		if !strings.Contains(body, call) {
			t.Errorf("runMonitoringCycle no longer invokes %s — the alert/health engine must keep running every cycle", call)
		}
	}
	// The stale-connection sweep must stay gated on EVERY detector read flag. A
	// failed read is not evidence that a device pair disappeared, so sweeping on
	// one would delete every edge of that family and recreate it with fresh IDs
	// next cycle. This is the cheap tripwire against "simplifying" the guard.
	for _, guard := range []string{"vpnOK", "l2OK", "overlayOK"} {
		if !strings.Contains(body, guard) {
			t.Errorf("runMonitoringCycle no longer consults %s — the stale-connection sweep must not run on a failed detector read", guard)
		}
	}

	if strings.Contains(body, "pollDevice(") {
		t.Errorf("runMonitoringCycle still references pollDevice — the direct device-SNMP loop is retired")
	}
}
