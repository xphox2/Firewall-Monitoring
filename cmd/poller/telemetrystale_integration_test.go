//go:build integration

// TELEMETRY_STALE end-to-end on real Postgres: the detection rides a raw-SQL
// MAX(timestamp) query against the PARTITIONED system_status table plus the
// resolveOpenAlertRows CASE/|| update — both shapes SQLite tolerates
// differently, so the fire→recover cycle is pinned here on the engine prod
// runs. Behind //go:build integration; skips unless TEST_PG_DSN is set.
package main

import (
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

func TestTelemetryStale_Postgres_EndToEnd(t *testing.T) {
	db := database.NewIntegrationDB(t) // skips if TEST_PG_DSN unset
	if err := db.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	cfg := &config.Config{}
	p := &Poller{
		cfg:            cfg,
		db:             db,
		alertManager:   alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db),
		notifier:       notifier.NewNotifier(cfg),
		prevIfaceStats: make(map[string]*models.InterfaceStats),
	}

	site := &models.Site{Name: "stale-e2e-site"}
	mustCreate(t, db, site)
	probe := &models.Probe{Name: "stale-e2e-probe", SiteID: site.ID, RegistrationKey: "k", ApprovalStatus: "approved"}
	mustCreate(t, db, probe)
	dev := &models.Device{Name: "fw-e2e-stale", IPAddress: "10.9.2.1", Enabled: true, Status: "online", ProbeID: &probe.ID}
	mustCreate(t, db, dev)

	old := time.Now().Add(-2 * time.Hour)
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: old, CPUUsage: 10})
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: old, Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})

	for i := 0; i < telemetryStaleCycles; i++ {
		p.checkRelayedTelemetry([]models.Device{*dev}, 5*time.Minute, nil)
	}
	if got := countAlerts(t, db, "TELEMETRY_STALE", dev.ID); got != 1 {
		t.Fatalf("TELEMETRY_STALE on Postgres = %d, want 1", got)
	}

	openRows := func() int64 {
		var open int64
		db.Gorm().Model(&models.Alert{}).
			Where("alert_type = ? AND device_id = ? AND resolved_at IS NULL", "TELEMETRY_STALE", dev.ID).
			Count(&open)
		return open
	}

	// Fresh vitals ALONE must not resolve — the interface signal is still stale
	// (the FortiGate SSH-alive/SNMP-dead shape stays alerted).
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 10})
	p.checkRelayedTelemetry([]models.Device{*dev}, 5*time.Minute, nil)
	if got := openRows(); got != 1 {
		t.Errorf("open rows after vitals-only refresh = %d, want 1 (interface signal still stale)", got)
	}

	// Fresh interface stats too → full recovery: the open row resolves
	// (CASE/|| update on PG) with exactly one _RESOLVED companion.
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Now(), Name: "port1", Index: 1, Status: "up", AdminStatus: "up"})
	p.checkRelayedTelemetry([]models.Device{*dev}, 5*time.Minute, nil)
	if got := openRows(); got != 0 {
		t.Errorf("open TELEMETRY_STALE rows after full recovery = %d, want 0", got)
	}
	if got := countAlerts(t, db, "TELEMETRY_STALE_RESOLVED", dev.ID); got != 1 {
		t.Errorf("TELEMETRY_STALE_RESOLVED companions = %d, want 1", got)
	}
}
