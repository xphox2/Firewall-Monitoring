package main

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// telemetryStaleAfter mirrors the runMonitoringCycle staleness value for a
// default-interval poller (3×PollInterval floored at 5 minutes).
const telemetryStaleAfter = 5 * time.Minute

// newTelemetryTestPoller builds a Poller with a REAL AlertManager over the test
// database, so checkRelayedTelemetry's alert side effects land in the alerts
// table where the tests can observe them. Global CPU threshold 80, legacy
// interface-down toggle on, spike detection off (per-test opt-in).
func newTelemetryTestPoller(t *testing.T) (*Poller, *database.Database) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Alerts.CPUThreshold = 80
	cfg.Alerts.InterfaceDownAlert = true
	notif := notifier.NewNotifier(cfg)
	p := &Poller{
		cfg:            cfg,
		db:             db,
		alertManager:   alerts.NewAlertManager(cfg, notif, db),
		notifier:       notif,
		prevIfaceStats: make(map[string]*models.InterfaceStats),
	}
	return p, db
}

func countAlerts(t *testing.T, db *database.Database, alertType string, deviceID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND device_id = ?", alertType, deviceID).
		Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", alertType, err)
	}
	return n
}

func mustCreate(t *testing.T, db *database.Database, value any) {
	t.Helper()
	if err := db.Gorm().Create(value).Error; err != nil {
		t.Fatalf("create %T: %v", value, err)
	}
}

// TestCheckRelayedTelemetry_SystemStatusFresh: a fresh over-threshold
// system_status row fires CPU_HIGH for the owning device.
func TestCheckRelayedTelemetry_SystemStatusFresh(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := &models.Device{Name: "fw1", IPAddress: "10.0.0.1", Enabled: true}
	mustCreate(t, db, dev)
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 95})

	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "CPU_HIGH", dev.ID); got != 1 {
		t.Errorf("CPU_HIGH alerts = %d, want 1", got)
	}
}

// TestCheckRelayedTelemetry_SystemStatusUsesDeviceSiteID: the device's siteID
// must be plumbed into the checks. A site-level CPU threshold override (99)
// above the reported usage suppresses the alert that the global threshold (80)
// would have fired — which only happens if siteID reached resolveAlertConfig.
func TestCheckRelayedTelemetry_SystemStatusUsesDeviceSiteID(t *testing.T) {
	p, db := newTelemetryTestPoller(t)

	site := &models.Site{Name: "HQ"}
	mustCreate(t, db, site)
	mustCreate(t, db, &models.SiteAlertConfig{SiteID: site.ID, CPUThreshold: 99})

	siteDev := &models.Device{Name: "fw-site", IPAddress: "10.0.0.2", Enabled: true, SiteID: &site.ID}
	freeDev := &models.Device{Name: "fw-free", IPAddress: "10.0.0.3", Enabled: true}
	mustCreate(t, db, siteDev)
	mustCreate(t, db, freeDev)

	now := time.Now()
	mustCreate(t, db, &models.SystemStatus{DeviceID: siteDev.ID, Timestamp: now, CPUUsage: 95})
	mustCreate(t, db, &models.SystemStatus{DeviceID: freeDev.ID, Timestamp: now, CPUUsage: 95})

	// Load the policy/site-config cache the way runMonitoringCycle does.
	p.alertManager.RefreshThresholds(db.Gorm())

	p.checkRelayedTelemetry([]models.Device{*siteDev, *freeDev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "CPU_HIGH", siteDev.ID); got != 0 {
		t.Errorf("site-override device: CPU_HIGH alerts = %d, want 0 (site threshold 99 > 95)", got)
	}
	if got := countAlerts(t, db, "CPU_HIGH", freeDev.ID); got != 1 {
		t.Errorf("no-site device: CPU_HIGH alerts = %d, want 1 (global threshold 80 < 95)", got)
	}
}

// TestCheckRelayedTelemetry_StaleRowsIgnored: rows older than staleAfter fire
// nothing — a dead device's last over-threshold/down sample must not keep
// re-alerting forever.
func TestCheckRelayedTelemetry_StaleRowsIgnored(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := &models.Device{Name: "fw-dead", IPAddress: "10.0.0.4", Enabled: true}
	mustCreate(t, db, dev)

	stale := time.Now().Add(-telemetryStaleAfter - time.Minute)
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: stale, CPUUsage: 95})
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: stale, Name: "port1", Index: 1, Status: "down", AdminStatus: "up"})
	mustCreate(t, db, &models.VPNStatus{DeviceID: dev.ID, Timestamp: stale, TunnelName: "hq-vpn", Status: "down"})

	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	for _, at := range []string{"CPU_HIGH", "INTERFACE_DOWN", "VPN_TUNNEL_DOWN"} {
		if got := countAlerts(t, db, at, dev.ID); got != 0 {
			t.Errorf("%s alerts from stale rows = %d, want 0", at, got)
		}
	}
	if len(p.prevIfaceStats) != 0 {
		t.Errorf("prevIfaceStats populated from stale rows: %v", p.prevIfaceStats)
	}
}

// TestCheckRelayedTelemetry_SameSampleGuard: an interface row whose timestamp
// equals the cached prevIfaceStats entry's has already been processed (the
// poller ticks at ~the collector's cadence) — the delta consumers must skip it
// and must NOT overwrite the cached baseline. A later snapshot with the same
// error growth fires normally (control).
func TestCheckRelayedTelemetry_SameSampleGuard(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := &models.Device{Name: "fw2", IPAddress: "10.0.0.5", Enabled: true}
	mustCreate(t, db, dev)

	t1 := time.Now().Add(-30 * time.Second)
	key := fmt.Sprintf("%d_%s", dev.ID, "port1")
	// Cached baseline from a previous cycle, stamped with the SAME timestamp
	// as the row currently in the DB (i.e. no new collector sample arrived).
	p.prevIfaceStats[key] = &models.InterfaceStats{DeviceID: dev.ID, Timestamp: t1, Name: "port1", Index: 1, Status: "up", AdminStatus: "up"}
	row := &models.InterfaceStats{DeviceID: dev.ID, Timestamp: t1, Name: "port1", Index: 1, Status: "up", AdminStatus: "up", InErrors: 5}
	mustCreate(t, db, row)

	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "INTERFACE_ERRORS", dev.ID); got != 0 {
		t.Errorf("INTERFACE_ERRORS alerts on same-timestamp snapshot = %d, want 0", got)
	}
	if p.prevIfaceStats[key].InErrors != 0 {
		t.Errorf("prevIfaceStats overwritten by a skipped same-timestamp sample")
	}

	// Control: a NEW snapshot (later timestamp) with error growth fires.
	t2 := t1.Add(30 * time.Second)
	if err := db.Gorm().Model(&models.InterfaceStats{}).Where("id = ?", row.ID).
		Update("timestamp", t2).Error; err != nil {
		t.Fatalf("advance snapshot timestamp: %v", err)
	}
	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "INTERFACE_ERRORS", dev.ID); got != 1 {
		t.Errorf("INTERFACE_ERRORS alerts on new snapshot = %d, want 1", got)
	}
	if p.prevIfaceStats[key].InErrors != 5 {
		t.Errorf("prevIfaceStats not updated after processing new sample: InErrors=%d, want 5", p.prevIfaceStats[key].InErrors)
	}
}

// TestCheckRelayedTelemetry_InterfaceDown: a fresh down (admin-up) interface
// row fires INTERFACE_DOWN, and prevIfaceStats is populated after the cycle.
func TestCheckRelayedTelemetry_InterfaceDown(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := &models.Device{Name: "fw3", IPAddress: "10.0.0.6", Enabled: true}
	mustCreate(t, db, dev)
	mustCreate(t, db, &models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Now(), Name: "wan1", Index: 2, Status: "down", AdminStatus: "up"})

	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "INTERFACE_DOWN", dev.ID); got != 1 {
		t.Errorf("INTERFACE_DOWN alerts = %d, want 1", got)
	}
	key := fmt.Sprintf("%d_%s", dev.ID, "wan1")
	if p.prevIfaceStats[key] == nil {
		t.Errorf("prevIfaceStats[%q] not populated after the cycle", key)
	}
}

// TestCheckRelayedTelemetry_VPNDown: a fresh down VPN tunnel row fires
// VPN_TUNNEL_DOWN.
func TestCheckRelayedTelemetry_VPNDown(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := &models.Device{Name: "fw4", IPAddress: "10.0.0.7", Enabled: true}
	mustCreate(t, db, dev)
	mustCreate(t, db, &models.VPNStatus{DeviceID: dev.ID, Timestamp: time.Now(), TunnelName: "branch-vpn", Status: "down"})

	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "VPN_TUNNEL_DOWN", dev.ID); got != 1 {
		t.Errorf("VPN_TUNNEL_DOWN alerts = %d, want 1", got)
	}
}

// TestCheckRelayedTelemetry_DisabledDeviceIgnored: rows belonging to a
// disabled device fire nothing even when fresh and over threshold.
func TestCheckRelayedTelemetry_DisabledDeviceIgnored(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	dev := &models.Device{Name: "fw-off", IPAddress: "10.0.0.8"}
	mustCreate(t, db, dev)
	// GORM omits zero-value fields carrying a `default:` tag on INSERT, so
	// Enabled:false at create time would silently become true — disable via a
	// targeted update instead.
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", dev.ID).Update("enabled", false).Error; err != nil {
		t.Fatalf("disable device: %v", err)
	}
	dev.Enabled = false
	mustCreate(t, db, &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), CPUUsage: 95})

	p.checkRelayedTelemetry([]models.Device{*dev}, telemetryStaleAfter)

	if got := countAlerts(t, db, "CPU_HIGH", dev.ID); got != 0 {
		t.Errorf("CPU_HIGH alerts for disabled device = %d, want 0", got)
	}
}
