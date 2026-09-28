package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// connGuardFixture seeds two active devices and one retired one.
func connGuardFixture(t *testing.T) (d *Database, a, b, gone models.Device) {
	t.Helper()
	d = NewDatabaseForTesting(t)
	retiredAt := time.Now().UTC().Add(-time.Hour)
	a = models.Device{Name: "HUB-FW", IPAddress: "10.0.0.1"}
	b = models.Device{Name: "OPNsense", IPAddress: "10.0.0.2"}
	gone = models.Device{Name: "GONE-FW", IPAddress: "10.0.0.3", RetiredAt: &retiredAt}
	for _, dev := range []*models.Device{&a, &b, &gone} {
		if err := d.db.Create(dev).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}
	return d, a, b, gone
}

func countConns(t *testing.T, d *Database) int64 {
	t.Helper()
	var n int64
	if err := d.db.Model(&models.DeviceConnection{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// The backstop refuses a retired or missing endpoint WITHOUT an error: the
// poller reads an upsert error as an incomplete cycle and would then skip the
// stale sweep that removes existing ghost rows.
func TestUpsertAutoConnection_RefusesRetiredOrMissingEndpointWithNil(t *testing.T) {
	d, a, _, gone := connGuardFixture(t)
	if err := d.UpsertAutoConnection(a.ID, gone.ID, "up", "t1", "HUB-FW ↔ GONE-FW", "ipsec", "provisioned"); err != nil {
		t.Fatalf("retired endpoint: got error %v, want nil", err)
	}
	if err := d.UpsertAutoConnection(a.ID, 9999, "up", "t1", "HUB-FW ↔ ?", "ipsec", "provisioned"); err != nil {
		t.Fatalf("missing endpoint: got error %v, want nil", err)
	}
	if err := d.UpsertAutoL2Connection(L2LinkUpsert{SourceID: gone.ID, DestID: a.ID, Status: "up", Name: "x", ConnType: "ethernet", MatchMethod: "fdb_match"}); err != nil {
		t.Fatalf("l2 retired endpoint: got error %v, want nil", err)
	}
	if n := countConns(t, d); n != 0 {
		t.Errorf("%d connection row(s) written to a retired or missing device, want 0", n)
	}
	if n := d.AutoConnectionSkipCount(); n != 3 {
		t.Errorf("AutoConnectionSkipCount = %d, want 3", n)
	}
}

// An operator may rename an auto-detected connection; the rename must survive
// every poller cycle. Only a leftover "?" placeholder name is replaced.
func TestUpsertAutoConnection_NameRefreshOnlyReplacesPlaceholder(t *testing.T) {
	d, a, b, _ := connGuardFixture(t)
	if err := d.UpsertAutoConnection(a.ID, b.ID, "up", "t1", "HUB-FW ↔ OPNsense", "ipsec", "provisioned"); err != nil {
		t.Fatalf("create: %v", err)
	}
	var c models.DeviceConnection
	d.db.First(&c)

	d.db.Model(&models.DeviceConnection{}).Where("id = ?", c.ID).Update("name", "Hub to lab")
	if err := d.UpsertAutoConnection(a.ID, b.ID, "down", "t1", "HUB-FW ↔ OPNsense", "ipsec", "provisioned"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	d.db.First(&c, c.ID)
	if c.Name != "Hub to lab" || c.Status != "down" {
		t.Errorf("after a cycle: name=%q status=%q, want the operator's name kept and status refreshed", c.Name, c.Status)
	}

	d.db.Model(&models.DeviceConnection{}).Where("id = ?", c.ID).Update("name", "? ↔ OPNsense")
	if err := d.UpsertAutoConnection(a.ID, b.ID, "up", "t1", "HUB-FW ↔ OPNsense", "ipsec", "provisioned"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	d.db.First(&c, c.ID)
	if c.Name != "HUB-FW ↔ OPNsense" {
		t.Errorf("a placeholder name was not replaced: %q", c.Name)
	}
}

// Every list, status and detail read hides a connection with a retired end.
func TestConnectionReads_ExcludeRetiredEndpoints(t *testing.T) {
	d, a, b, gone := connGuardFixture(t)
	live := models.DeviceConnection{Name: "live", SourceDeviceID: a.ID, DestDeviceID: b.ID, ConnectionType: "ipsec", Status: "up"}
	ghost := models.DeviceConnection{Name: "? ↔ OPNsense", SourceDeviceID: gone.ID, DestDeviceID: b.ID, ConnectionType: "ipsec", Status: "down", AutoDetected: true}
	for _, c := range []*models.DeviceConnection{&live, &ghost} {
		if err := d.db.Create(c).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	all, err := d.GetAllConnections()
	if err != nil || len(all) != 1 || all[0].ID != live.ID {
		t.Errorf("GetAllConnections = %d rows (err %v), want only the live one", len(all), err)
	}
	st, err := d.GetConnectionStatuses()
	if err != nil || len(st) != 1 {
		t.Errorf("GetConnectionStatuses = %d rows (err %v), want 1", len(st), err)
	}
	if _, err := d.GetConnectionDetail(ghost.ID); err == nil {
		t.Error("GetConnectionDetail returned a connection whose endpoint is retired")
	}
	if _, err := d.GetConnectionDetail(live.ID); err != nil {
		t.Errorf("GetConnectionDetail(live): %v", err)
	}
	if _, err := d.GetConnectionTraffic(ghost.ID, 24); err == nil {
		t.Error("GetConnectionTraffic returned data for a connection whose endpoint is retired")
	}
}

// v69 removes rows to retired or missing devices and nothing else.
func TestMigrateV69_DeletesConnectionsToRetiredDevices(t *testing.T) {
	d, a, b, gone := connGuardFixture(t)
	seed := []models.DeviceConnection{
		{Name: "live", SourceDeviceID: a.ID, DestDeviceID: b.ID, ConnectionType: "ipsec"},
		{Name: "live manual", SourceDeviceID: b.ID, DestDeviceID: a.ID, ConnectionType: "ethernet"},
		{Name: "? ↔ OPNsense", SourceDeviceID: gone.ID, DestDeviceID: b.ID, ConnectionType: "ipsec", AutoDetected: true},
		{Name: "to retired", SourceDeviceID: a.ID, DestDeviceID: gone.ID, ConnectionType: "ethernet"},
		{Name: "to missing", SourceDeviceID: a.ID, DestDeviceID: 9999, ConnectionType: "ipsec", AutoDetected: true},
	}
	for i := range seed {
		if err := d.db.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := d.migrateDeleteConnectionsToRetiredDevices(); err != nil {
		t.Fatalf("migrate v69: %v", err)
	}
	var names []string
	d.db.Model(&models.DeviceConnection{}).Order("name").Pluck("name", &names)
	if len(names) != 2 || names[0] != "live" || names[1] != "live manual" {
		t.Errorf("after v69: %v, want [live, live manual]", names)
	}
	// Idempotent.
	if err := d.migrateDeleteConnectionsToRetiredDevices(); err != nil {
		t.Fatalf("migrate v69 rerun: %v", err)
	}
	if n := countConns(t, d); n != 2 {
		t.Errorf("rerun changed the row count to %d", n)
	}
}

// The VPN panel cross-fills subnets and the peer deep-link from connected
// peers; a leftover row to a retired device must not make it link there.
func TestGetLatestVPNStatuses_IgnoresConnectionsToRetiredPeers(t *testing.T) {
	d, a, _, gone := connGuardFixture(t)
	now := time.Now()
	if err := d.SaveVPNStatuses([]models.VPNStatus{
		{DeviceID: a.ID, TunnelName: "t1", TunnelType: "ipsec", RemoteIP: gone.IPAddress, Status: "up", Timestamp: now},
		{DeviceID: gone.ID, TunnelName: "t1", TunnelType: "ipsec", RemoteIP: a.IPAddress, Status: "up",
			LocalSubnet: "192.168.13.0/24", RemoteSubnet: "192.168.50.0/24", Timestamp: now},
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}
	ghost := models.DeviceConnection{Name: "? ↔ HUB-FW", SourceDeviceID: a.ID, DestDeviceID: gone.ID, ConnectionType: "ipsec", AutoDetected: true}
	if err := d.db.Create(&ghost).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	st, err := d.GetLatestVPNStatuses(a.ID)
	if err != nil || len(st) != 1 {
		t.Fatalf("GetLatestVPNStatuses = %d rows, err %v", len(st), err)
	}
	if st[0].RemoteDeviceID != nil || st[0].LocalSubnet != "" {
		t.Errorf("tunnel enriched from a retired peer: remote_device_id=%v local_subnet=%q", st[0].RemoteDeviceID, st[0].LocalSubnet)
	}
}
