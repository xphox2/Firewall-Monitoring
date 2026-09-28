//go:build integration

package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// v69 and the ActiveConnections scope on real PostgreSQL: the NOT IN
// subqueries and the scoped Preload read.
func TestPostgresMigrateV69_AndActiveConnectionsScope(t *testing.T) {
	d := NewIntegrationDB(t)
	retiredAt := time.Now().UTC().Add(-time.Hour)
	a := models.Device{Name: "pg-hub", IPAddress: "10.60.0.1"}
	b := models.Device{Name: "pg-peer", IPAddress: "10.60.0.2"}
	gone := models.Device{Name: "pg-gone", IPAddress: "10.60.0.3", RetiredAt: &retiredAt}
	for _, dev := range []*models.Device{&a, &b, &gone} {
		if err := d.db.Create(dev).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}
	live := models.DeviceConnection{Name: "pg live", SourceDeviceID: a.ID, DestDeviceID: b.ID, ConnectionType: "ipsec"}
	ghost := models.DeviceConnection{Name: "pg ? ↔ peer", SourceDeviceID: gone.ID, DestDeviceID: b.ID, ConnectionType: "ipsec", AutoDetected: true}
	for _, c := range []*models.DeviceConnection{&live, &ghost} {
		if err := d.db.Create(c).Error; err != nil {
			t.Fatalf("seed connection: %v", err)
		}
	}

	all, err := d.GetAllConnections()
	if err != nil {
		t.Fatalf("GetAllConnections: %v", err)
	}
	for _, c := range all {
		if c.ID == ghost.ID {
			t.Error("GetAllConnections returned the connection to a retired device")
		}
	}

	if err := d.migrateDeleteConnectionsToRetiredDevices(); err != nil {
		t.Fatalf("migrate v69: %v", err)
	}
	var n int64
	d.db.Model(&models.DeviceConnection{}).Where("id = ?", ghost.ID).Count(&n)
	if n != 0 {
		t.Error("v69 left the connection to a retired device")
	}
	d.db.Model(&models.DeviceConnection{}).Where("id = ?", live.ID).Count(&n)
	if n != 1 {
		t.Error("v69 deleted a live connection")
	}
}
