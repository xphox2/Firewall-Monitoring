package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetLatestVPNStatuses_PeerCrossFill_AUDIT035 exercises the rewritten
// peer-tunnel fetch in GetLatestVPNStatuses. The old code ran one
// `WHERE device_id = ? ORDER BY timestamp DESC` query PER peer device (an
// N+1); it is now a single `device_id IN (...)` query. This test confirms the
// peer cross-fill still works end to end: device A's tunnel, which is missing
// its subnets, gets them (and its RemoteDeviceID) filled in from peer device
// B's matching tunnel — which is only possible if the single-query peer fetch
// returns B's subnet-bearing row.
func TestGetLatestVPNStatuses_PeerCrossFill_AUDIT035(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// DeviceConnection isn't in the default test-migration set; ensure it.
	if err := d.Gorm().AutoMigrate(&models.Device{}, &models.DeviceConnection{}, &models.VPNStatus{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	devA := &models.Device{Name: "A", IPAddress: "10.0.0.1"}
	devB := &models.Device{Name: "B", IPAddress: "10.0.0.2"}
	if err := d.Gorm().Create(devA).Error; err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := d.Gorm().Create(devB).Error; err != nil {
		t.Fatalf("create B: %v", err)
	}
	if err := d.Gorm().Create(&models.DeviceConnection{Name: "A-B", SourceDeviceID: devA.ID, DestDeviceID: devB.ID}).Error; err != nil {
		t.Fatalf("create connection: %v", err)
	}

	now := time.Now().UTC()
	// A's tunnel: subnets unknown, remote_ip points at B.
	if err := d.Gorm().Create(&models.VPNStatus{
		DeviceID: devA.ID, TunnelName: "tunA", RemoteIP: "10.0.0.2", Status: "up", Timestamp: now,
	}).Error; err != nil {
		t.Fatalf("create A vpn: %v", err)
	}
	// B's peer tunnel: has subnets, remote_ip points back at A. An older,
	// subnet-less B row is also present to confirm the ORDER BY / filter pick
	// the right one.
	if err := d.Gorm().Create(&models.VPNStatus{
		DeviceID: devB.ID, TunnelName: "tunB", RemoteIP: "10.0.0.1", Status: "up",
		LocalSubnet: "192.168.1.0/24", RemoteSubnet: "192.168.2.0/24", Timestamp: now,
	}).Error; err != nil {
		t.Fatalf("create B vpn: %v", err)
	}
	if err := d.Gorm().Create(&models.VPNStatus{
		DeviceID: devB.ID, TunnelName: "tunB", RemoteIP: "10.0.0.1", Status: "down",
		Timestamp: now.Add(-2 * time.Hour),
	}).Error; err != nil {
		t.Fatalf("create B old vpn: %v", err)
	}

	statuses, err := d.GetLatestVPNStatuses(devA.ID)
	if err != nil {
		t.Fatalf("GetLatestVPNStatuses: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 latest status for A, got %d", len(statuses))
	}
	s := statuses[0]
	if s.LocalSubnet != "192.168.1.0/24" {
		t.Errorf("LocalSubnet not cross-filled from peer B: got %q, want 192.168.1.0/24", s.LocalSubnet)
	}
	if s.RemoteSubnet != "192.168.2.0/24" {
		t.Errorf("RemoteSubnet not cross-filled from peer B: got %q, want 192.168.2.0/24", s.RemoteSubnet)
	}
	if s.RemoteDeviceID == nil || *s.RemoteDeviceID != devB.ID {
		t.Errorf("RemoteDeviceID not resolved to peer B (%d): got %v", devB.ID, s.RemoteDeviceID)
	}
}
