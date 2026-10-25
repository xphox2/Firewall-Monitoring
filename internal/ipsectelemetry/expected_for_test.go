package ipsectelemetry

import (
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"
	"firewall-mon/internal/vpnsession"
)

// A tunnel to a DECOMMISSIONED peer can never come up. Expecting its children
// manufactures an outage: the parser synthesises a "down" row for every
// expected child the box is not carrying, on EVERY telemetry cycle, for as long
// as the tunnel stays "provisioned" — which is exactly how a retired FortiGate
// keeps re-appearing as a phantom peer on the topology map.
func TestExpectedFor_SkipsRetiredPeer(t *testing.T) {
	db := database.NewDatabaseForTesting(t)

	live := &models.Device{Name: "opn-live", IPAddress: "198.51.100.7", Vendor: "opnsense"}
	if err := db.Gorm().Create(live).Error; err != nil {
		t.Fatalf("create live device: %v", err)
	}
	gone := &models.Device{Name: "fg-retired", IPAddress: "203.0.113.9", Vendor: "fortigate"}
	if err := db.Gorm().Create(gone).Error; err != nil {
		t.Fatalf("create retired device: %v", err)
	}

	// A policy-based tunnel (the only shape with pair-level detail) between the
	// live OPNsense and the FortiGate.
	in := &ipsec.TunnelIntent{
		Name: "fwm-orphan", Enabled: true, IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
	}
	in.Ends[0] = ipsec.EndpointSpec{DeviceID: live.ID, Vendor: "opnsense", EgressIface: "wan", ProtectedSubnets: []string{"192.168.150.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{DeviceID: gone.ID, Vendor: "fortigate", EgressIface: "port1", ProtectedSubnets: []string{"192.168.113.0/24"}}
	row, err := database.IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	row.Name = "fwm-orphan"
	row.Status = "up" // provisioned: NOT draft / rolled_back
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	// While the peer is alive the child IS expected.
	want := expectedFor(db, live.ID)
	if len(want) != 1 {
		t.Fatalf("want 1 expected child while the peer is alive, got %d: %+v", len(want), want)
	}
	if want[0].TunnelName != "fwm-orphan" {
		t.Errorf("expected child tunnel = %q, want fwm-orphan", want[0].TunnelName)
	}

	// Retire the far end: the child can never come up, so it must NOT be
	// expected — otherwise the parser manufactures a "down" row for it.
	if err := db.RetireDevice(gone.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	got := expectedFor(db, live.ID)
	if len(got) != 0 {
		t.Errorf("a retired peer must produce no expected children, got %d: %+v", len(got), got)
	}
}

// A PURGED peer is the same case: the row is gone, so the pair points at a
// device that does not exist.
func TestExpectedFor_SkipsPurgedPeer(t *testing.T) {
	db := database.NewDatabaseForTesting(t)

	live := &models.Device{Name: "opn-live", IPAddress: "198.51.100.7", Vendor: "opnsense"}
	if err := db.Gorm().Create(live).Error; err != nil {
		t.Fatalf("create live device: %v", err)
	}
	gone := &models.Device{Name: "fg-purged", IPAddress: "203.0.113.9", Vendor: "fortigate"}
	if err := db.Gorm().Create(gone).Error; err != nil {
		t.Fatalf("create purged device: %v", err)
	}
	in := &ipsec.TunnelIntent{
		Name: "fwm-purged", Enabled: true, IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
	}
	in.Ends[0] = ipsec.EndpointSpec{DeviceID: live.ID, Vendor: "opnsense", EgressIface: "wan", ProtectedSubnets: []string{"192.168.150.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{DeviceID: gone.ID, Vendor: "fortigate", EgressIface: "port1", ProtectedSubnets: []string{"192.168.113.0/24"}}
	row, err := database.IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	row.Name = "fwm-purged"
	row.Status = "up"
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := db.DeleteDevice(gone.ID); err != nil {
		t.Fatalf("purge peer: %v", err)
	}
	if got := expectedFor(db, live.ID); len(got) != 0 {
		t.Errorf("a purged peer must produce no expected children, got %d: %+v", len(got), got)
	}
}

// The device's OWN side of a healthy tunnel must still be expected — the skip
// is scoped to the far end, not to the reporting device.
func TestExpectedFor_KeepsHealthyPair(t *testing.T) {
	db := database.NewDatabaseForTesting(t)

	live := &models.Device{Name: "opn-live", IPAddress: "198.51.100.7", Vendor: "opnsense"}
	if err := db.Gorm().Create(live).Error; err != nil {
		t.Fatalf("create live device: %v", err)
	}
	peer := &models.Device{Name: "fg-live", IPAddress: "203.0.113.9", Vendor: "fortigate"}
	if err := db.Gorm().Create(peer).Error; err != nil {
		t.Fatalf("create peer: %v", err)
	}
	in := &ipsec.TunnelIntent{
		Name: "fwm-healthy", Enabled: true, IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
	}
	in.Ends[0] = ipsec.EndpointSpec{DeviceID: live.ID, Vendor: "opnsense", EgressIface: "wan", ProtectedSubnets: []string{"192.168.150.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{DeviceID: peer.ID, Vendor: "fortigate", EgressIface: "port1", ProtectedSubnets: []string{"192.168.113.0/24"}}
	row, err := database.IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	row.Name = "fwm-healthy"
	row.Status = "up"
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	got := expectedFor(db, live.ID)
	if len(got) != 1 {
		t.Fatalf("a healthy pair must still be expected, got %d: %+v", len(got), got)
	}
	var _ vpnsession.ExpectedChild = got[0]
}
