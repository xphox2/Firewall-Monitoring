package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestResolveDevicesByIPs verifies the batched resolver returns the same
// management-IP-over-interface-address precedence as the per-IP ResolveDeviceByIP,
// across many IPs in one call, and omits IPs with no match.
func TestResolveDevicesByIPs(t *testing.T) {
	d := NewDatabaseForTesting(t)

	devA := models.Device{Name: "A", IPAddress: "10.0.0.1"}
	devB := models.Device{Name: "B", IPAddress: "10.0.0.2"}
	devC := models.Device{Name: "C", IPAddress: "10.0.0.50"}
	for _, dev := range []*models.Device{&devA, &devB, &devC} {
		if err := d.db.Create(dev).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}

	// 10.0.0.1 is also claimed by an interface address on devC — the management
	// IP (devA) must win. 10.0.0.99 is interface-only on devB.
	addrs := []models.InterfaceAddress{
		{DeviceID: devC.ID, IPAddress: "10.0.0.1"},
		{DeviceID: devB.ID, IPAddress: "10.0.0.99"},
	}
	for i := range addrs {
		if err := d.db.Create(&addrs[i]).Error; err != nil {
			t.Fatalf("create interface address: %v", err)
		}
	}

	got := d.ResolveDevicesByIPs([]string{"10.0.0.1", "10.0.0.2", "10.0.0.99", "1.2.3.4"})

	if got["10.0.0.1"] != devA.ID {
		t.Errorf("10.0.0.1 -> %d, want devA %d (management IP must win over interface addr)", got["10.0.0.1"], devA.ID)
	}
	if got["10.0.0.2"] != devB.ID {
		t.Errorf("10.0.0.2 -> %d, want devB %d", got["10.0.0.2"], devB.ID)
	}
	if got["10.0.0.99"] != devB.ID {
		t.Errorf("10.0.0.99 -> %d, want devB %d (via interface address)", got["10.0.0.99"], devB.ID)
	}
	if _, ok := got["1.2.3.4"]; ok {
		t.Errorf("1.2.3.4 should be absent, got %d", got["1.2.3.4"])
	}

	if len(d.ResolveDevicesByIPs(nil)) != 0 {
		t.Error("empty input should return empty map")
	}
}
