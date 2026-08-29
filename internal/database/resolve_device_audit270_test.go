package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestResolveDeviceByIP_Deterministic_AUDIT270 pins that a shared IP always
// resolves to the same (lowest-id) device. The interface-address lookup pre-fix
// used .First with no ORDER BY, so gorm ordered by the interface_addresses
// primary key — returning whichever address row was inserted first regardless of
// its device_id. Here the LOWER-id device's address is inserted SECOND, so the
// unordered lookup returns the HIGHER-id device; the .Order("device_id ASC") fix
// makes it deterministic.
func TestResolveDeviceByIP_Deterministic_AUDIT270(t *testing.T) {
	d := NewDatabaseForTesting(t)

	shared := "10.9.9.9"
	// Distinct management IPs so the management-IP lookup misses and the
	// interface-address branch runs.
	devA := &models.Device{Name: "A", IPAddress: "10.0.0.1"}
	devB := &models.Device{Name: "B", IPAddress: "10.0.0.2"}
	if err := d.Gorm().Create(devA).Error; err != nil {
		t.Fatalf("create devA: %v", err)
	}
	if err := d.Gorm().Create(devB).Error; err != nil {
		t.Fatalf("create devB: %v", err)
	}
	if devA.ID >= devB.ID {
		t.Fatalf("expected devA.ID (%d) < devB.ID (%d)", devA.ID, devB.ID)
	}

	// Insert the HIGHER-id device's address first (lower interface_addresses id),
	// then the lower-id device's — so an id-of-address ordering would pick devB.
	if err := d.Gorm().Create(&models.InterfaceAddress{DeviceID: devB.ID, IPAddress: shared}).Error; err != nil {
		t.Fatalf("create addr B: %v", err)
	}
	if err := d.Gorm().Create(&models.InterfaceAddress{DeviceID: devA.ID, IPAddress: shared}).Error; err != nil {
		t.Fatalf("create addr A: %v", err)
	}

	for i := 0; i < 3; i++ {
		if got := d.ResolveDeviceByIP(shared); got != devA.ID {
			t.Fatalf("ResolveDeviceByIP(%s) = %d, want lowest device id %d (nondeterministic pre-fix)", shared, got, devA.ID)
		}
	}

	// The batched twin must agree.
	m := d.ResolveDevicesByIPs([]string{shared})
	if m[shared] != devA.ID {
		t.Fatalf("ResolveDevicesByIPs[%s] = %d, want %d", shared, m[shared], devA.ID)
	}
}
