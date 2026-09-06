package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestDeleteProbe_RetiredDeviceDoesNotBlock: a retired device assigned to the
// probe no longer blocks DeleteProbe/DecommissionProbe (it is not polled), and
// DeleteProbe detaches it (probe_id → NULL) so the devices.probe_id FK cannot
// refuse the probe delete.
func TestDeleteProbe_RetiredDeviceDoesNotBlock(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probe := &models.Probe{Name: "old-probe"}
	if err := d.CreateProbe(probe); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", ProbeID: &probe.ID}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := d.RetireDevice(dev.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}

	if err := d.DecommissionProbe(probe.ID); err != nil {
		t.Fatalf("DecommissionProbe with only a retired device assigned: %v", err)
	}
	if err := d.DeleteProbe(probe.ID); err != nil {
		t.Fatalf("DeleteProbe with only a retired device assigned: %v", err)
	}
	if _, err := d.GetProbe(probe.ID); err == nil {
		t.Error("probe still exists after delete")
	}
	got, err := d.GetDevice(dev.ID)
	if err != nil {
		t.Fatalf("retired device must survive the probe delete: %v", err)
	}
	if got.ProbeID != nil {
		t.Errorf("retired device probe_id = %v, want NULL", *got.ProbeID)
	}
	if got.RetiredAt == nil {
		t.Error("device lost its retired marker")
	}
}
