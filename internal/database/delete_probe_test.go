package database

import (
	"errors"
	"testing"

	"firewall-mon/internal/models"
)

// TestDeleteProbe_RefusesWhenDevicesAssigned guards the regression where a probe
// with assigned devices could never be deleted: the bare DELETE hit the
// devices.probe_id foreign key and returned an opaque "Failed to delete probe".
// DeleteProbe now returns ErrProbeHasDevices so the handler can tell the
// operator to reassign devices first.
func TestDeleteProbe_RefusesWhenDevicesAssigned(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probe := &models.Probe{Name: "old-probe"}
	if err := d.CreateProbe(probe); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	dev := &models.Device{Name: "dev1", ProbeID: &probe.ID}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	err := d.DeleteProbe(probe.ID)
	if !errors.Is(err, ErrProbeHasDevices) {
		t.Fatalf("expected ErrProbeHasDevices, got %v", err)
	}

	// The probe must still exist after the refused delete.
	if _, err := d.GetProbe(probe.ID); err != nil {
		t.Fatalf("probe should still exist after refused delete: %v", err)
	}
}

// TestDeleteProbe_CleansUpDependents verifies that once no devices reference the
// probe, DeleteProbe removes the probe AND the FK-referencing child rows
// (probe_approvals, probe_heartbeats) plus the registration SystemSetting — the
// rows that previously made the delete fail with a foreign-key violation.
func TestDeleteProbe_CleansUpDependents(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probe := &models.Probe{Name: "old-probe", RegistrationKey: "deadbeefhash"}
	if err := d.CreateProbe(probe); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	if err := d.db.Create(&models.ProbeApproval{ProbeID: probe.ID, Status: "approved"}).Error; err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if err := d.db.Create(&models.ProbeHeartbeat{ProbeID: probe.ID, Status: "online"}).Error; err != nil {
		t.Fatalf("create heartbeat: %v", err)
	}
	if err := d.db.Create(&models.SystemSetting{Key: "probe_registration_" + probe.RegistrationKey, Value: probe.Name}).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}

	if err := d.DeleteProbe(probe.ID); err != nil {
		t.Fatalf("DeleteProbe: %v", err)
	}

	if _, err := d.GetProbe(probe.ID); err == nil {
		t.Fatal("probe should be deleted")
	}

	var approvals, heartbeats, settings int64
	d.db.Model(&models.ProbeApproval{}).Where("probe_id = ?", probe.ID).Count(&approvals)
	d.db.Model(&models.ProbeHeartbeat{}).Where("probe_id = ?", probe.ID).Count(&heartbeats)
	d.db.Model(&models.SystemSetting{}).Where("key = ?", "probe_registration_"+probe.RegistrationKey).Count(&settings)
	if approvals != 0 || heartbeats != 0 || settings != 0 {
		t.Fatalf("dependents not cleaned: approvals=%d heartbeats=%d settings=%d", approvals, heartbeats, settings)
	}
}
