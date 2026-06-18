package database

import (
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestDecommissionProbe_PreservesRowAndTelemetry verifies the soft-decommission
// path keeps the probe row AND its telemetry (so running totals are preserved),
// only stamping decommissioned_at and disabling the probe.
func TestDecommissionProbe_PreservesRowAndTelemetry(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probe := &models.Probe{Name: "old-probe", Enabled: true, ApprovalStatus: "approved"}
	if err := d.CreateProbe(probe); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	if err := d.db.Create(&models.SyslogMessage{ProbeID: probe.ID, Timestamp: time.Now()}).Error; err != nil {
		t.Fatalf("seed syslog: %v", err)
	}

	if err := d.DecommissionProbe(probe.ID); err != nil {
		t.Fatalf("DecommissionProbe: %v", err)
	}

	got, err := d.GetProbe(probe.ID)
	if err != nil {
		t.Fatalf("probe should still exist after decommission: %v", err)
	}
	if got.DecommissionedAt == nil {
		t.Error("decommissioned_at should be set")
	}
	if got.Enabled {
		t.Error("decommissioned probe should be disabled")
	}

	// Telemetry must survive untouched — it's a running total.
	var syslog int64
	d.db.Model(&models.SyslogMessage{}).Where("probe_id = ?", probe.ID).Count(&syslog)
	if syslog != 1 {
		t.Errorf("telemetry must be preserved on decommission, got %d syslog rows", syslog)
	}

	// Restore clears the marker and re-enables.
	if err := d.RecommissionProbe(probe.ID); err != nil {
		t.Fatalf("RecommissionProbe: %v", err)
	}
	got, _ = d.GetProbe(probe.ID)
	if got.DecommissionedAt != nil || !got.Enabled {
		t.Errorf("recommission should clear decommissioned_at and re-enable: %+v", got.DecommissionedAt)
	}
}

// TestDecommissionProbe_RefusesWhenDevicesAssigned mirrors DeleteProbe's guard:
// the operator must reassign devices to the replacement probe first.
func TestDecommissionProbe_RefusesWhenDevicesAssigned(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probe := &models.Probe{Name: "old-probe"}
	if err := d.CreateProbe(probe); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	if err := d.db.Create(&models.Device{Name: "dev1", ProbeID: &probe.ID}).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := d.DecommissionProbe(probe.ID); !errors.Is(err, ErrProbeHasDevices) {
		t.Fatalf("expected ErrProbeHasDevices, got %v", err)
	}
}

// TestDeleteDevice_PreservesTelemetry guards the fix that a device delete must
// NOT physically erase its historical telemetry — the rows are orphaned but
// kept (data is a running total, never destroyed just because a device is gone).
func TestDeleteDevice_PreservesTelemetry(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.DeviceConnection{}); err != nil {
		t.Fatalf("migrate connections: %v", err)
	}

	dev := &models.Device{Name: "dev1"}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	now := time.Now()
	if err := d.db.Create(&models.SystemStatus{DeviceID: dev.ID, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed status: %v", err)
	}
	if err := d.db.Create(&models.TrapEvent{DeviceID: dev.ID, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed trap: %v", err)
	}
	if err := d.db.Create(&models.Alert{DeviceID: dev.ID, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	if err := d.DeleteDevice(dev.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}

	// Device row gone…
	var devices int64
	d.db.Model(&models.Device{}).Where("id = ?", dev.ID).Count(&devices)
	if devices != 0 {
		t.Error("device row should be deleted")
	}
	// …but its telemetry preserved (orphaned, not erased).
	for _, c := range []struct {
		name  string
		model interface{}
	}{
		{"system_status", &models.SystemStatus{}},
		{"trap_events", &models.TrapEvent{}},
		{"alerts", &models.Alert{}},
	} {
		var n int64
		d.db.Model(c.model).Where("device_id = ?", dev.ID).Count(&n)
		if n != 1 {
			t.Errorf("%s telemetry must survive device delete, got %d rows", c.name, n)
		}
	}
}

// TestGetTelemetryTotals_IndependentOfProbeExistence verifies the orphan-safe
// running totals count every telemetry row regardless of whether the collecting
// probe still exists.
func TestGetTelemetryTotals_IndependentOfProbeExistence(t *testing.T) {
	d := NewDatabaseForTesting(t)

	now := time.Now().UTC()
	// probe_id 999 never exists in the probes table — these are "orphaned" rows.
	if err := d.db.Create(&models.SyslogMessage{ProbeID: 999, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed syslog: %v", err)
	}
	if err := d.db.Create(&models.TrapEvent{ProbeID: 999, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed trap: %v", err)
	}
	if err := d.db.Create(&models.PingResult{ProbeID: 999, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed ping: %v", err)
	}

	totals, err := d.GetTelemetryTotals()
	if err != nil {
		t.Fatalf("GetTelemetryTotals: %v", err)
	}
	if totals.Syslog != 1 || totals.Traps != 1 || totals.Pings != 1 {
		t.Errorf("orphaned telemetry must still be counted: %+v", totals)
	}
	if totals.SyslogLastHr != 1 || totals.TrapsLastHr != 1 {
		t.Errorf("last-hour counts wrong: %+v", totals)
	}
}

// TestMigrateUnifyPingStats_MergesDuplicates verifies migration v3 collapses the
// per-probe duplicate ping rows for a device+target into one continuous series
// and installs the new uniqueness index.
func TestMigrateUnifyPingStats_MergesDuplicates(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.PingStats{}); err != nil {
		t.Fatalf("migrate ping_stats: %v", err)
	}
	// Simulate the pre-migration schema: drop the new unique index so two probe
	// rows for the same (device, target) can coexist.
	if err := d.db.Exec(`DROP INDEX IF EXISTS idx_pingstats_device_target`).Error; err != nil {
		t.Fatalf("drop new index: %v", err)
	}

	older := time.Now().Add(-time.Minute)
	newer := time.Now()
	if err := d.db.Create(&models.PingStats{DeviceID: 1, ProbeID: 1, TargetIP: "8.8.8.8",
		MinLatency: 10, MaxLatency: 30, AvgLatency: 20, PacketLoss: 0, Samples: 10, UpdatedAt: older}).Error; err != nil {
		t.Fatalf("seed row A: %v", err)
	}
	if err := d.db.Create(&models.PingStats{DeviceID: 1, ProbeID: 2, TargetIP: "8.8.8.8",
		MinLatency: 5, MaxLatency: 50, AvgLatency: 25, PacketLoss: 1, Samples: 20, UpdatedAt: newer}).Error; err != nil {
		t.Fatalf("seed row B: %v", err)
	}

	if err := d.migrateUnifyPingStats(); err != nil {
		t.Fatalf("migrateUnifyPingStats: %v", err)
	}

	var rows []models.PingStats
	if err := d.db.Where("device_id = ? AND target_ip = ?", 1, "8.8.8.8").Find(&rows).Error; err != nil {
		t.Fatalf("load merged: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 merged row, got %d", len(rows))
	}
	m := rows[0]
	if m.Samples != 30 {
		t.Errorf("samples = %d, want 30 (sum)", m.Samples)
	}
	if m.MinLatency != 5 {
		t.Errorf("min = %v, want 5", m.MinLatency)
	}
	if m.MaxLatency != 50 {
		t.Errorf("max = %v, want 50", m.MaxLatency)
	}
	// sample-weighted avg = (20*10 + 25*20) / 30 = 23.333…
	if m.AvgLatency < 23.3 || m.AvgLatency > 23.4 {
		t.Errorf("avg = %v, want ~23.33 (sample-weighted)", m.AvgLatency)
	}

	// The new unique index must now reject a duplicate (device, target).
	dup := d.db.Create(&models.PingStats{DeviceID: 1, ProbeID: 3, TargetIP: "8.8.8.8", Samples: 1, UpdatedAt: time.Now()}).Error
	if dup == nil {
		t.Error("expected unique-index violation inserting a duplicate (device, target) after migration")
	}
}

// TestRunMigrations_RealChain_Sqlite runs the actual registeredMigrations list
// (baseline → partition → unify_ping_stats → probe_decommissioned_at) on a fresh
// DB to confirm v3/v4 are idempotent and error-free end-to-end (the PG lane
// covers this in CI; this gives a fast local signal too).
func TestRunMigrations_RealChain_Sqlite(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	// Re-running must be a no-op (every migration recorded + idempotent).
	if err := d.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations (second run): %v", err)
	}
	// The probe column and the unified ping index must exist.
	if !d.db.Migrator().HasColumn(&models.Probe{}, "decommissioned_at") {
		t.Error("probes.decommissioned_at column missing after migrations")
	}
	if err := d.db.Create(&models.PingStats{DeviceID: 7, ProbeID: 1, TargetIP: "1.1.1.1", Samples: 1, UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("seed ping after migrations: %v", err)
	}
	dup := d.db.Create(&models.PingStats{DeviceID: 7, ProbeID: 2, TargetIP: "1.1.1.1", Samples: 1, UpdatedAt: time.Now()}).Error
	if dup == nil {
		t.Error("unified ping unique index (device,target) not enforced after real migration chain")
	}
}
