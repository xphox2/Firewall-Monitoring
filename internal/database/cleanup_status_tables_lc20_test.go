package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// LC-20 (2026-07-04 audit): the five per-poll status tables (vpn_status,
// ha_status, security_stats, sdwan_health, license_info) had NO retention path
// — both the AUDIT-029 and 2026-07-01 H4 passes missed them, so every poll
// cycle and every collector push appended rows forever. They are now in
// CleanupOldData's entries slice: the four charted tables follow StatusDays
// unless their own RETENTION_*_DAYS knob is set; license_info has its own knob.

// TestCleanupOldData_CoversFiveStatusTables_LC20 seeds one stale (60d) and one
// recent (1d) row per table and asserts cleanup removes exactly the stale one.
func TestCleanupOldData_CoversFiveStatusTables_LC20(t *testing.T) {
	d := NewDatabaseForTesting(t)
	stale := time.Now().AddDate(0, 0, -60)
	recent := time.Now().AddDate(0, 0, -1)

	seed := func(model interface{}) {
		t.Helper()
		if err := d.Gorm().Create(model).Error; err != nil {
			t.Fatalf("seed %T: %v", model, err)
		}
	}
	seed(&models.VPNStatus{DeviceID: 1, TunnelName: "old", Timestamp: stale})
	seed(&models.VPNStatus{DeviceID: 1, TunnelName: "new", Timestamp: recent})
	seed(&models.HAStatus{DeviceID: 1, SystemMode: "a-p", Timestamp: stale})
	seed(&models.HAStatus{DeviceID: 1, SystemMode: "a-p", Timestamp: recent})
	seed(&models.SecurityStats{DeviceID: 1, AVDetected: 1, Timestamp: stale})
	seed(&models.SecurityStats{DeviceID: 1, AVDetected: 2, Timestamp: recent})
	seed(&models.SDWANHealth{DeviceID: 1, Name: "wan1", Timestamp: stale})
	seed(&models.SDWANHealth{DeviceID: 1, Name: "wan1", Timestamp: recent})
	seed(&models.LicenseInfo{DeviceID: 1, Description: "old", Timestamp: stale})
	seed(&models.LicenseInfo{DeviceID: 1, Description: "new", Timestamp: recent})

	// StatusDays 30 governs the four charted tables (their knobs are 0 =
	// follow StatusDays); license_info needs its own knob.
	if err := d.CleanupOldData(config.RetentionConfig{
		StatusDays:      30,
		LicenseInfoDays: 30,
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	tables := []struct {
		name  string
		model interface{}
	}{
		{"vpn_status", &models.VPNStatus{}},
		{"ha_status", &models.HAStatus{}},
		{"security_stats", &models.SecurityStats{}},
		{"sdwan_health", &models.SDWANHealth{}},
		{"license_info", &models.LicenseInfo{}},
	}
	for _, tbl := range tables {
		var count int64
		if err := d.Gorm().Model(tbl.model).Count(&count).Error; err != nil {
			t.Errorf("%s: count after cleanup: %v", tbl.name, err)
			continue
		}
		if count != 1 {
			t.Errorf("%s has %d row(s) after cleanup, want 1 (stale row pruned, recent row kept) — LC-20: the table must be in CleanupOldData's entries slice", tbl.name, count)
		}
	}
}

// TestCleanupOldData_StatusTablePerTableKnob_LC20 verifies the per-table knob
// overrides the StatusDays fallback: with StatusDays=90 and VPNStatusDays=10,
// a 20-day-old vpn_status row is pruned while a 20-day-old ha_status row
// (still on the 90-day fallback) survives.
func TestCleanupOldData_StatusTablePerTableKnob_LC20(t *testing.T) {
	d := NewDatabaseForTesting(t)
	ts := time.Now().AddDate(0, 0, -20)

	if err := d.Gorm().Create(&models.VPNStatus{DeviceID: 1, TunnelName: "t1", Timestamp: ts}).Error; err != nil {
		t.Fatalf("seed vpn_status: %v", err)
	}
	if err := d.Gorm().Create(&models.HAStatus{DeviceID: 1, SystemMode: "a-p", Timestamp: ts}).Error; err != nil {
		t.Fatalf("seed ha_status: %v", err)
	}

	if err := d.CleanupOldData(config.RetentionConfig{
		StatusDays:    90,
		VPNStatusDays: 10,
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var vpn, ha int64
	d.Gorm().Model(&models.VPNStatus{}).Count(&vpn)
	d.Gorm().Model(&models.HAStatus{}).Count(&ha)
	if vpn != 0 {
		t.Errorf("vpn_status: %d row(s) remain; RETENTION_VPN_STATUS_DAYS=10 should have pruned the 20-day-old row", vpn)
	}
	if ha != 1 {
		t.Errorf("ha_status: %d row(s) remain, want 1; the 90-day StatusDays fallback should have kept the 20-day-old row", ha)
	}
}
