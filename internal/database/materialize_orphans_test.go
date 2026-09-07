package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestParseDeviceStatusMessage pins the name/IP recovery used by migration v61,
// including a name that itself contains parentheses.
func TestParseDeviceStatusMessage(t *testing.T) {
	cases := []struct {
		msg, name, ip string
	}{
		{"Device TECHLABS-FW-01 (192.168.25.1) is offline", "TECHLABS-FW-01", "192.168.25.1"},
		{"Device Edge (lab) (10.0.0.5) is back online", "Edge (lab)", "10.0.0.5"},
		{"Device v6 (2001:db8::1) is offline", "v6", "2001:db8::1"},
		{"Device X (not-an-ip) is offline", "", ""},
		{"Device X is offline", "", ""},
		{"Interface port1 is down", "", ""},
		{"Device  (1.1.1.1) is offline", "", ""},
	}
	for _, tc := range cases {
		name, ip := parseDeviceStatusMessage(tc.msg)
		if name != tc.name || ip != tc.ip {
			t.Errorf("%q → (%q, %q), want (%q, %q)", tc.msg, name, ip, tc.name, tc.ip)
		}
	}
}

// TestMigrateMaterializeOrphanedDevices: orphaned history for ids 42/43/44 is
// materialized as retired rows under the ORIGINAL ids (42 named from its
// newest status alert, 43 with no parsable alert → fallback, 44 whose
// recovered name collides with a live device → fallback); the device_id=0
// digest alert never creates a device; a rerun is a no-op.
func TestMigrateMaterializeOrphanedDevices(t *testing.T) {
	d := NewDatabaseForTesting(t)

	if err := d.db.Create(&models.Device{Name: "LIVE-FW", IPAddress: "10.9.9.9"}).Error; err != nil {
		t.Fatalf("seed live device: %v", err)
	}
	now := time.Now()
	seed := []*models.Alert{
		{DeviceID: 42, Timestamp: now.Add(-2 * time.Hour), AlertType: "DEVICE_OFFLINE", Message: "Device OLD-NAME (10.0.0.1) is offline"},
		{DeviceID: 42, Timestamp: now.Add(-time.Hour), AlertType: "CPU_HIGH", Message: "CPU 99%"},
		{DeviceID: 42, Timestamp: now, AlertType: "DEVICE_OFFLINE", Message: "Device Edge (lab) (10.0.0.5) is offline"},
		{DeviceID: 0, Timestamp: now, AlertType: "SFLOW_SECURITY_DIGEST", Message: "digest"},
		{DeviceID: 44, Timestamp: now, AlertType: "DEVICE_OFFLINE", Message: "Device LIVE-FW (10.9.9.9) is offline"},
	}
	for _, a := range seed {
		if err := d.db.Create(a).Error; err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}
	if err := d.db.Create(&models.UptimeRecord{DeviceID: 43, Timestamp: now}).Error; err != nil {
		t.Fatalf("seed uptime: %v", err)
	}
	if err := d.db.Create(&models.VPNStatus{DeviceID: 42, Timestamp: now, TunnelName: "t"}).Error; err != nil {
		t.Fatalf("seed vpn: %v", err)
	}

	if err := d.migrateMaterializeOrphanedDevices(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var total int64
	d.db.Model(&models.Device{}).Count(&total)
	if total != 4 {
		t.Fatalf("devices = %d, want 4 (live + 42/43/44; never device 0)", total)
	}
	var zero int64
	d.db.Model(&models.Device{}).Where("id = 0").Count(&zero)
	if zero != 0 {
		t.Error("a device with id 0 was materialized from the digest alert")
	}

	check := func(id uint, name, ip string) {
		t.Helper()
		dev, err := d.GetDevice(id)
		if err != nil {
			t.Fatalf("device %d not materialized: %v", id, err)
		}
		if dev.Name != name || dev.IPAddress != ip {
			t.Errorf("device %d = %q/%q, want %q/%q", id, dev.Name, dev.IPAddress, name, ip)
		}
		if dev.RetiredAt == nil || dev.Enabled || dev.Status != "offline" || dev.Vendor != "fortigate" {
			t.Errorf("device %d: retired_at=%v enabled=%v status=%q vendor=%q", id, dev.RetiredAt, dev.Enabled, dev.Status, dev.Vendor)
		}
	}
	check(42, "Edge (lab)", "10.0.0.5")
	check(43, "Removed device #43", "0.0.0.0")
	check(44, "Removed device #44", "0.0.0.0")

	// Rerun: nothing changes.
	if err := d.migrateMaterializeOrphanedDevices(); err != nil {
		t.Fatalf("migrate rerun: %v", err)
	}
	d.db.Model(&models.Device{}).Count(&total)
	if total != 4 {
		t.Errorf("rerun changed device count to %d", total)
	}

	// The recovered row is a normal retired device: excluded from the active
	// scope, restorable.
	active, _ := d.GetActiveDevices()
	if len(active) != 1 {
		t.Errorf("active devices = %d, want 1 (materialized rows are retired)", len(active))
	}
	if err := d.RestoreDevice(42, nil); err != nil {
		t.Errorf("restore materialized device: %v", err)
	}
}
