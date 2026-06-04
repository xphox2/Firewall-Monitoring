package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestMarkStaleProbeDevicesOffline_ReturnsTransitions verifies that the stale
// check returns exactly the devices that transitioned online -> offline, so
// the poller can fire a DEVICE_OFFLINE alert + critical email per transition.
//
// The pre-fix function returned only an int64 row count, so probe-assigned
// devices flipped offline in the UI with no alert and no email (the
// CheckDeviceOffline path is only reachable via the directly-polled
// updateDeviceStatus, which never runs for probe devices). This test pins the
// new contract: the returned slice is the online->offline transition set —
// stale-but-already-offline, fresh, disabled, and non-probe devices are all
// excluded — and the flipped rows are actually persisted as offline.
func TestMarkStaleProbeDevicesOffline_ReturnsTransitions(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probeID := uint(1)
	old := time.Now().Add(-30 * time.Minute) // well past any stale threshold
	fresh := time.Now().Add(-10 * time.Second)
	threshold := time.Now().Add(-5 * time.Minute)

	devices := []models.Device{
		// A: probe, enabled, online, stale -> SHOULD flip + be returned.
		{Name: "A-stale-online-probe", IPAddress: "10.0.0.1", ProbeID: &probeID, Enabled: true, Status: "online", LastPolled: old},
		// B: probe, enabled, online, fresh -> stays online, not returned.
		{Name: "B-fresh-online-probe", IPAddress: "10.0.0.2", ProbeID: &probeID, Enabled: true, Status: "online", LastPolled: fresh},
		// C: probe, enabled, already offline, stale -> not a transition, not returned.
		{Name: "C-stale-offline-probe", IPAddress: "10.0.0.3", ProbeID: &probeID, Enabled: true, Status: "offline", LastPolled: old},
		// D: NOT probe-assigned, online, stale -> directly-polled, the poller's
		// updateDeviceStatus owns it; the stale check must skip it.
		{Name: "D-stale-online-direct", IPAddress: "10.0.0.4", ProbeID: nil, Enabled: true, Status: "online", LastPolled: old},
		// E: probe, DISABLED, online, stale -> excluded (disabled devices aren't alerted).
		{Name: "E-stale-online-disabled", IPAddress: "10.0.0.5", ProbeID: &probeID, Enabled: false, Status: "online", LastPolled: old},
	}
	for i := range devices {
		if err := d.Gorm().Create(&devices[i]).Error; err != nil {
			t.Fatalf("seed %s: %v", devices[i].Name, err)
		}
	}
	// Device.Enabled has gorm `default:true`, so Create with the zero value
	// (false) lets the column default win and stores it as enabled. Force the
	// disabled state explicitly so the exclusion is actually exercised.
	if err := d.Gorm().Model(&models.Device{}).Where("name = ?", "E-stale-online-disabled").UpdateColumn("enabled", false).Error; err != nil {
		t.Fatalf("force-disable E: %v", err)
	}

	flipped, err := d.MarkStaleProbeDevicesOffline(threshold)
	if err != nil {
		t.Fatalf("MarkStaleProbeDevicesOffline: %v", err)
	}

	// Only device A should be returned.
	if len(flipped) != 1 {
		names := make([]string, len(flipped))
		for i, f := range flipped {
			names[i] = f.Name
		}
		t.Fatalf("transition set = %v, want exactly [A-stale-online-probe]", names)
	}
	if flipped[0].Name != "A-stale-online-probe" {
		t.Errorf("returned %q, want A-stale-online-probe", flipped[0].Name)
	}
	// The returned struct must already carry the new status so the caller can
	// alert on it without a re-read.
	if flipped[0].Status != "offline" {
		t.Errorf("returned device Status = %q, want offline", flipped[0].Status)
	}

	// Verify persisted state per device.
	want := map[string]string{
		"A-stale-online-probe":    "offline", // flipped
		"B-fresh-online-probe":    "online",  // fresh, untouched
		"C-stale-offline-probe":   "offline", // already offline, unchanged
		"D-stale-online-direct":   "online",  // non-probe, untouched
		"E-stale-online-disabled": "online",  // disabled, untouched
	}
	var got []models.Device
	if err := d.Gorm().Find(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, dev := range got {
		if w, ok := want[dev.Name]; ok && dev.Status != w {
			t.Errorf("%s persisted status = %q, want %q", dev.Name, dev.Status, w)
		}
	}
}

// TestMarkStaleProbeDevicesOffline_NoTransitions verifies the common steady
// state: when nothing is stale, the call returns an empty slice and no error
// (so the poller's per-device alert loop is skipped).
func TestMarkStaleProbeDevicesOffline_NoTransitions(t *testing.T) {
	d := NewDatabaseForTesting(t)
	probeID := uint(1)
	fresh := time.Now().Add(-10 * time.Second)
	threshold := time.Now().Add(-5 * time.Minute)

	dev := models.Device{Name: "fresh", IPAddress: "10.0.0.9", ProbeID: &probeID, Enabled: true, Status: "online", LastPolled: fresh}
	if err := d.Gorm().Create(&dev).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	flipped, err := d.MarkStaleProbeDevicesOffline(threshold)
	if err != nil {
		t.Fatalf("MarkStaleProbeDevicesOffline: %v", err)
	}
	if len(flipped) != 0 {
		t.Errorf("transition set = %d devices, want 0", len(flipped))
	}
}
