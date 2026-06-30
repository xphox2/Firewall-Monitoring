package main

import (
	"testing"

	"firewall-mon/internal/detect"
)

// TestApplyDetectSettings verifies the admin-UI override precedence: a valid
// positive system_setting overrides the env/default base; a blank, invalid, or
// non-positive value leaves the base untouched (falls back to env → default).
func TestApplyDetectSettings(t *testing.T) {
	base := detect.Config{
		PortScanPorts:      100,
		SuperSpreaderHosts: 100,
		DataExfilBytes:     1 << 30,
		BeaconMinSamples:   8,
		BeaconMaxAvgBytes:  1500,
		BeaconMaxCV:        0.35,
		CapacityThreshold:  0.80,
	}

	// Override a subset; leave others blank/invalid to prove fall-through.
	got := applyDetectSettings(base, map[string]string{
		"detect_port_scan_ports":      "40",
		"detect_capacity_threshold":   "0.9",
		"detect_super_spreader_hosts": "",    // blank → keep base
		"detect_beacon_max_cv":        "abc", // invalid → keep base
		"detect_beacon_min_samples":   "0",   // non-positive → keep base
		"detect_data_exfil_bytes":     "536870912",
	})

	if got.PortScanPorts != 40 {
		t.Errorf("PortScanPorts = %d, want 40 (overridden)", got.PortScanPorts)
	}
	if got.CapacityThreshold != 0.9 {
		t.Errorf("CapacityThreshold = %v, want 0.9 (overridden)", got.CapacityThreshold)
	}
	if got.DataExfilBytes != 536870912 {
		t.Errorf("DataExfilBytes = %d, want 536870912 (overridden)", got.DataExfilBytes)
	}
	if got.SuperSpreaderHosts != 100 {
		t.Errorf("SuperSpreaderHosts = %d, want 100 (blank → base)", got.SuperSpreaderHosts)
	}
	if got.BeaconMaxCV != 0.35 {
		t.Errorf("BeaconMaxCV = %v, want 0.35 (invalid → base)", got.BeaconMaxCV)
	}
	if got.BeaconMinSamples != 8 {
		t.Errorf("BeaconMinSamples = %d, want 8 (non-positive → base)", got.BeaconMinSamples)
	}

	// Empty map = base unchanged.
	if applyDetectSettings(base, map[string]string{}) != base {
		t.Errorf("empty settings map must leave base unchanged")
	}
}
