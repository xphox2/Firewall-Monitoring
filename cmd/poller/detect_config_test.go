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

// TestApplyDetectSettings_Tranche4Knobs: the DDoS/sampling knobs follow the
// same positive-overrides / blank-falls-through convention.
func TestApplyDetectSettings_Tranche4Knobs(t *testing.T) {
	base := detect.Config{DDoSBps: 1_000_000_000, DDoSPps: 20_000, DDoSFps: 3_500, SampRateMinRows: 3}
	got := applyDetectSettings(base, map[string]string{
		"detect_ddos_bps":          "500000000",
		"detect_ddos_pps":          "",   // blank → base
		"detect_ddos_fps":          "-5", // non-positive → base
		"detect_ddos_prefix_pps":   "9000",
		"detect_samprate_min_rows": "10",
	})
	if got.DDoSBps != 500_000_000 || got.DDoSPps != 20_000 || got.DDoSFps != 3_500 {
		t.Errorf("ddos thresholds wrong: %+v", got)
	}
	if got.DDoSPrefixPps != 9000 || got.SampRateMinRows != 10 {
		t.Errorf("prefix/samprate wrong: %+v", got)
	}
}

// TestApplyDetectSettings_EnabledFlagsThreeState pins the dedicated parser for
// detect_<name>_enabled: DB "0" disables, DB "1" enables, blank/other keeps
// the env-derived base — the numeric "<=0 falls through" convention would
// have eaten the 0-means-disabled semantics.
func TestApplyDetectSettings_EnabledFlagsThreeState(t *testing.T) {
	t.Run("db-0-disables", func(t *testing.T) {
		got := applyDetectSettings(detect.Config{}, map[string]string{"detect_ddos_volumetric_enabled": "0"})
		if !got.DDoSVolumetricDisabled {
			t.Error("DB \"0\" must disable")
		}
	})
	t.Run("db-1-enables-over-env-disable", func(t *testing.T) {
		base := detect.Config{DDoSPrefixDisabled: true} // env said disabled
		got := applyDetectSettings(base, map[string]string{"detect_ddos_prefix_enabled": "1"})
		if got.DDoSPrefixDisabled {
			t.Error("DB \"1\" must override an env-level disable")
		}
	})
	t.Run("blank-keeps-env", func(t *testing.T) {
		base := detect.Config{SamplingRateChangeDisabled: true}
		got := applyDetectSettings(base, map[string]string{"detect_sampling_rate_change_enabled": ""})
		if !got.SamplingRateChangeDisabled {
			t.Error("blank must keep the env-derived value")
		}
		got = applyDetectSettings(detect.Config{}, map[string]string{})
		if got.SamplingRateChangeDisabled {
			t.Error("absent key must keep the (enabled) zero value")
		}
	})
	t.Run("garbage-keeps-env", func(t *testing.T) {
		got := applyDetectSettings(detect.Config{}, map[string]string{"detect_ddos_volumetric_enabled": "yes"})
		if got.DDoSVolumetricDisabled {
			t.Error("unparseable value must not disable")
		}
	})
}
