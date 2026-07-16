package handlers

import (
	"net/http"
	"testing"
)

// TestUpdateSettings_Tranche4DetectKeys: the DDoS/sampling threshold keys
// accept positive integers (blank = default), and the three-state enable
// flags accept only 0/1/blank.
func TestUpdateSettings_Tranche4DetectKeys(t *testing.T) {
	post := func(t *testing.T, key, val string) int {
		t.Helper()
		h, _ := setupTestHandler(t)
		body := []map[string]string{{"key": key, "value": val, "category": "detection", "type": "string"}}
		return doSettingsRequest(t, h.UpdateSettings, "POST", body).Code
	}

	for _, key := range []string{"detect_ddos_bps", "detect_ddos_pps", "detect_ddos_fps",
		"detect_ddos_prefix_bps", "detect_samprate_min_rows"} {
		if code := post(t, key, "5000"); code != http.StatusOK {
			t.Errorf("%s=5000: code %d, want 200", key, code)
		}
		if code := post(t, key, ""); code != http.StatusOK {
			t.Errorf("%s blank: code %d, want 200 (blank = default)", key, code)
		}
		if code := post(t, key, "abc"); code != http.StatusBadRequest {
			t.Errorf("%s=abc: code %d, want 400", key, code)
		}
		if code := post(t, key, "0"); code != http.StatusBadRequest {
			t.Errorf("%s=0: code %d, want 400 (positive integer or blank)", key, code)
		}
	}

	for _, key := range []string{"detect_ddos_volumetric_enabled", "detect_ddos_prefix_enabled",
		"detect_sampling_rate_change_enabled"} {
		for _, ok := range []string{"0", "1", ""} {
			if code := post(t, key, ok); code != http.StatusOK {
				t.Errorf("%s=%q: code %d, want 200", key, ok, code)
			}
		}
		if code := post(t, key, "2"); code != http.StatusBadRequest {
			t.Errorf("%s=2: code %d, want 400 (three-state 0/1/blank)", key, code)
		}
	}
}
