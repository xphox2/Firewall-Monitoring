package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/models"
)

// TestUpdateSettings_TelemetryStaleMinutesValidation: the TELEMETRY_STALE
// threshold knob accepts 0 (disabled) through 1440 and rejects junk — an
// unparseable value silently persisted would surface as the poller quietly
// falling back to its default.
func TestUpdateSettings_TelemetryStaleMinutesValidation(t *testing.T) {
	post := func(t *testing.T, val string) (*int, string) {
		t.Helper()
		h, db := setupTestHandler(t)
		body := []map[string]string{{"key": "telemetry_stale_minutes", "value": val, "category": "alerts", "type": "string"}}
		w := doSettingsRequest(t, h.UpdateSettings, "POST", body)
		var stored models.SystemSetting
		err := db.Gorm().Where(`"key" = ?`, "telemetry_stale_minutes").First(&stored).Error
		code := w.Code
		if err != nil {
			return &code, ""
		}
		return &code, stored.Value
	}

	for _, valid := range []string{"0", "15", "60", "1440"} {
		code, stored := post(t, valid)
		if *code != http.StatusOK || stored != valid {
			t.Errorf("value %q: code=%d stored=%q, want 200/%q", valid, *code, stored, valid)
		}
	}
	for _, invalid := range []string{"-1", "1441", "abc", "1.5", ""} {
		code, stored := post(t, invalid)
		if *code != http.StatusBadRequest || stored != "" {
			t.Errorf("value %q: code=%d stored=%q, want 400 and nothing persisted", invalid, *code, stored)
		}
	}
}
