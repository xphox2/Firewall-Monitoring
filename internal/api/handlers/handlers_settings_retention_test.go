package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// retentionKeyList is the 12 GUI retention keys, in the same order the page
// renders them, so the field-count and key-set assertions stay in sync with the
// handler's retentionGUIKnobs.
var retentionKeyList = []string{
	database.RetentionDefaultDaysKey,
	database.RetentionSyslogMonthsKey,
	database.RetentionFlowDaysKey,
	database.RetentionFlowRollupDaysKey,
	database.RetentionTrapDaysKey,
	database.RetentionStatusDaysKey,
	database.RetentionAlertDaysKey,
	database.RetentionDeniedEventDaysKey,
	database.RetentionNetEventDaysKey,
	database.RetentionSecEventDaysKey,
	database.RetentionSecConfigChangeDaysKey,
	database.RetentionNetEventRollupDaysKey,
}

func settingsBody(kv map[string]string) string {
	list := make([]map[string]string, 0, len(kv))
	for k, v := range kv {
		list = append(list, map[string]string{"key": k, "value": v})
	}
	b, _ := json.Marshal(list)
	return string(b)
}

// Blank, 0 and a concrete N are all accepted for the 12 day/knob keys.
func TestUpdateSettings_RetentionKnobsAcceptBlankZeroAndN(t *testing.T) {
	h, _ := setupTestHandler(t)
	kv := map[string]string{}
	for i, k := range retentionKeyList {
		switch i % 3 {
		case 0:
			kv[k] = "" // blank: clear the override
		case 1:
			kv[k] = "0"
		default:
			if k == database.RetentionSyslogMonthsKey {
				kv[k] = "6"
			} else {
				kv[k] = "30"
			}
		}
	}
	c, rec := jsonReq(http.MethodPost, "/api/settings", settingsBody(kv))
	h.UpdateSettings(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// Out-of-range and non-integer values are rejected for the 12 keys.
func TestUpdateSettings_RetentionKnobsRejectInvalid(t *testing.T) {
	cases := []struct {
		key, value, name string
	}{
		{database.RetentionDefaultDaysKey, "-1", "negative"},
		{database.RetentionFlowDaysKey, "3651", "above 3650"},
		{database.RetentionTrapDaysKey, "abc", "non-integer"},
		{database.RetentionNetEventDaysKey, "3651", "net event above 3650"},
		{database.RetentionSecConfigChangeDaysKey, "-1", "sec config negative"},
		{database.RetentionSyslogMonthsKey, "121", "months above 120"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := setupTestHandler(t)
			c, rec := jsonReq(http.MethodPost, "/api/settings", settingsBody(map[string]string{tc.key: tc.value}))
			h.UpdateSettings(c)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s=%q: status = %d, want 400: %s", tc.key, tc.value, rec.Code, rec.Body.String())
			}
		})
	}
}

// GetRetentionSettings returns one field per knob with the right stored,
// value and source: "ui" when a value is stored, else "env" when the
// environment set it, else "default".
func TestGetRetentionSettings_FieldsSourceStoredValue(t *testing.T) {
	h, db := setupTestHandler(t)
	h.config.Retention = config.RetentionConfig{
		DefaultDays:         90,
		SyslogMonths:        0,
		FlowDays:            365,
		NetEventDays:        30,
		SecConfigChangeDays: 0,
	}
	// Store two overrides so their fields read source="ui".
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.RetentionDefaultDaysKey, Value: "45"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.RetentionNetEventDaysKey, Value: "14"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/api/settings/retention", "")
	h.GetRetentionSettings(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Fields []struct {
				Key      string `json:"key"`
				EnvKey   string `json:"env_key"`
				Stored   string `json:"stored"`
				EnvValue string `json:"env_value"`
				Value    string `json:"value"`
				Source   string `json:"source"`
				Unit     string `json:"unit"`
				Min      int    `json:"min"`
				Max      int    `json:"max"`
			} `json:"fields"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data.Fields) != 12 {
		t.Fatalf("got %d fields, want 12", len(body.Data.Fields))
	}
	byKey := map[string]struct{ Stored, EnvValue, Value, Source string }{}
	for _, f := range body.Data.Fields {
		byKey[f.Key] = struct{ Stored, EnvValue, Value, Source string }{f.Stored, f.EnvValue, f.Value, f.Source}
	}

	// Stored override → source "ui", stored and value both 45.
	if f := byKey[database.RetentionDefaultDaysKey]; f.Stored != "45" || f.Value != "45" || f.Source != "ui" {
		t.Errorf("default_days = %+v, want stored=45 value=45 source=ui", f)
	}
	// Net event 0-semantics: stored 14 wins; source ui.
	if f := byKey[database.RetentionNetEventDaysKey]; f.Stored != "14" || f.Value != "14" || f.Source != "ui" {
		t.Errorf("net_event_days = %+v, want stored=14 value=14 source=ui", f)
	}
	// Unstored, env unset → source "default", value from the env config.
	if f := byKey[database.RetentionFlowDaysKey]; f.Stored != "" || f.Source != "default" || f.Value != "365" {
		t.Errorf("flow_days = %+v, want stored=\"\" source=default value=365", f)
	}
	// Months knob max is 120.
	if f := body.Data.Fields[1]; f.Key != database.RetentionSyslogMonthsKey || f.Max != 120 || f.Unit != "months" {
		t.Errorf("syslog_months field = %+v, want key=%s max=120 unit=months", f, database.RetentionSyslogMonthsKey)
	}
}

// GetRetentionSettings reports source="env" when the environment set the key
// and nothing is stored.
func TestGetRetentionSettings_EnvSource(t *testing.T) {
	t.Setenv("RETENTION_FLOW_DAYS", "222")
	cfg := config.Load()

	h, _ := setupTestHandler(t)
	h.config = cfg

	c, rec := jsonReq(http.MethodGet, "/api/settings/retention", "")
	h.GetRetentionSettings(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Fields []struct {
				Key      string `json:"key"`
				Stored   string `json:"stored"`
				EnvValue string `json:"env_value"`
				Value    string `json:"value"`
				Source   string `json:"source"`
			} `json:"fields"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, f := range body.Data.Fields {
		if f.Key == database.RetentionFlowDaysKey {
			if f.Source != "env" || f.Stored != "" || f.EnvValue != "222" || f.Value != "222" {
				t.Errorf("flow_days = %+v, want source=env stored=\"\" env_value=222 value=222", f)
			}
			return
		}
	}
	t.Fatalf("flow_days field not found")
}
