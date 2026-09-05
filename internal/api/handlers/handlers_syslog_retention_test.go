package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestGetSyslogRetention_CarriesIngestRateAndProjectionKeys: the Retention
// page renders the ingest rate, projection and volume verdict from named JSON
// keys; a renamed or dropped key would silently blank the column rather than
// fail, so the contract is pinned here.
func TestGetSyslogRetention_CarriesIngestRateAndProjectionKeys(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/api/settings/syslog-retention", "")
	h.GetSyslogRetention(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{
		"rate_hours", "disk_bytes_per_row", "disk_width_measured",
		"current_syslog_bytes", "database_bytes",
		"projected_syslog_bytes", "projected_forever",
		"volume_total_bytes", "volume_free_bytes", "volume_known", "volume_total_derived",
	} {
		if _, ok := body.Data[key]; !ok {
			t.Errorf("report JSON lacks %q", key)
		}
	}

	var sevs []map[string]json.RawMessage
	if err := json.Unmarshal(body.Data["severities"], &sevs); err != nil {
		t.Fatalf("decode severities: %v", err)
	}
	if len(sevs) != 8 {
		t.Fatalf("%d severities, want 8", len(sevs))
	}
	for _, key := range []string{"rate_available", "rows_per_day", "bytes_per_day", "projected_bytes", "projected_forever"} {
		if _, ok := sevs[0][key]; !ok {
			t.Errorf("severity entry lacks %q", key)
		}
	}
}
