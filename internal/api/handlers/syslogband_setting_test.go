package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The band boundary is an operator setting, so the API is its contract. It is
// clamped server-side too, but the API REJECTS rather than clamping so the
// operator learns the bound instead of silently getting something else.

func postBoundary(t *testing.T, h *Handler, value string) int {
	t.Helper()
	router := gin.New()
	router.POST("/settings", h.UpdateSettings)

	body, _ := json.Marshal([]map[string]string{
		{"key": "syslog_critical_below_severity", "value": value, "category": "retention", "type": "string"},
	})
	req := httptest.NewRequest("POST", "/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code
}

func TestSyslogBandSetting_AcceptsTheUsefulRange(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, v := range []string{"1", "4", "5", "6"} {
		if code := postBoundary(t, h, v); code != http.StatusOK {
			t.Errorf("boundary %q rejected with %d — 1..6 must all be settable", v, code)
		}
	}
}

// Above 6 the setting would silently break its own promise: cleanup would grant
// severity 6 the long critical window while syslog aggregation keeps deleting it
// at the informational age on its own cadence.
func TestSyslogBandSetting_RejectsAboveAggregationThreshold(t *testing.T) {
	h, _ := setupTestHandler(t)
	if code := postBoundary(t, h, "7"); code != http.StatusBadRequest {
		t.Errorf("boundary 7 accepted with %d, want 400 — severity 6+ is owned by "+
			"aggregation, so a boundary above it cannot be honoured", code)
	}
}

func TestSyslogBandSetting_RejectsNonPositiveAndGarbage(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, v := range []string{"0", "-1", "", "notanumber"} {
		if code := postBoundary(t, h, v); code != http.StatusBadRequest {
			t.Errorf("boundary %q accepted with %d, want 400", v, code)
		}
	}
}
