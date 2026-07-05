package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// getFlowSamplesJSON hits GET /admin/api/flows with the given query string and
// returns the decoded sample list.
func getFlowSamplesJSON(t *testing.T, h *Handler, query string) []models.FlowSample {
	t.Helper()
	router := gin.New()
	router.GET("/admin/api/flows", h.GetFlowSamples)
	req := httptest.NewRequest("GET", "/admin/api/flows"+query, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/flows%s = %d: %s", query, w.Code, w.Body.String())
	}
	var resp struct {
		Data []models.FlowSample `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Data
}

// TestGetFlowSamples_FirewallEventFilter pins the LC-52 read path: the flows
// list honors a firewall_event param (0 is a real value — "no event"), and a
// junk value is ignored rather than 500ing (L24 numeric-filter rule).
func TestGetFlowSamples_FirewallEventFilter(t *testing.T) {
	h, db := setupTestHandler(t)
	now := time.Now()
	samples := []models.FlowSample{
		{Timestamp: now, SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", Protocol: 6, Bytes: 100},
		{Timestamp: now, SrcAddr: "192.0.2.9", DstAddr: "10.0.0.4", Protocol: 6,
			FirewallEvent: models.FirewallEventDenied},
		{Timestamp: now, SrcAddr: "192.0.2.9", DstAddr: "10.0.0.5", Protocol: 6,
			FirewallEvent: models.FirewallEventDenied},
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	denied := getFlowSamplesJSON(t, h, "?firewall_event=3")
	if len(denied) != 2 {
		t.Errorf("firewall_event=3 returned %d rows, want 2", len(denied))
	}
	for _, s := range denied {
		if s.FirewallEvent != models.FirewallEventDenied {
			t.Errorf("firewall_event=3 leaked row with event=%d", s.FirewallEvent)
		}
	}
	if none := getFlowSamplesJSON(t, h, "?firewall_event=0"); len(none) != 1 {
		t.Errorf("firewall_event=0 returned %d rows, want 1 — zero must act as a real filter", len(none))
	}
	// Junk value: ignored (all rows), never a 500 (dialect-safe numeric parse).
	if all := getFlowSamplesJSON(t, h, "?firewall_event=bogus"); len(all) != 3 {
		t.Errorf("junk firewall_event returned %d rows, want 3 (filter ignored)", len(all))
	}
}

// TestGetFlowSamples_HoursFilter pins the LC-36 fix: the samples list (and
// therefore the CSV export built from it) honors an hours window, so an
// export labeled "24h" no longer silently spans days. Absent/invalid hours
// keeps the legacy unbounded newest-first behavior for API back-compat.
func TestGetFlowSamples_HoursFilter(t *testing.T) {
	h, db := setupTestHandler(t)
	now := time.Now()
	samples := []models.FlowSample{
		{Timestamp: now.Add(-10 * time.Minute), SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", Protocol: 6},
		{Timestamp: now.Add(-3 * time.Hour), SrcAddr: "10.0.0.2", DstAddr: "8.8.8.8", Protocol: 6},
		{Timestamp: now.Add(-3 * 24 * time.Hour), SrcAddr: "10.0.0.3", DstAddr: "8.8.8.8", Protocol: 6},
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if got := getFlowSamplesJSON(t, h, "?hours=1"); len(got) != 1 {
		t.Errorf("hours=1 returned %d rows, want 1", len(got))
	}
	if got := getFlowSamplesJSON(t, h, "?hours=24"); len(got) != 2 {
		t.Errorf("hours=24 returned %d rows, want 2", len(got))
	}
	if got := getFlowSamplesJSON(t, h, ""); len(got) != 3 {
		t.Errorf("no hours param returned %d rows, want 3 (back-compat: unbounded)", len(got))
	}
	// Out-of-range values are ignored, mirroring httputil.ParseHours bounds.
	if got := getFlowSamplesJSON(t, h, "?hours=999999"); len(got) != 3 {
		t.Errorf("hours=999999 returned %d rows, want 3 (over-cap value ignored)", len(got))
	}
	if got := getFlowSamplesJSON(t, h, "?hours=-5"); len(got) != 3 {
		t.Errorf("hours=-5 returned %d rows, want 3 (invalid value ignored)", len(got))
	}
}
