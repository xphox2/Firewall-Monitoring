package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetTraps_HoursWindow pins the ranges the Traps page sends: without
// `hours` the list is unbounded (API back-compat), with it the scan is bounded.
func TestGetTraps_HoursWindow(t *testing.T) {
	h, db := setupTestHandler(t)
	now := time.Now()
	if err := db.Gorm().Create(&models.TrapEvent{
		Timestamp: now.Add(-48 * time.Hour),
		TrapOID:   "1.3.6.1.4.1.999.1",
		SourceIP:  "203.0.113.1",
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.TrapEvent{
		Timestamp: now.Add(-10 * time.Minute),
		TrapOID:   "1.3.6.1.4.1.999.2",
		SourceIP:  "203.0.113.2",
	}).Error; err != nil {
		t.Fatal(err)
	}

	list := func(path string) []models.TrapEvent {
		t.Helper()
		c, rec := jsonReq(http.MethodGet, path, "")
		h.GetTraps(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 (%s)", path, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data []models.TrapEvent `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal %s: %v", path, err)
		}
		return resp.Data
	}

	if got := list("/x?hours=1"); len(got) != 1 || got[0].TrapOID != "1.3.6.1.4.1.999.2" {
		t.Fatalf("hours=1 returned %+v, want only the recent trap", got)
	}
	if got := list("/x"); len(got) != 2 {
		t.Fatalf("no hours returned %d traps, want both", len(got))
	}
	// A junk window must not 500 (parsed, ignored).
	if got := list("/x?hours=abc"); len(got) != 2 {
		t.Fatalf("hours=abc returned %d traps, want both", len(got))
	}
}
