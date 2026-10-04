package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestTestEventRule_UnscopedUsesDeviceVendor pins that an unscoped rule
// preview extracts every message with ITS device's vendor, as the live engine
// does — not with the FortiGate extractor for everything. Two devices, one
// fortigate and one opnsense, each with a FortiOS-shaped `subtype="vpn"` line
// (the OPNsense one stands in for a FortiOS field appearing in a non-FortiGate
// device's log text); a rule `subtype eq vpn` must match only the FortiGate
// message. Pre-change: matched=2 — the opnsense device's line "matched" through
// the FortiGate KV extractor, a hit the engine would never have produced.
func TestTestEventRule_UnscopedUsesDeviceVendor(t *testing.T) {
	h, db := setupTestHandler(t)

	fg := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}
	opn := &models.Device{Name: "fw-example-02", IPAddress: "192.0.2.2", Vendor: "opnsense"}
	for _, d := range []*models.Device{fg, opn} {
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("create device %s: %v", d.Name, err)
		}
	}
	const line = `date=2026-10-04 time=12:00:00 devname="fw-example" type="event" subtype="vpn" level="error" logdesc="IPsec phase 1 error" msg="IPsec phase 1 error"`
	now := time.Now()
	msgs := []models.SyslogMessage{
		{Timestamp: now, DeviceID: fg.ID, Severity: 3, Message: line},
		{Timestamp: now, DeviceID: opn.ID, Severity: 3, Message: line},
	}
	for i := range msgs {
		if err := db.Gorm().Create(&msgs[i]).Error; err != nil {
			t.Fatalf("create syslog %d: %v", i, err)
		}
	}

	post := func(vendorScope string) map[string]interface{} {
		t.Helper()
		router := gin.New()
		router.POST("/event-rules/test", h.TestEventRule)
		body, _ := json.Marshal(map[string]interface{}{
			"match_json":   `{"op":"eq","field":"subtype","value":"vpn"}`,
			"vendor_scope": vendorScope,
			"limit":        100,
		})
		req := httptest.NewRequest(http.MethodPost, "/event-rules/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
		}
		var resp struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v (%s)", err, w.Body.String())
		}
		return resp.Data
	}

	// Unscoped: per-device vendor. Only the FortiGate message carries a
	// `subtype` field once the opnsense line goes through the filterlog
	// extractor (which finds no CSV and adds nothing).
	d := post("")
	if got := d["scanned"]; got != float64(2) {
		t.Fatalf("scanned = %v, want 2", got)
	}
	if got := d["matched"]; got != float64(1) {
		t.Errorf("unscoped matched = %v, want 1 (only the fortigate device's message)", got)
	}

	// Explicit scope is unchanged: every message is extracted with that vendor,
	// so both lines match under a fortigate scope and neither under opnsense.
	if got := post("fortigate")["matched"]; got != float64(2) {
		t.Errorf("fortigate-scoped matched = %v, want 2", got)
	}
	if got := post("opnsense")["matched"]; got != float64(0) {
		t.Errorf("opnsense-scoped matched = %v, want 0", got)
	}
}
