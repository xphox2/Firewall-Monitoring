package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetNetEvents_Shape seeds one net_event and asserts the handler returns a
// 200 with the events/total/total_capped envelope the Events page reads.
func TestGetNetEvents_Shape(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-1", IPAddress: "10.0.0.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	row := &models.NetEvent{
		Ts:       time.Now(),
		DeviceID: dev.ID,
		Activity: 3,
		Action:   1,
	}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed net_event: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x?hours=24", "")
	h.GetNetEvents(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Events      []models.NetEvent `json:"events"`
			Total       int64             `json:"total"`
			TotalCapped bool              `json:"total_capped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || resp.Data.Total != 1 || len(resp.Data.Events) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

// TestGetNetEvents_BadNumericParams asserts non-numeric numeric filters are
// rejected with 400 before being bound against uint/smallint columns (AUDIT-251
// / 22P02). Only the first offending filter matters for the assertion; each is
// exercised independently.
func TestGetNetEvents_BadNumericParams(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, param := range []string{"device_id", "probe_id", "site_id", "activity", "action"} {
		c, rec := jsonReq(http.MethodGet, "/x?"+param+"=not-a-number", "")
		h.GetNetEvents(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetNetEvents(%s=not-a-number) = %d, want 400", param, rec.Code)
		}
	}
}

// TestGetNetEvents_BadIPParams asserts a malformed src_ip/dst_ip is rejected
// with 400 (not a 500 from an invalid inet cast on Postgres) before it reaches
// the query, while a valid bare IP or CIDR passes.
func TestGetNetEvents_BadIPParams(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, tc := range []struct{ param, val string }{
		{"src_ip", "not-an-ip"},
		{"src_ip", "10.0.0.0/99"},
		{"dst_ip", "999.999.999.999"},
		{"dst_ip", "10.0.0.0/8/8"},
	} {
		c, rec := jsonReq(http.MethodGet, "/x?"+tc.param+"="+tc.val, "")
		h.GetNetEvents(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetNetEvents(%s=%q) = %d, want 400", tc.param, tc.val, rec.Code)
		}
	}
	for _, ok := range []string{"10.0.0.5", "10.0.0.0/24", "2001:db8::1"} {
		c, rec := jsonReq(http.MethodGet, "/x?src_ip="+ok, "")
		h.GetNetEvents(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetNetEvents(src_ip=%q) = %d, want 200", ok, rec.Code)
		}
	}
}
