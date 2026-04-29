package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// doDiffEndpointRequest invokes GetDeviceConfigDiff via gin's test recorder
// using the same path shape (`/api/devices/:id/config-history/diff`) the
// production router registers. This catches any param-binding mismatch the
// production setup might have.
func doDiffEndpointRequest(t *testing.T, h *Handler, deviceID, fromID, toID uint) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET("/api/devices/:id/config-history/diff", h.GetDeviceConfigDiff)
	url := "/api/devices/" + strconv.FormatUint(uint64(deviceID), 10) +
		"/config-history/diff?from=" + strconv.FormatUint(uint64(fromID), 10) +
		"&to=" + strconv.FormatUint(uint64(toID), 10)
	req := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestGetDeviceConfigDiff_ResponseShape_MatchesJSExpectations is the
// integration test for the diff endpoint. The JS in admin-device-detail.js
// reads these exact fields from the response, in this exact shape — if any
// drift, the modal renders blank or throws. Asserting the contract here means
// any future server-side change that breaks the modal fails CI before it
// reaches the user.
func TestGetDeviceConfigDiff_ResponseShape_MatchesJSExpectations(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)

	// Two real-shaped FortiGate revisions. Same NormalizedChecksum so the
	// "logically identical" banner path triggers on the JS side — we test
	// both diff paths via separate cases below.
	rev1 := &models.DeviceConfigRevision{
		DeviceID:           device.ID,
		Checksum:           "raw-md5-1",
		NormalizedChecksum: "norm-md5-A",
		ConfigText:         fortigateRawA,
		Length:             len(fortigateRawA),
		TriggerSource:      "syslog",
		BackupQuality:      "full",
	}
	rev2 := &models.DeviceConfigRevision{
		DeviceID:           device.ID,
		Checksum:           "raw-md5-2",
		NormalizedChecksum: "norm-md5-A", // SAME → "logically identical" case
		ConfigText:         fortigateRawB,
		Length:             len(fortigateRawB),
		TriggerSource:      "poll",
		BackupQuality:      "full",
	}
	if err := h.db.Gorm().Create(rev1).Error; err != nil {
		t.Fatalf("create rev1: %v", err)
	}
	if err := h.db.Gorm().Create(rev2).Error; err != nil {
		t.Fatalf("create rev2: %v", err)
	}

	w := doDiffEndpointRequest(t, h, device.ID, rev1.ID, rev2.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			From struct {
				ID                 uint   `json:"id"`
				Timestamp          string `json:"timestamp"`
				Checksum           string `json:"checksum"`
				NormalizedChecksum string `json:"normalized_checksum"`
				TriggerSource      string `json:"trigger_source"`
				BackupQuality      string `json:"backup_quality"`
				ConfigText         string `json:"config_text"`
			} `json:"from"`
			To struct {
				ID                 uint   `json:"id"`
				Timestamp          string `json:"timestamp"`
				Checksum           string `json:"checksum"`
				NormalizedChecksum string `json:"normalized_checksum"`
				TriggerSource      string `json:"trigger_source"`
				BackupQuality      string `json:"backup_quality"`
				ConfigText         string `json:"config_text"`
			} `json:"to"`
			Vendor           string                          `json:"vendor"`
			VolatilePatterns []map[string]interface{}        `json:"volatile_patterns"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}

	if !resp.Success {
		t.Fatalf("success = false; body=%s", w.Body.String())
	}

	// Every field the JS reads MUST be present and correctly populated.
	if resp.Data.From.ID != rev1.ID {
		t.Errorf("from.id = %d, want %d", resp.Data.From.ID, rev1.ID)
	}
	if resp.Data.To.ID != rev2.ID {
		t.Errorf("to.id = %d, want %d", resp.Data.To.ID, rev2.ID)
	}
	if resp.Data.From.ConfigText != fortigateRawA {
		t.Errorf("from.config_text mismatch (got %d bytes, want %d)",
			len(resp.Data.From.ConfigText), len(fortigateRawA))
	}
	if resp.Data.To.ConfigText != fortigateRawB {
		t.Errorf("to.config_text mismatch (got %d bytes, want %d)",
			len(resp.Data.To.ConfigText), len(fortigateRawB))
	}
	if resp.Data.From.NormalizedChecksum != "norm-md5-A" {
		t.Errorf("from.normalized_checksum = %q, want %q", resp.Data.From.NormalizedChecksum, "norm-md5-A")
	}
	if resp.Data.To.NormalizedChecksum != "norm-md5-A" {
		t.Errorf("to.normalized_checksum = %q, want %q", resp.Data.To.NormalizedChecksum, "norm-md5-A")
	}
	if resp.Data.From.TriggerSource != "syslog" {
		t.Errorf("from.trigger_source = %q, want %q", resp.Data.From.TriggerSource, "syslog")
	}
	if resp.Data.From.BackupQuality != "full" {
		t.Errorf("from.backup_quality = %q, want %q", resp.Data.From.BackupQuality, "full")
	}

	// Vendor + volatile_patterns power the masking in the JS renderer.
	if resp.Data.Vendor != "fortigate" {
		t.Errorf("vendor = %q, want %q", resp.Data.Vendor, "fortigate")
	}
	if len(resp.Data.VolatilePatterns) == 0 {
		t.Error("volatile_patterns is empty — JS won't be able to mask volatile lines")
	}

	// Each volatile pattern must have name + regex (the JS compiles the regex).
	for i, p := range resp.Data.VolatilePatterns {
		if _, ok := p["name"].(string); !ok {
			t.Errorf("volatile_patterns[%d] missing string `name`", i)
		}
		if _, ok := p["regex"].(string); !ok {
			t.Errorf("volatile_patterns[%d] missing string `regex`", i)
		}
	}
}

// TestGetDeviceConfigDiff_NotFound_404 — bad revision IDs return 404, JS
// renders a visible error in the modal body.
func TestGetDeviceConfigDiff_NotFound_404(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)
	w := doDiffEndpointRequest(t, h, device.ID, 999, 1000)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for missing revisions", w.Code)
	}
}

// TestGetDeviceConfigDiff_InvalidParams_400 — missing from/to should 400.
func TestGetDeviceConfigDiff_InvalidParams_400(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)
	router := gin.New()
	router.GET("/api/devices/:id/config-history/diff", h.GetDeviceConfigDiff)
	req := httptest.NewRequest("GET", "/api/devices/"+strconv.FormatUint(uint64(device.ID), 10)+"/config-history/diff", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing params", w.Code)
	}
}

// TestGetDeviceConfigDiff_NonFortiGateDevice_NoVolatilePatterns — devices
// without a known vendor get the identity normalizer; volatile_patterns
// should be empty (or null) so the JS doesn't try to mask anything.
func TestGetDeviceConfigDiff_NonFortiGateDevice_NoVolatilePatterns(t *testing.T) {
	h, db := setupTestHandler(t)
	probe := &models.Probe{
		Name:            "test-probe",
		RegistrationKey: "k",
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("create probe: %v", err)
	}
	device := &models.Device{
		Name: "generic-fw", IPAddress: "10.0.0.1", Vendor: "paloalto", ProbeID: &probe.ID,
	}
	if err := db.Gorm().Create(device).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	r1 := &models.DeviceConfigRevision{
		DeviceID: device.ID, Checksum: "x", NormalizedChecksum: "n1", ConfigText: "a", Length: 1,
	}
	r2 := &models.DeviceConfigRevision{
		DeviceID: device.ID, Checksum: "y", NormalizedChecksum: "n2", ConfigText: "b", Length: 1,
	}
	db.Gorm().Create(r1)
	db.Gorm().Create(r2)

	w := doDiffEndpointRequest(t, h, device.ID, r1.ID, r2.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Data struct {
			Vendor           string                   `json:"vendor"`
			VolatilePatterns []map[string]interface{} `json:"volatile_patterns"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Data.Vendor != "paloalto" {
		t.Errorf("vendor = %q, want %q", resp.Data.Vendor, "paloalto")
	}
	if len(resp.Data.VolatilePatterns) != 0 {
		t.Errorf("volatile_patterns should be empty for paloalto (no vendor-specific masking yet); got %d", len(resp.Data.VolatilePatterns))
	}
}
