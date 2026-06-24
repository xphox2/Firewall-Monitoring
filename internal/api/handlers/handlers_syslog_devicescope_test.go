package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestReceiveSyslog_DeviceNotOwnedByProbe_Filtered is the regression for the
// 2026-06-23 CTO-loop H1 finding: ReceiveSyslogMessages was the only ingestion
// handler that did NOT enforce the per-probe device allow-list, so a probe could
// POST syslog attributed to ANY device (alert injection + forged config-change
// attribution against another site's device). The handler now mirrors its
// siblings: any DeviceID the probe does not own is dropped.
func TestReceiveSyslog_DeviceNotOwnedByProbe_Filtered(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	// A device the probe does NOT own (unassigned).
	otherDevice := &models.Device{Name: "victim-fw", IPAddress: "10.99.0.1"}
	db.Gorm().Create(otherDevice)

	msgs := []map[string]interface{}{{
		"device_id": otherDevice.ID, // spoofed: not owned by this probe
		"severity":  1,              // would fire SYSLOG_CRITICAL
		"message":   "forged critical event",
		"timestamp": time.Now(),
	}}

	w := doTestRequest(t, h.ReceiveSyslogMessages, "POST", "/syslog", probe.ID, probe.RegistrationKey, msgs)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (filtered, not rejected); body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	data, _ := resp["data"].(map[string]interface{})
	if saved, _ := data["saved"].(float64); saved != 0 {
		t.Errorf("saved = %v, want 0 (spoofed cross-probe message must be dropped)", saved)
	}

	// Critical security assertion: nothing stored against the victim device.
	var count int64
	db.Gorm().Model(&models.SyslogMessage{}).Where("device_id = ?", otherDevice.ID).Count(&count)
	if count != 0 {
		t.Errorf("SECURITY: %d cross-probe syslog row(s) stored against an unowned device", count)
	}
}

// TestReceiveSyslog_OwnDevice_Saved confirms the allow-list change does not
// reject legitimate, owned-device traffic.
func TestReceiveSyslog_OwnDevice_Saved(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	msgs := []map[string]interface{}{{
		"device_id": device.ID,
		"severity":  5,
		"message":   "legit event",
		"timestamp": time.Now(),
	}}

	w := doTestRequest(t, h.ReceiveSyslogMessages, "POST", "/syslog", probe.ID, probe.RegistrationKey, msgs)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.SyslogMessage{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 1 {
		t.Errorf("owned-device syslog count = %d, want 1", count)
	}
}

// TestReceiveSyslog_DevicelessSaved confirms device-less syslog (DeviceID 0,
// the common case for messages whose source IP resolves to no monitored device)
// is still stored — the allow-list only gates a positive, unowned DeviceID.
func TestReceiveSyslog_DevicelessSaved(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	msgs := []map[string]interface{}{{
		// no device_id; a source IP that resolves to nothing
		"source_ip": "203.0.113.50",
		"severity":  5,
		"message":   "device-less event",
		"timestamp": time.Now(),
	}}

	w := doTestRequest(t, h.ReceiveSyslogMessages, "POST", "/syslog", probe.ID, probe.RegistrationKey, msgs)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ? AND device_id = 0", probe.ID).Count(&count)
	if count != 1 {
		t.Errorf("device-less syslog count = %d, want 1 (must not be dropped)", count)
	}
}
