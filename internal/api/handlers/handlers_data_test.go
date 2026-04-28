package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// ── validateProbe (via ReceiveConfigRevision) ────────────────────────────────

func TestValidateProbe_MissingAuthHeader_Returns401(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)
	_ = device

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, "", map[string]interface{}{
		"device_id":   device.ID,
		"config_text": "test",
		"checksum":    "abc",
	})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestValidateProbe_WrongToken_Returns401(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)
	_ = device

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, "wrong-key", map[string]interface{}{
		"device_id":   device.ID,
		"config_text": "test",
		"checksum":    "abc",
	})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestValidateProbe_PendingApproval_Returns403(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)
	_ = device
	// Downgrade probe to pending
	db.Gorm().Model(probe).Update("approval_status", "pending")

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": "test",
		"checksum":    "abc",
	})

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── ReceiveConfigRevision ─────────────────────────────────────────────────────

func TestReceiveConfigRevision_FirstRevision_Saved(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": "config version 1",
		"checksum":    "aaaa1111",
		"timestamp":   time.Now(),
		"length":      16,
	})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 1 {
		t.Errorf("config revision count = %d, want 1", count)
	}
}

func TestReceiveConfigRevision_SameChecksum_Deduped_NotSaved(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	body := map[string]interface{}{
		"device_id":   device.ID,
		"config_text": "config unchanged",
		"checksum":    "dedupme",
		"length":      16,
	}
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, body)
	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, body)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	data, _ := resp["data"].(map[string]interface{})
	if data["deduped"] != true {
		t.Errorf("expected deduped=true in response, got: %v", w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 1 {
		t.Errorf("deduped: expected 1 revision in DB, got %d", count)
	}
}

func TestReceiveConfigRevision_DifferentChecksum_Saved(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id": device.ID, "config_text": "version 1", "checksum": "v1", "length": 9,
	})
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id": device.ID, "config_text": "version 2", "checksum": "v2", "length": 9,
	})

	var count int64
	db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 2 {
		t.Errorf("expected 2 revisions for different checksums, got %d", count)
	}
}

func TestReceiveConfigRevision_DeviceNotOwned_Returns403(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	// Device owned by a different probe (probeID = nil means unassigned)
	otherDevice := &models.Device{Name: "other-fw", IPAddress: "10.0.0.1"}
	db.Gorm().Create(otherDevice)

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id": otherDevice.ID, "config_text": "evil", "checksum": "evil", "length": 4,
	})

	if w.Code != http.StatusForbidden {
		t.Errorf("cross-probe data injection: status = %d, want 403", w.Code)
	}
}

func TestReceiveConfigRevision_ConfigTooLarge_Returns400(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	oversized := strings.Repeat("x", maxConfigTextSize+1)
	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": oversized,
		"checksum":    "toobig",
		"length":      len(oversized),
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized config: status = %d, want 400", w.Code)
	}
}

// ── ReceiveSystemStatuses ────────────────────────────────────────────────────

func TestReceiveSystemStatuses_Valid_Saves(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	statuses := []map[string]interface{}{{
		"device_id":  device.ID,
		"probe_id":   probe.ID,
		"timestamp":  time.Now(),
		"cpu_user":   5.0,
		"cpu_system": 2.0,
	}}

	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey, statuses)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 1 {
		t.Errorf("system status count = %d, want 1", count)
	}
}

func TestReceiveSystemStatuses_DeviceNotOwnedByProbe_Filtered(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	otherDevice := &models.Device{Name: "other-fw", IPAddress: "10.99.0.1"}
	db.Gorm().Create(otherDevice)

	statuses := []map[string]interface{}{{
		"device_id": otherDevice.ID,
		"probe_id":  probe.ID,
		"timestamp": time.Now(),
	}}

	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey, statuses)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (filtered, not rejected)", w.Code)
	}

	// Critical security test: cross-probe data must not be stored
	var count int64
	db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", otherDevice.ID).Count(&count)
	if count != 0 {
		t.Errorf("SECURITY: cross-probe status data was stored (%d rows)", count)
	}
}

func TestReceiveSystemStatuses_TruncatesAt100(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	statuses := make([]map[string]interface{}, 150)
	for i := range statuses {
		statuses[i] = map[string]interface{}{
			"device_id": device.ID,
			"probe_id":  probe.ID,
			"timestamp": time.Now(),
		}
	}

	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey, statuses)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	data, _ := resp["data"].(map[string]interface{})
	saved, _ := data["saved"].(float64)
	if saved > 100 {
		t.Errorf("saved = %v, want ≤100 (truncation not applied)", saved)
	}
}

func TestReceiveSystemStatuses_NoAuth_Returns401(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, "", []interface{}{})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
