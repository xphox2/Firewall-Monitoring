package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

const fortiDenyLine = `subtype="forward" srcip=203.0.113.9 srcport=44000 srcintf="wan1" srcintfrole="wan" ` +
	`dstip=198.51.100.150 dstport=3389 dstintf="root" proto=6 action="deny" policyid=20 policytype="policy" service="RDP"`

// TestProjectDeniedEvents_NoVendorIsGeneric: a FortiOS action="deny" line is
// projected only when its device is tagged fortigate. DeviceID 0 (no device),
// a device whose vendor is "generic" and a device whose vendor is stored empty
// all project nothing — the old code treated every one of those as a
// FortiGate.
func TestProjectDeniedEvents_NoVendorIsGeneric(t *testing.T) {
	h, db := setupTestHandler(t)
	generic := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "generic"}
	forti := &models.Device{Name: "fw-example-02", IPAddress: "192.0.2.2", Vendor: "fortigate"}
	empty := &models.Device{Name: "fw-example-03", IPAddress: "192.0.2.3", Vendor: "fortigate"}
	for _, d := range []*models.Device{generic, forti, empty} {
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}
	// A pre-v71 row shape: vendor stored as ''. Written with raw SQL because
	// GORM would apply the column default to a zero-valued field.
	if err := db.Gorm().Exec(`UPDATE devices SET vendor = '' WHERE id = ?`, empty.ID).Error; err != nil {
		t.Fatalf("blank vendor: %v", err)
	}
	now := time.Now()
	msg := func(id uint) models.SyslogMessage {
		return models.SyslogMessage{DeviceID: id, ProbeID: 1, Timestamp: now, Message: fortiDenyLine}
	}

	for _, tc := range []struct {
		name string
		id   uint
		want int64
	}{
		{"device id 0", 0, 0},
		{"vendor generic", generic.ID, 0},
		{"vendor empty", empty.ID, 0},
		{"vendor fortigate", forti.ID, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := db.Gorm().Exec(`DELETE FROM denied_events`).Error; err != nil {
				t.Fatal(err)
			}
			h.projectDeniedEvents([]models.SyslogMessage{msg(tc.id)})
			var n int64
			db.Gorm().Model(&models.DeniedEvent{}).Count(&n)
			if n != tc.want {
				t.Fatalf("denied_events = %d, want %d", n, tc.want)
			}
		})
	}
}

// TestDeviceVendor_FallbacksAndCache: the resolver's contract — generic for
// id 0, a missing row and an empty value; lower-cased otherwise; and one
// GetDevice per id per TTL (a vendor change is seen only after the entry
// expires, which the test forces).
func TestDeviceVendor_FallbacksAndCache(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "OPNsense"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	if got := h.deviceVendor(0); got != GenericVendor {
		t.Errorf("deviceVendor(0) = %q", got)
	}
	if got := h.deviceVendor(dev.ID + 100); got != GenericVendor {
		t.Errorf("deviceVendor(missing) = %q", got)
	}
	if got := h.deviceVendor(dev.ID); got != "opnsense" {
		t.Errorf("deviceVendor(opnsense device) = %q", got)
	}
	// Cached: a change in the row is not seen until the entry expires.
	if err := db.Gorm().Exec(`UPDATE devices SET vendor = 'pfsense' WHERE id = ?`, dev.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got := h.deviceVendor(dev.ID); got != "opnsense" {
		t.Errorf("deviceVendor within TTL = %q, want the cached opnsense", got)
	}
	h.mu.Lock()
	h.deviceVendorCache[dev.ID] = deviceVendorEntry{vendor: "opnsense", expiry: time.Now().Add(-time.Second)}
	h.mu.Unlock()
	if got := h.deviceVendor(dev.ID); got != "pfsense" {
		t.Errorf("deviceVendor after expiry = %q, want pfsense", got)
	}
	if err := db.Gorm().Exec(`UPDATE devices SET vendor = '' WHERE id = ?`, dev.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	delete(h.deviceVendorCache, dev.ID)
	h.mu.Unlock()
	if got := h.deviceVendor(dev.ID); got != GenericVendor {
		t.Errorf("deviceVendor(empty vendor) = %q, want generic", got)
	}
}

// TestCreateDevice_DefaultVendorIsGeneric: POST /admin/api/devices without a
// vendor stores "generic" (was "fortigate"), and the 400 for an unknown vendor
// lists every accepted name from validVendors.
func TestCreateDevice_DefaultVendorIsGeneric(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	body, _ := json.Marshal(map[string]interface{}{"name": "fw-example-09", "ip_address": "192.0.2.9", "probe_id": probe.ID})
	c, rec := jsonReq(http.MethodPost, "/x", string(body))
	h.CreateDevice(c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data models.Device `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Vendor != "generic" {
		t.Errorf("response vendor = %q, want generic", resp.Data.Vendor)
	}
	stored, err := db.GetDevice(resp.Data.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Vendor != "generic" {
		t.Errorf("stored vendor = %q, want generic", stored.Vendor)
	}

	body, _ = json.Marshal(map[string]interface{}{"name": "fw-example-10", "ip_address": "192.0.2.10", "probe_id": probe.ID, "vendor": "acme"})
	c, rec = jsonReq(http.MethodPost, "/x", string(body))
	h.CreateDevice(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown vendor = %d %s, want 400", rec.Code, rec.Body.String())
	}
	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	for v := range validVendors {
		if !strings.Contains(errResp.Error, v) {
			t.Errorf("400 body %q does not list vendor %q", errResp.Error, v)
		}
	}
}
