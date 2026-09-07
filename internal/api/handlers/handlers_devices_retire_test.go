package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func idParam(id uint) gin.Params {
	return gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
}

// TestRetireRestoreDevice_Handlers walks the lifecycle through the HTTP layer:
// retire (200, then 409), PUT on a retired device (409), POST create with the
// retired name (409 carrying retired_device_id), restore with settings (200,
// settings applied, `enabled` stripped), restore of an active device (409).
func TestRetireRestoreDevice_Handlers(t *testing.T) {
	h, db := setupTestHandler(t)
	// Secrets are only encrypted when a key is configured; give the harness one
	// so the restore path's encrypt-before-write is actually observable.
	db.SetEncryptionKeyForTesting("retire-test-key")
	probe, device := setupProbeAndDevice(t, db)

	// Retire via the handler (also what DELETE /devices/:id now runs).
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = idParam(device.ID)
	h.RetireDevice(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("retire = %d %s, want 200", rec.Code, rec.Body.String())
	}
	c, rec = jsonReq(http.MethodPost, "/x", "")
	c.Params = idParam(device.ID)
	h.RetireDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("second retire = %d, want 409", rec.Code)
	}
	c, rec = jsonReq(http.MethodPost, "/x", "")
	c.Params = idParam(999999)
	h.RetireDevice(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("retire unknown = %d, want 404", rec.Code)
	}

	// PUT on a retired device is refused.
	c, rec = jsonReq(http.MethodPut, "/x", `{"description":"edit"}`)
	c.Params = idParam(device.ID)
	h.UpdateDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("update retired = %d, want 409", rec.Code)
	}
	var upd struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &upd)
	if upd.Error != "device is retired; restore it first" {
		t.Errorf("update retired error = %q", upd.Error)
	}

	// Same-name re-add → 409 naming the retired device.
	body, _ := json.Marshal(map[string]interface{}{"name": device.Name, "ip_address": "192.168.1.9", "probe_id": probe.ID})
	c, rec = jsonReq(http.MethodPost, "/x", string(body))
	h.CreateDevice(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("create with retired name = %d %s, want 409", rec.Code, rec.Body.String())
	}
	var conflict struct {
		Error           string `json:"error"`
		RetiredDeviceID uint   `json:"retired_device_id"`
		RetiredAt       string `json:"retired_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("decode 409: %v", err)
	}
	if conflict.Error != "a retired device with this name exists" || conflict.RetiredDeviceID != device.ID || conflict.RetiredAt == "" {
		t.Errorf("409 body = %+v", conflict)
	}

	// Restore with a rejected body leaves the device retired.
	c, rec = jsonReq(http.MethodPost, "/x", `{"snmp_port": 70000}`)
	c.Params = idParam(device.ID)
	h.RestoreDevice(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("restore with bad settings = %d, want 400", rec.Code)
	}
	if got, _ := db.GetDevice(device.ID); got.RetiredAt == nil {
		t.Error("a rejected restore body must not restore the device")
	}

	// Restore with settings: applied, `enabled:false` stripped, secrets encrypted.
	body, _ = json.Marshal(map[string]interface{}{
		"ip_address": "192.168.1.9", "description": "re-added", "enabled": false,
		"snmp_community": "newsecret", "ssh_password": "",
	})
	c, rec = jsonReq(http.MethodPost, "/x", string(body))
	c.Params = idParam(device.ID)
	h.RestoreDevice(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore with settings = %d %s, want 200", rec.Code, rec.Body.String())
	}
	got, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("get restored: %v", err)
	}
	if got.RetiredAt != nil || !got.Enabled || got.Status != "unknown" {
		t.Errorf("restored: retired_at=%v enabled=%v status=%q", got.RetiredAt, got.Enabled, got.Status)
	}
	if got.IPAddress != "192.168.1.9" || got.Description != "re-added" || got.SNMPCommunity != "newsecret" {
		t.Errorf("settings not applied: ip=%q desc=%q community=%q", got.IPAddress, got.Description, got.SNMPCommunity)
	}
	var raw struct{ SNMPCommunity string }
	db.Gorm().Model(&models.Device{}).Select("snmp_community").Where("id = ?", device.ID).Scan(&raw)
	if raw.SNMPCommunity == "newsecret" {
		t.Error("restore wrote the SNMP community in plaintext (must go through the encrypting update path)")
	}

	// Restore of an active device → 409; empty-body restore after a retire → 200.
	c, rec = jsonReq(http.MethodPost, "/x", "")
	c.Params = idParam(device.ID)
	h.RestoreDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("restore active = %d, want 409", rec.Code)
	}
	if err := db.RetireDevice(device.ID); err != nil {
		t.Fatalf("retire again: %v", err)
	}
	c, rec = jsonReq(http.MethodPost, "/x", "")
	c.Params = idParam(device.ID)
	h.RestoreDevice(c)
	if rec.Code != http.StatusOK {
		t.Errorf("empty-body restore = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if got, _ := db.GetDevice(device.ID); got.RetiredAt != nil || got.IPAddress != "192.168.1.9" {
		t.Errorf("empty-body restore: retired_at=%v ip=%q", got.RetiredAt, got.IPAddress)
	}
}

// TestCreateDevice_ActiveNameCollision409: a duplicate ACTIVE name is a clean
// 409 (was an opaque 500 from the unique index).
func TestCreateDevice_ActiveNameCollision409(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	body, _ := json.Marshal(map[string]interface{}{"name": device.Name, "ip_address": "192.168.1.9", "probe_id": probe.ID})
	c, rec := jsonReq(http.MethodPost, "/x", string(body))
	h.CreateDevice(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("create duplicate active name = %d %s, want 409", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error != "device name already in use" {
		t.Errorf("error = %q", resp.Error)
	}
	var n int64
	db.Gorm().Model(&models.Device{}).Count(&n)
	if n != 1 {
		t.Errorf("device count = %d after refused create, want 1", n)
	}
}

// TestDeleteSite_WithMembers409: the site handler maps ErrSiteHasMembers to
// 409 and the site survives.
func TestDeleteSite_WithMembers409(t *testing.T) {
	h, db := setupTestHandler(t)
	site := &models.Site{Name: "occupied"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	if err := db.Gorm().Create(&models.Device{Name: "fw", IPAddress: "10.0.0.1", SiteID: &site.ID}).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	c, rec := jsonReq(http.MethodDelete, "/x", "")
	c.Params = idParam(site.ID)
	h.DeleteSite(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete occupied site = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if _, err := db.GetSite(site.ID); err != nil {
		t.Errorf("site was deleted despite the guard: %v", err)
	}
}

// TestRestoreDevice_NameCollisionLeavesRetired: a restore whose settings rename
// the device onto an ACTIVE device's name is a 409 and — because restore and
// settings are one transaction — leaves the device retired rather than
// restored-but-unrenamed.
func TestRestoreDevice_NameCollisionLeavesRetired(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	if err := db.Gorm().Create(&models.Device{Name: "taken", IPAddress: "192.168.1.50"}).Error; err != nil {
		t.Fatalf("create second device: %v", err)
	}
	if err := db.RetireDevice(device.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}

	c, rec := jsonReq(http.MethodPost, "/x", `{"name":"taken","description":"renamed"}`)
	c.Params = idParam(device.ID)
	h.RestoreDevice(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("restore onto a taken name = %d %s, want 409", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error != "device name already in use" {
		t.Errorf("error = %q", resp.Error)
	}
	got, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if got.RetiredAt == nil || got.Enabled || got.Name != device.Name || got.Description != "" {
		t.Errorf("after 409 restore: retired_at=%v enabled=%v name=%q description=%q — the restore must have rolled back",
			got.RetiredAt, got.Enabled, got.Name, got.Description)
	}
}
