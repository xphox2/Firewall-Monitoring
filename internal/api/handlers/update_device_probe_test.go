package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestUpdateDevice_ReassignProbeAndSite is the regression for the operator
// report: editing a device to change its probe says "saved" but reverts on
// refresh. Root cause was that UpdateDevice loaded the device via GetDevice
// (which Preload("Probe")/Preload("Site")) and then wrote with
// Model(device).Updates(map). gorm re-derived probe_id/site_id from the loaded
// belongs-to associations (the OLD probe/site) and clobbered the new values in
// the update map. The fix writes via Model(&Device{}).Where("id = ?", id) so
// gorm honors the map values. Both foreign keys are exercised here.
func TestUpdateDevice_ReassignProbeAndSite(t *testing.T) {
	h, db := setupTestHandler(t)
	// :memory: SQLite gives each pooled connection its own private DB; pin to a
	// single connection so the write and the re-fetch see the same data.
	if sqlDB, err := db.Gorm().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	probe1, device := setupProbeAndDevice(t, db)

	probe2 := &models.Probe{Name: "new-probe", RegistrationKey: "newkey", ApprovalStatus: "approved", Status: "online"}
	if err := db.Gorm().Create(probe2).Error; err != nil {
		t.Fatalf("create probe2: %v", err)
	}
	site := &models.Site{Name: "site-A"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	if probe2.ID == probe1.ID {
		t.Fatal("probe ids collided")
	}

	router := gin.New()
	router.PUT("/devices/:id", h.UpdateDevice)

	body, _ := json.Marshal(map[string]interface{}{
		"probe_id": probe2.ID,
		"site_id":  site.ID,
	})
	req := httptest.NewRequest("PUT", "/devices/"+strconv.FormatUint(uint64(device.ID), 10), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var got models.Device
	if err := db.Gorm().First(&got, device.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if got.ProbeID == nil || *got.ProbeID != probe2.ID {
		t.Fatalf("probe_id did not persist: want %d, got %v", probe2.ID, got.ProbeID)
	}
	if got.SiteID == nil || *got.SiteID != site.ID {
		t.Fatalf("site_id did not persist: want %d, got %v", site.ID, got.SiteID)
	}

	// Unassigning (probe_id: null) must also work.
	body, _ = json.Marshal(map[string]interface{}{"probe_id": nil})
	req = httptest.NewRequest("PUT", "/devices/"+strconv.FormatUint(uint64(device.ID), 10), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("unassign: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	got = models.Device{}
	db.Gorm().First(&got, device.ID)
	if got.ProbeID != nil {
		t.Fatalf("probe_id should be NULL after unassign, got %v", *got.ProbeID)
	}
}
