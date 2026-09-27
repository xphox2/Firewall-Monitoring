package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func postFlows(t *testing.T, h *Handler, db *database.Database, key string, batch []map[string]interface{}) []models.FlowSample {
	t.Helper()
	gin.SetMode(gin.TestMode)
	probe := &models.Probe{Name: key + "-probe", RegistrationKey: database.HashProbeKey(key), ApprovalStatus: "approved"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/:id/flows", h.ReceiveFlowSamples)
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/probes/"+strconv.FormatUint(uint64(probe.ID), 10)+"/flows", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("flows POST = %d: %s", w.Code, w.Body.String())
	}
	var rows []models.FlowSample
	if err := db.Gorm().Where("probe_id = ?", probe.ID).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	return rows
}

// TestFlowIngest_ClassifiesAgainstOwnNetworks: once the operator's networks
// are loaded, a flow from their own public range is Outbound, not External, and
// carries the set's revision. Before any set has loaded, ingest falls back to
// the private defaults with class_rev 0 — never the current revision.
func TestFlowIngest_ClassifiesAgainstOwnNetworks(t *testing.T) {
	h, db := setupTestHandler(t)
	flow := []map[string]interface{}{{"sampler_address": "10.9.1.1", "src_addr": "66.179.9.156", "dst_addr": "203.0.113.9",
		"src_port": 443, "dst_port": 51234, "protocol": 6, "bytes": 100, "packets": 1, "direction": 3, "class_rev": 9}}

	h.internalNets.Store(nil)
	rows := postFlows(t, h, db, "noset", flow)
	if rows[0].Direction != classify.DirExternal || rows[0].ClassRev != 0 {
		t.Errorf("no set loaded: direction %s class_rev %d, want External and 0",
			classify.DirectionName(rows[0].Direction), rows[0].ClassRev)
	}

	if err := db.Gorm().Create(&models.SystemSetting{Key: database.FlowInternalNetworksKey, Value: "66.179.9.144/28"}).Error; err != nil {
		t.Fatalf("seed networks: %v", err)
	}
	h.RefreshInternalNetworks()
	rows = postFlows(t, h, db, "withset", flow)
	if rows[0].Direction != classify.DirOutbound || rows[0].ClassRev != 1 {
		t.Errorf("own network loaded: direction %s class_rev %d, want Outbound and 1",
			classify.DirectionName(rows[0].Direction), rows[0].ClassRev)
	}
}

// TestRefreshInternalNetworks_KeepsPreviousSetOnError: a failed rebuild must
// not swap in a defaults-only set stamped with the current revision.
func TestRefreshInternalNetworks_KeepsPreviousSetOnError(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.FlowInternalNetworksKey, Value: "66.179.9.144/28"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	h.RefreshInternalNetworks()
	before := h.internalNets.Load()
	if before == nil {
		t.Fatal("no set after a successful refresh")
	}
	if err := db.Gorm().Migrator().DropTable(&models.InterfaceAddress{}); err != nil {
		t.Fatalf("drop: %v", err)
	}
	h.RefreshInternalNetworks()
	if h.internalNets.Load() != before {
		t.Error("a failed refresh replaced the previous set")
	}
}

// TestUpdateSettings_InternalNetworks: the list is validated, stored canonical,
// refuses a catch-all, and applies to ingest immediately on save.
func TestUpdateSettings_InternalNetworks(t *testing.T) {
	h, db := setupTestHandler(t)
	post := func(key, val string) int {
		t.Helper()
		body := []map[string]string{{"key": key, "value": val, "category": "flows", "type": "string"}}
		return doSettingsRequest(t, h.UpdateSettings, "POST", body).Code
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "not-a-network", "10.0.0.0/33"} {
		if code := post(database.FlowInternalNetworksKey, bad); code != http.StatusBadRequest {
			t.Errorf("%q: code %d, want 400", bad, code)
		}
	}
	if code := post(database.FlowInternalAutoKey, "maybe"); code != http.StatusBadRequest {
		t.Errorf("auto=maybe: code %d, want 400", code)
	}
	if code := post(database.FlowInternalNetworksKey, "66.179.9.150/28, 66.9.166.120"); code != http.StatusOK {
		t.Fatalf("valid list: code %d", code)
	}
	if v, _ := db.GetSettingValue(database.FlowInternalNetworksKey); v != "66.179.9.144/28\n66.9.166.120/32" {
		t.Errorf("stored %q, want the canonical form", v)
	}
	if got := h.internalNets.Load().Direction("66.9.166.120", "8.8.8.8"); got != classify.DirOutbound {
		t.Errorf("the saved list did not apply on save: %s", classify.DirectionName(got))
	}
}

// TestGetFlowInternalNetworks lists each entry with its source.
func TestGetFlowInternalNetworks(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.FlowInternalNetworksKey, Value: "66.9.166.120/32"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/admin/api/flows/internal-networks", nil)
	h.GetFlowInternalNetworks(c)
	var resp struct {
		Data struct {
			Networks []database.InternalNetwork `json:"networks"`
			Auto     bool                       `json:"auto"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("code %d body %s err %v", w.Code, w.Body.String(), err)
	}
	if len(resp.Data.Networks) != 1 || resp.Data.Networks[0].CIDR != "66.9.166.120/32" || resp.Data.Networks[0].Source != "manual" || !resp.Data.Auto {
		t.Errorf("got %+v", resp.Data)
	}
}
