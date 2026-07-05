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

// TestFlowIngest_AppNamePrecedence pins the LC-05 contract documented on
// FlowSample.AppName: exporter app identification (PAN App-ID / FortiGate app
// options) outranks the port heuristic in app_category when present, and
// unknown or absent app names fall through to the port heuristic.
func TestFlowIngest_AppNamePrecedence(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	const key = "lc05-appname-key"
	probe := &models.Probe{Name: "lc05-probe", RegistrationKey: database.HashProbeKey(key), ApprovalStatus: "approved"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}

	router := gin.New()
	router.POST("/api/probes/:id/flows", h.ReceiveFlowSamples)

	batch := []map[string]interface{}{
		// [0] PAN identified "ssl" on a non-standard port: the port heuristic
		// alone said Unknown; vendor truth must win → Web.
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.1", "dst_addr": "8.8.8.8",
			"src_port": 50000, "dst_port": 9443, "protocol": 6, "bytes": 100, "packets": 1,
			"app_name": "ssl"},
		// [1] Unknown app name: conservative fall-through to the port
		// heuristic (443 → Web), never Unknown-because-unmapped.
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.2", "dst_addr": "8.8.8.8",
			"src_port": 50000, "dst_port": 443, "protocol": 6, "bytes": 100, "packets": 1,
			"app_name": "some-saas-product"},
		// [2] No app name: pure port heuristic (53 → DNS), unchanged behavior.
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.3", "dst_addr": "8.8.4.4",
			"src_port": 50000, "dst_port": 53, "protocol": 17, "bytes": 100, "packets": 1},
		// [3] PAN container-app convention: "dns-base" maps like "dns" even on
		// a non-standard port.
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.4", "dst_addr": "8.8.4.4",
			"src_port": 50000, "dst_port": 5355, "protocol": 17, "bytes": 100, "packets": 1,
			"app_name": "dns-base"},
	}
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
	if err := db.Gorm().Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("saved %d rows, want 4", len(rows))
	}
	want := []classify.Category{classify.Web, classify.Web, classify.DNS, classify.DNS}
	desc := []string{
		"app_name=ssl on port 9443 (vendor truth outranks port heuristic)",
		"unknown app_name on port 443 (fall through to port heuristic)",
		"no app_name on port 53 (port heuristic unchanged)",
		"app_name=dns-base on port 5355 (PAN -base container convention)",
	}
	for i, r := range rows {
		if classify.Category(r.AppCategory) != want[i] {
			t.Errorf("row%d %s: app_category=%d, want %d", i, desc[i], r.AppCategory, uint8(want[i]))
		}
	}
}
