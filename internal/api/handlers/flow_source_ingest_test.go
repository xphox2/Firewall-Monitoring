package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestFlowIngest_FlowSource pins the Tranche 3 multi-protocol ingest contract:
// flow_source is stored as sent for known values, clamped to sFlow for junk,
// zero when absent; zero-byte rows (NSEL denied/create, NAT events) are LEGAL;
// and NetFlow-sourced rows never feed the sFlow-cumulative agent-drops table.
func TestFlowIngest_FlowSource(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.Probe{}, &models.FlowSample{}, &models.AgentDrops{}, &models.ProcessedBatch{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const key = "t3-source-key"
	probe := &models.Probe{Name: "t3-probe", RegistrationKey: database.HashProbeKey(key), ApprovalStatus: "approved"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}

	router := gin.New()
	router.POST("/api/probes/:id/flows", h.ReceiveFlowSamples)

	// One batch, four shapes:
	//  [0] NetFlow v9 row with drops set (must NOT reach flow_agent_drops)
	//  [1] junk flow_source 200 (clamped to 0)
	//  [2] absent flow_source (zero value)
	//  [3] zero-byte ASA-style denied record (must be saved)
	batch := []map[string]interface{}{
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.1", "dst_addr": "8.8.8.8",
			"bytes": 4000, "packets": 4, "flow_source": models.FlowSourceNetFlowV9, "drops": 500, "sampling_rate": 1},
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.2", "dst_addr": "8.8.4.4",
			"bytes": 100, "packets": 1, "flow_source": 200},
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.3", "dst_addr": "1.1.1.1",
			"bytes": 100, "packets": 1},
		{"sampler_address": "10.9.1.1", "src_addr": "192.0.2.66", "dst_addr": "10.0.0.4",
			"bytes": 0, "packets": 0, "flow_source": models.FlowSourceNetFlowV9,
			"firewall_event": models.FirewallEventDenied},
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
		t.Fatalf("saved %d rows, want 4 (zero-byte denied record must be legal)", len(rows))
	}
	if rows[0].FlowSource != models.FlowSourceNetFlowV9 {
		t.Errorf("row0 flow_source = %d, want %d", rows[0].FlowSource, models.FlowSourceNetFlowV9)
	}
	if rows[1].FlowSource != models.FlowSourceSFlow {
		t.Errorf("row1 flow_source = %d, want clamp to %d", rows[1].FlowSource, models.FlowSourceSFlow)
	}
	if rows[2].FlowSource != models.FlowSourceSFlow {
		t.Errorf("row2 flow_source = %d, want zero-value %d", rows[2].FlowSource, models.FlowSourceSFlow)
	}
	if rows[3].FirewallEvent != models.FirewallEventDenied || rows[3].Bytes != 0 {
		t.Errorf("row3 denied record mangled: event=%d bytes=%d", rows[3].FirewallEvent, rows[3].Bytes)
	}

	// The NetFlow row's drops value must not have created an agent-drops
	// baseline/delta — that table's math assumes sFlow's cumulative counter.
	var dropRows int64
	db.Gorm().Model(&models.AgentDrops{}).Count(&dropRows)
	if dropRows != 0 {
		t.Errorf("flow_agent_drops has %d rows, want 0 — NetFlow rows must not feed the sFlow drops pipeline", dropRows)
	}
}
