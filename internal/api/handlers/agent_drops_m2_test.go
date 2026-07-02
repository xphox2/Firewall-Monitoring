package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/detect"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestFlowIngest_AggregatesAgentDrops_M2 pins the 2026-07-01 audit M2 fix: the
// drops pipeline's missing half. FlowSample.Drops (a CUMULATIVE per-agent
// counter) was persisted per row, but nothing aggregated it into
// flow_agent_drops — so the sampling_backoff detector read a table nothing
// wrote and SFLOW_SAMPLING_BACKOFF could never fire. Ingesting two batches
// with a growing counter must produce the delta in flow_agent_drops, and the
// detector must pick it up.
func TestFlowIngest_AggregatesAgentDrops_M2(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.Probe{}, &models.FlowSample{}, &models.AgentDrops{}, &models.ProcessedBatch{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const key = "m2-drops-key"
	probe := &models.Probe{Name: "drops-probe", RegistrationKey: database.HashProbeKey(key), ApprovalStatus: "approved"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}

	router := gin.New()
	router.POST("/api/probes/:id/flows", h.ReceiveFlowSamples)
	post := func(drops uint64) {
		t.Helper()
		body, _ := json.Marshal([]models.FlowSample{{
			SamplerAddress: "10.9.0.1", SamplingRate: 512, Drops: drops,
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", Bytes: 100, Packets: 1,
		}})
		req := httptest.NewRequest("POST", "/api/probes/"+strconv.FormatUint(uint64(probe.ID), 10)+"/flows", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("flows POST = %d: %s", w.Code, w.Body.String())
		}
	}

	post(100) // first sighting: baseline only, no delta row
	post(150) // cumulative grew by 50 → one delta row

	var rows []models.AgentDrops
	if err := db.Gorm().Find(&rows).Error; err != nil {
		t.Fatalf("query drops: %v", err)
	}
	var total uint64
	for _, r := range rows {
		if r.AgentAddress != "10.9.0.1" || r.SamplingRate != 512 {
			t.Errorf("unexpected drops row: %+v", r)
		}
		total += r.DropsCount
	}
	if total != 50 {
		t.Fatalf("aggregated drops = %d, want 50 (delta of the cumulative counter, not the raw values)", total)
	}

	// The detector must now see the drops (pre-fix: zero rows, never fired).
	dets := detect.RunAll(detect.Window{
		DB:    db.Gorm(),
		Start: time.Now().UTC().Add(-5 * time.Minute),
		End:   time.Now().UTC().Add(time.Minute),
	}, time.Now())
	found := false
	for _, d := range dets {
		if d.Detector == "sampling_backoff" && d.SrcAddr == "10.9.0.1" {
			found = true
		}
	}
	if !found {
		t.Error("sampling_backoff detection did not fire for the dropping agent — the pipeline is still dead")
	}
}
