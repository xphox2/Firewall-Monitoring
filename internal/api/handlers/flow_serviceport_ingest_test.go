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

// TestFlowIngest_StampsServicePort pins that ingest stamps the conversation's
// service side and that a collector cannot supply service_port or class_rev:
// the sample struct is also the wire format, so both are overwritten.
func TestFlowIngest_StampsServicePort(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	const key = "svcport-key"
	probe := &models.Probe{Name: "svcport-probe", RegistrationKey: database.HashProbeKey(key), ApprovalStatus: "approved"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/:id/flows", h.ReceiveFlowSamples)

	batch := []map[string]interface{}{
		// A server's reply: src 443 → client port. Collector-supplied values
		// for the two server-owned fields must be ignored.
		{"sampler_address": "10.9.1.1", "src_addr": "66.179.9.156", "dst_addr": "198.51.100.7",
			"src_port": 443, "dst_port": 51234, "protocol": 6, "bytes": 100, "packets": 1,
			"service_port": 9999, "class_rev": 7},
		// Two ephemeral ports: no service.
		{"sampler_address": "10.9.1.1", "src_addr": "10.0.0.2", "dst_addr": "8.8.8.8",
			"src_port": 40000, "dst_port": 41000, "protocol": 17, "bytes": 100, "packets": 1},
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
	if err := db.Gorm().Order("id").Find(&rows).Error; err != nil || len(rows) != 2 {
		t.Fatalf("query: %v (%d rows)", err, len(rows))
	}
	if want := uint16(1); rows[0].ServicePort != 443 || rows[0].ClassRev != want {
		t.Errorf("server reply stamped service_port=%d class_rev=%d, want 443 and the set's revision %d (collector values ignored)",
			rows[0].ServicePort, rows[0].ClassRev, want)
	}
	if rows[1].ServicePort != 0 {
		t.Errorf("ephemeral-to-ephemeral flow stamped service_port=%d, want 0", rows[1].ServicePort)
	}
}
