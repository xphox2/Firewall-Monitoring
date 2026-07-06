package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// postSuppress issues a suppress-source request and returns the recorder.
func postSuppress(t *testing.T, router *gin.Engine, id uint, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/admin/api/alerts/"+strconv.FormatUint(uint64(id), 10)+"/suppress-source", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestSuppressSource_Validation covers the suppress-source guardrails (v0.11.46,
// plan test f): wrong alert type rejected, a src not among the alert's sources
// rejected, and no-source-at-all → 422.
func TestSuppressSource_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, db := setupTestHandler(t)
	if err := db.Gorm().AutoMigrate(&models.Alert{}, &models.FlowDetection{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/admin/api/alerts/:id/suppress-source", h.SuppressAlertSource)

	// A non-security alert can't silence a source.
	cpu := &models.Alert{AlertType: "CPU_HIGH", Severity: "warning", MetricName: "cpu_usage"}
	db.Gorm().Create(cpu)
	if w := postSuppress(t, router, cpu.ID, map[string]any{"hours": 24}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("wrong-type suppress = %d, want 422: %s", w.Code, w.Body.String())
	}

	// A security alert with a source + a linked detection.
	sec := &models.Alert{AlertType: models.AlertTypeSFlowSecurity, Severity: "warning", MetricName: "sflow_port_scan", SourceAddr: "203.0.113.5"}
	db.Gorm().Create(sec)
	det := &models.FlowDetection{Detector: "port_scan", Category: "security", SrcAddr: "203.0.113.5", AlertID: &sec.ID}
	db.Gorm().Create(det)

	// A src not among the alert's sources is rejected.
	if w := postSuppress(t, router, sec.ID, map[string]any{"hours": 24, "src": "8.8.8.8"}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("foreign-src suppress = %d, want 422: %s", w.Code, w.Body.String())
	}

	// The valid path: no src supplied → uses the alert's SourceAddr, silences it,
	// and (per-source alert) acks the alert.
	if w := postSuppress(t, router, sec.ID, map[string]any{"hours": 24}); w.Code != http.StatusOK {
		t.Fatalf("valid suppress = %d, want 200: %s", w.Code, w.Body.String())
	}
	on, _ := db.IsFlowSourceSuppressed("203.0.113.5", time.Now())
	if !on {
		t.Error("source should be suppressed after a valid request")
	}
	var got models.Alert
	db.Gorm().First(&got, sec.ID)
	if !got.Acknowledged {
		t.Error("per-source security alert should be acked after silencing its source")
	}

	// No-source alert → 422.
	orphan := &models.Alert{AlertType: models.AlertTypeSFlowSecurity, Severity: "warning", MetricName: "sflow_port_scan"}
	db.Gorm().Create(orphan)
	if w := postSuppress(t, router, orphan.ID, map[string]any{"hours": 24}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("no-source suppress = %d, want 422: %s", w.Code, w.Body.String())
	}
}
