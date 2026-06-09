package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func TestGetAuditLogs(t *testing.T) {
	h, db := setupTestHandler(t)

	// Seed some audit logs
	log1 := &models.AuditLog{
		CreatedAt: time.Now().Add(-1 * time.Hour),
		Actor:     "admin1",
		ActorID:   1,
		Method:    "POST",
		Action:    "/admin/api/devices",
		Target:    "name=test-fw",
		Status:    201,
		IPAddress: "192.168.1.50",
		UserAgent: "Mozilla/5.0",
	}
	log2 := &models.AuditLog{
		CreatedAt: time.Now().Add(-2 * time.Hour),
		Actor:     "admin2",
		ActorID:   2,
		Method:    "DELETE",
		Action:    "/admin/api/devices/:id",
		Target:    "id=5",
		Status:    200,
		IPAddress: "192.168.1.51",
		UserAgent: "Mozilla/5.0",
	}

	if err := db.SaveAuditLog(log1); err != nil {
		t.Fatalf("save audit log 1: %v", err)
	}
	if err := db.SaveAuditLog(log2); err != nil {
		t.Fatalf("save audit log 2: %v", err)
	}

	// Make request
	router := gin.New()
	router.GET("/admin/api/audit", h.GetAuditLogs)

	// Case 1: no filters
	req := httptest.NewRequest("GET", "/admin/api/audit", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got code %d, want 200", w.Code)
	}

	var resp struct {
		Data struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
			Total     int64             `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Data.Total != 2 {
		t.Errorf("got total %d, want 2", resp.Data.Total)
	}
	if len(resp.Data.AuditLogs) != 2 {
		t.Errorf("got %d logs, want 2", len(resp.Data.AuditLogs))
	}

	// Case 2: filter by actor
	req = httptest.NewRequest("GET", "/admin/api/audit?actor=admin1", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp2 struct {
		Data struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
			Total     int64             `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp2.Data.Total != 1 || resp2.Data.AuditLogs[0].Actor != "admin1" {
		t.Errorf("filter by actor failed: got total %d", resp2.Data.Total)
	}
}
