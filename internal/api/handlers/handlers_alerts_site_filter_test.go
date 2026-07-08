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

// TestGetAlerts_SiteFilter verifies the site_id filter (v0.11.58) added for the
// NOC dashboard's site-click → Alert History flow: it scopes to a site via
// device→site AND folds in site-scoped alerts (SFLOW_SECURITY_DIGEST, DeviceID 0)
// through the alerts.site_id column, and understands the "unassigned" bucket. It
// also guards that the device_id filter still works (the state-sourced deep-link).
func TestGetAlerts_SiteFilter(t *testing.T) {
	h, db := setupTestHandler(t)

	siteA := &models.Site{Name: "site-a"}
	siteB := &models.Site{Name: "site-b"}
	if err := db.Gorm().Create(siteA).Error; err != nil {
		t.Fatalf("site A: %v", err)
	}
	if err := db.Gorm().Create(siteB).Error; err != nil {
		t.Fatalf("site B: %v", err)
	}

	devA := &models.Device{Name: "dev-a", IPAddress: "10.0.0.1", SiteID: &siteA.ID}
	devB := &models.Device{Name: "dev-b", IPAddress: "10.0.0.2", SiteID: &siteB.ID}
	devU := &models.Device{Name: "dev-unassigned", IPAddress: "10.0.0.3"} // no site
	for _, d := range []*models.Device{devA, devB, devU} {
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("device %s: %v", d.Name, err)
		}
	}

	mkAlert := func(deviceID uint, siteID *uint, atype models.AlertType) {
		a := &models.Alert{
			DeviceID:  deviceID,
			SiteID:    siteID,
			AlertType: atype,
			Severity:  "warning",
			Message:   "seeded",
			Timestamp: time.Now(),
		}
		if err := db.Gorm().Create(a).Error; err != nil {
			t.Fatalf("create alert: %v", err)
		}
	}
	// 2 device-scoped alerts on site A, 1 on site B, 1 on the unassigned device,
	// and 1 site-scoped digest (DeviceID 0, SiteID = site A).
	mkAlert(devA.ID, nil, "TEST_ALERT")
	mkAlert(devA.ID, nil, "CPU_HIGH")
	mkAlert(devB.ID, nil, "TEST_ALERT")
	mkAlert(devU.ID, nil, "TEST_ALERT")
	mkAlert(0, &siteA.ID, models.AlertTypeSFlowSecurityDigest)

	router := gin.New()
	router.GET("/api/alerts", h.GetAlerts)
	total := func(query string) int {
		req := httptest.NewRequest("GET", "/api/alerts"+query, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", query, w.Code, w.Body.String())
		}
		var resp struct {
			Data struct {
				Total int `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s: %v", query, err)
		}
		return resp.Data.Total
	}

	if got := total("?site_id=" + itoa(siteA.ID)); got != 3 {
		t.Errorf("site_id=A → %d alerts, want 3 (2 device-scoped + 1 site digest)", got)
	}
	if got := total("?site_id=" + itoa(siteB.ID)); got != 1 {
		t.Errorf("site_id=B → %d alerts, want 1", got)
	}
	if got := total("?site_id=unassigned"); got != 1 {
		t.Errorf("site_id=unassigned → %d alerts, want 1 (the site-less device)", got)
	}
	if got := total("?device_id=" + itoa(devA.ID)); got != 2 {
		t.Errorf("device_id=A → %d alerts, want 2 (device filter regression)", got)
	}
	if got := total(""); got != 5 {
		t.Errorf("no filter → %d alerts, want 5", got)
	}
}
