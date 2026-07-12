package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestGetAlertConfigOverview_5b pins the Alerting-hub overview aggregation: one
// row per customized threshold across all four scopes (site/device/policy/rule),
// plus an alerts-disabled row, with names resolved.
func TestGetAlertConfigOverview_5b(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	g := db.Gorm()

	site := &models.Site{Name: "HQ"}
	if err := g.Create(site).Error; err != nil {
		t.Fatalf("site: %v", err)
	}
	dev := &models.Device{Name: "fw-01"}
	devOff := &models.Device{Name: "fw-off"}
	if err := g.Create(dev).Error; err != nil {
		t.Fatalf("dev: %v", err)
	}
	if err := g.Create(devOff).Error; err != nil {
		t.Fatalf("devOff: %v", err)
	}

	if err := g.Create(&models.SiteAlertConfig{SiteID: site.ID, CPUThreshold: 70}).Error; err != nil {
		t.Fatalf("site cfg: %v", err)
	}
	if err := g.Create(&models.DeviceAlertConfig{DeviceID: dev.ID, AlertsEnabled: true, DiskThreshold: 95}).Error; err != nil {
		t.Fatalf("dev cfg: %v", err)
	}
	// AlertsEnabled has default:true so GORM omits the false zero on Create —
	// force it with an explicit column write (known gotcha).
	if err := g.Create(&models.DeviceAlertConfig{DeviceID: devOff.ID, AlertsEnabled: true}).Error; err != nil {
		t.Fatalf("devOff cfg: %v", err)
	}
	if err := g.Model(&models.DeviceAlertConfig{}).Where("device_id = ?", devOff.ID).Update("alerts_enabled", false).Error; err != nil {
		t.Fatalf("disable: %v", err)
	}

	policy := &models.AlertPolicy{Name: "Strict", IsDefault: true,
		Rules: []models.AlertRule{{AlertType: models.AlertTypeCPUHigh, Enabled: true, Threshold: 88}}}
	if err := g.Create(policy).Error; err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := g.Create(&models.EventRule{Name: "burst", Enabled: true, Source: "metric",
		AlertType: models.AlertTypeCPUHigh, MatchJSON: `{"op":"eq","field":"event_type","value":"cpu_high"}`,
		DampenJSON: `{"threshold":50}`}).Error; err != nil {
		t.Fatalf("event rule: %v", err)
	}

	router := gin.New()
	router.GET("/api/alert-config/overview", h.GetAlertConfigOverview)
	req := httptest.NewRequest("GET", "/api/alert-config/overview", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("overview = %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Global    map[string]any `json:"global"`
			Overrides []struct {
				Scope     string  `json:"scope"`
				ScopeName string  `json:"scope_name"`
				AlertType string  `json:"alert_type"`
				Value     float64 `json:"value"`
				Kind      string  `json:"kind"`
			} `json:"overrides"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	if resp.Data.Global == nil {
		t.Fatal("global block missing")
	}

	has := func(scope, name, at string, val float64, kind string) bool {
		for _, r := range resp.Data.Overrides {
			if r.Scope == scope && r.ScopeName == name && r.AlertType == at && r.Value == val && r.Kind == kind {
				return true
			}
		}
		return false
	}
	if !has("site", "HQ", "CPU_HIGH", 70, "threshold") {
		t.Errorf("missing site CPU override; got %+v", resp.Data.Overrides)
	}
	if !has("device", "fw-01", "DISK_HIGH", 95, "threshold") {
		t.Errorf("missing device DISK override; got %+v", resp.Data.Overrides)
	}
	if !has("policy", "Strict", "CPU_HIGH", 88, "threshold") {
		t.Errorf("missing policy CPU override; got %+v", resp.Data.Overrides)
	}
	if !has("rule", "burst", "CPU_HIGH", 50, "threshold") {
		t.Errorf("missing metric-rule override; got %+v", resp.Data.Overrides)
	}
	// alerts-disabled device row (no alert_type/value).
	disabled := false
	for _, r := range resp.Data.Overrides {
		if r.Scope == "device" && r.ScopeName == "fw-off" && r.Kind == "disabled" {
			disabled = true
		}
	}
	if !disabled {
		t.Errorf("missing alerts-disabled row for fw-off; got %+v", resp.Data.Overrides)
	}
}
