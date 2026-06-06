package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestGetDashboardAll_BatchedEnrichments_AUDIT033 verifies the dashboard
// enrichment is computed correctly after replacing the per-device N+1 loop with
// batched aggregate queries: summaries must reflect the LATEST timestamp per
// device (older rows ignored) and the up/alive counts must be right.
func TestGetDashboardAll_BatchedEnrichments_AUDIT033(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().AutoMigrate(&models.SDWANHealth{}, &models.DeviceConnection{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	dev := &models.Device{Name: "fw1", IPAddress: "10.0.0.1"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}

	T := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	old := T.Add(-time.Hour)
	mk := func(v interface{}) {
		if err := db.Gorm().Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
	}
	// system_status: 2 rows total; latest at T.
	mk(&models.SystemStatus{DeviceID: dev.ID, Timestamp: old, CPUUsage: 10})
	mk(&models.SystemStatus{DeviceID: dev.ID, Timestamp: T, CPUUsage: 55, MemoryUsage: 60, SessionCount: 1234})
	// interface_stats: a noise row at `old`, then 3 at T (2 up, 1 down).
	mk(&models.InterfaceStats{DeviceID: dev.ID, Timestamp: old, Status: "up"})
	mk(&models.InterfaceStats{DeviceID: dev.ID, Timestamp: T, Status: "up"})
	mk(&models.InterfaceStats{DeviceID: dev.ID, Timestamp: T, Status: "up"})
	mk(&models.InterfaceStats{DeviceID: dev.ID, Timestamp: T, Status: "down"})
	// vpn_status: 2 at T (1 up).
	mk(&models.VPNStatus{DeviceID: dev.ID, Timestamp: T, Status: "up"})
	mk(&models.VPNStatus{DeviceID: dev.ID, Timestamp: T, Status: "down"})
	// sdwan_health: 2 at T (1 alive).
	mk(&models.SDWANHealth{DeviceID: dev.ID, Timestamp: T, State: "alive"})
	mk(&models.SDWANHealth{DeviceID: dev.ID, Timestamp: T, State: "down"})
	// ha_status: 2 members at T.
	mk(&models.HAStatus{DeviceID: dev.ID, Timestamp: T, SystemMode: "active-passive"})
	mk(&models.HAStatus{DeviceID: dev.ID, Timestamp: T, SystemMode: "active-passive"})

	router := gin.New()
	router.GET("/dashboard/all", h.GetDashboardAll)
	req := httptest.NewRequest("GET", "/dashboard/all", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Enrichments map[string]struct {
				HasStatus    bool    `json:"has_status"`
				StatusRows   int64   `json:"status_rows"`
				CPUUsage     float64 `json:"cpu_usage"`
				SessionCount int     `json:"session_count"`
				IfaceTotal   int     `json:"iface_total"`
				IfaceUp      int     `json:"iface_up"`
				IfaceDown    int     `json:"iface_down"`
				VPNTotal     int     `json:"vpn_total"`
				VPNUp        int     `json:"vpn_up"`
				HAMode       string  `json:"ha_mode"`
				HAMembers    int     `json:"ha_members"`
				SDWANTotal   int     `json:"sdwan_total"`
				SDWANAlive   int     `json:"sdwan_alive"`
			} `json:"enrichments"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body.String())
	}
	e, ok := resp.Data.Enrichments[fmt.Sprint(dev.ID)]
	if !ok {
		t.Fatalf("no enrichment for device %d; body=%s", dev.ID, w.Body.String())
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"has_status", e.HasStatus, true},
		{"status_rows", e.StatusRows, int64(2)},
		{"cpu_usage (latest)", e.CPUUsage, float64(55)},
		{"session_count (latest)", e.SessionCount, 1234},
		{"iface_total (latest ts only)", e.IfaceTotal, 3},
		{"iface_up", e.IfaceUp, 2},
		{"iface_down", e.IfaceDown, 1},
		{"vpn_total", e.VPNTotal, 2},
		{"vpn_up", e.VPNUp, 1},
		{"ha_mode", e.HAMode, "active-passive"},
		{"ha_members", e.HAMembers, 2},
		{"sdwan_total", e.SDWANTotal, 2},
		{"sdwan_alive", e.SDWANAlive, 1},
	}
	for _, c := range checks {
		if fmt.Sprint(c.got) != fmt.Sprint(c.want) {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
