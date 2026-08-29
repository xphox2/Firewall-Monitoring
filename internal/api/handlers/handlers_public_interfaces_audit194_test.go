package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// AUDIT-194/195: the public_interfaces allowlist was enforced only in
// public-dashboard.js — an anonymous caller hitting /api/public/interfaces or
// /chart directly received every interface (names, MACs, VLANs, counters) of a
// public device. These tests pin the SERVER-side enforcement, including the
// critical empty-list semantic (empty/absent list = "no narrowing configured"
// = all interfaces; deny-all-on-empty would blank every unconfigured public
// dashboard). AUDIT-252: the global `else if db != nil` fallbacks served a
// NON-public device's telemetry when no device passed the public gate — pinned
// to the 503 terminals instead.

// doPublicGet routes an anonymous GET (with query string) through a real gin
// engine, since the public handlers read c.Query and c.Request.Context().
func doPublicGet(t *testing.T, handlerFn gin.HandlerFunc, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET("/endpoint", handlerFn)
	req := httptest.NewRequest("GET", rawURL, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// seedPublicDeviceWithInterfaces creates an enabled public device carrying one
// latest-timestamp stats row each for wan1/lan1/dmz (ifIndex 1/2/3).
func seedPublicDeviceWithInterfaces(t *testing.T, db *database.Database) *models.Device {
	t.Helper()
	dev := &models.Device{Name: "edge-fw", IPAddress: "192.0.2.1", Enabled: true, PublicVisible: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	ts := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	for i, name := range []string{"wan1", "lan1", "dmz"} {
		row := &models.InterfaceStats{DeviceID: dev.ID, Timestamp: ts, Name: name, Index: i + 1, Status: "up"}
		if err := db.Gorm().Create(row).Error; err != nil {
			t.Fatalf("seed iface %s: %v", name, err)
		}
	}
	return dev
}

func setAllowlistSetting(t *testing.T, db *database.Database, value string) {
	t.Helper()
	if err := db.Gorm().Create(&models.SystemSetting{Key: "public_interfaces", Value: value}).Error; err != nil {
		t.Fatalf("seed public_interfaces setting: %v", err)
	}
}

func decodeIfaceNames(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var resp struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v; body = %s", err, w.Body.String())
	}
	names := make([]string, 0, len(resp.Data))
	for _, d := range resp.Data {
		names = append(names, d.Name)
	}
	return names
}

func TestGetPublicInterfaces_AllowlistFiltersServerSide_AUDIT194(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	setAllowlistSetting(t, db, fmt.Sprintf(`{"%d":["wan1"]}`, dev.ID))

	w := doPublicGet(t, h.GetPublicInterfaces, fmt.Sprintf("/endpoint?device_id=%d", dev.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	names := decodeIfaceNames(t, w)
	if len(names) != 1 || names[0] != "wan1" {
		t.Errorf("allowlisted response = %v, want exactly [wan1] — the curation must be enforced server-side", names)
	}
	for _, leaked := range []string{"lan1", "dmz"} {
		if strings.Contains(w.Body.String(), leaked) {
			t.Errorf("non-allowlisted interface %q leaked to the anonymous response", leaked)
		}
	}
}

// TestGetPublicInterfaces_EmptyAllowlistShowsAll_AUDIT194 pins the CRITICAL
// semantic: an absent setting, an absent device key, and an explicit empty
// list all mean "no narrowing configured" — every interface is served, exactly
// as public-dashboard.js behaves (it only filters when allowed.length > 0).
func TestGetPublicInterfaces_EmptyAllowlistShowsAll_AUDIT194(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)

	// No setting row at all.
	w := doPublicGet(t, h.GetPublicInterfaces, fmt.Sprintf("/endpoint?device_id=%d", dev.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("no setting: status = %d; body = %s", w.Code, w.Body.String())
	}
	if names := decodeIfaceNames(t, w); len(names) != 3 {
		t.Errorf("no setting: got %v, want all 3 interfaces (absent list must not deny-all)", names)
	}

	// Explicit empty list for this device.
	setAllowlistSetting(t, db, fmt.Sprintf(`{"%d":[]}`, dev.ID))
	w = doPublicGet(t, h.GetPublicInterfaces, fmt.Sprintf("/endpoint?device_id=%d", dev.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("empty list: status = %d; body = %s", w.Code, w.Body.String())
	}
	if names := decodeIfaceNames(t, w); len(names) != 3 {
		t.Errorf("empty list: got %v, want all 3 interfaces (empty list means no narrowing, NOT deny-all)", names)
	}
}

// TestGetPublicInterfaceChart_NonAllowlistedIndexEmptySeries_AUDIT194: chart
// history for an index outside the allowlist must come back as the SAME
// empty-series payload the no-data case emits (200, empty arrays) — not a 403
// — while an allowlisted index still charts.
func TestGetPublicInterfaceChart_NonAllowlistedIndexEmptySeries_AUDIT194(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	setAllowlistSetting(t, db, fmt.Sprintf(`{"%d":["wan1"]}`, dev.ID))

	// Second in-range point for both wan1 (index 1) and lan1 (index 2), so each
	// has >= 2 points and would chart a real series absent the gate.
	later := time.Now().Add(-1 * time.Minute).Truncate(time.Second)
	for _, row := range []*models.InterfaceStats{
		{DeviceID: dev.ID, Timestamp: later, Name: "wan1", Index: 1, InBytes: 1000, OutBytes: 2000},
		{DeviceID: dev.ID, Timestamp: later, Name: "lan1", Index: 2, InBytes: 3000, OutBytes: 4000},
	} {
		if err := db.Gorm().Create(row).Error; err != nil {
			t.Fatalf("seed chart point: %v", err)
		}
	}

	decodeChart := func(w *httptest.ResponseRecorder) (labels []string, view, rng string) {
		t.Helper()
		var resp struct {
			Data struct {
				Labels []string `json:"labels"`
				View   string   `json:"view"`
				Range  string   `json:"range"`
			} `json:"data"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode chart body: %v; body = %s", err, w.Body.String())
		}
		return resp.Data.Labels, resp.Data.View, resp.Data.Range
	}

	// Non-allowlisted index -> the empty-series shape, indistinguishable from
	// no-data, so the SPA renders an empty chart.
	w := doPublicGet(t, h.GetPublicInterfaceChart, fmt.Sprintf("/endpoint?device_id=%d&index=2", dev.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("non-allowed index: status = %d, want 200 (empty series, not an error); body = %s", w.Code, w.Body.String())
	}
	labels, view, rng := decodeChart(w)
	if len(labels) != 0 {
		t.Errorf("non-allowlisted index charted %d points — history leaked past the allowlist", len(labels))
	}
	if view != "rate" || rng != "1h" {
		t.Errorf("empty-series payload shape drifted: view=%q range=%q, want rate/1h", view, rng)
	}

	// Allowlisted index still charts.
	w = doPublicGet(t, h.GetPublicInterfaceChart, fmt.Sprintf("/endpoint?device_id=%d&index=1", dev.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("allowed index: status = %d; body = %s", w.Code, w.Body.String())
	}
	if labels, _, _ := decodeChart(w); len(labels) == 0 {
		t.Error("allowlisted index returned an empty series — the gate must not blank curated interfaces")
	}
}

// TestGetPublicDashboard_NoPublicDevice_503_AUDIT252: with zero public-visible
// devices, the anonymous dashboard must 503 — never fall back to the
// newest-reporting NON-public device's telemetry.
func TestGetPublicDashboard_NoPublicDevice_503_AUDIT252(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "internal-fw", IPAddress: "192.0.2.9", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// PublicVisible has a DB-level default:true, so a zero-value false is
	// dropped from the INSERT — flip it explicitly.
	if err := db.Gorm().Model(dev).Update("public_visible", false).Error; err != nil {
		t.Fatalf("mark non-public: %v", err)
	}
	status := &models.SystemStatus{DeviceID: dev.ID, Timestamp: time.Now(), Hostname: "secret-hostname", Version: "v7.4.1", CPUUsage: 12}
	if err := db.Gorm().Create(status).Error; err != nil {
		t.Fatalf("seed status: %v", err)
	}

	w := doPublicGet(t, h.GetPublicDashboard, "/endpoint")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no device is public (body = %s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secret-hostname") {
		t.Error("a non-public device's hostname leaked through the deleted global fallback (AUDIT-252)")
	}
}

// TestGetPublicInterfaces_NoPublicDevice_503_AUDIT252 pins the same terminal
// for the interfaces endpoint (its deleted fallback served
// GetLatestInterfaceStats unfiltered).
func TestGetPublicInterfaces_NoPublicDevice_503_AUDIT252(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "internal-fw", IPAddress: "192.0.2.10", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := db.Gorm().Model(dev).Update("public_visible", false).Error; err != nil {
		t.Fatalf("mark non-public: %v", err)
	}
	row := &models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Now(), Name: "mgmt-secret", Index: 1}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed iface: %v", err)
	}

	w := doPublicGet(t, h.GetPublicInterfaces, "/endpoint")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no device is public (body = %s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "mgmt-secret") {
		t.Error("a non-public device's interface leaked through the deleted global fallback (AUDIT-252)")
	}
}
