package handlers

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// A connection to a retired device is hidden from every list and map, so the
// API must not create one, and must answer for an existing one as if it were
// gone. GetDevice returns retired devices, which is why this needs its own
// check.

func seedRetiredDevice(t *testing.T, h *Handler) *models.Device {
	t.Helper()
	at := time.Now().UTC().Add(-time.Hour)
	d := &models.Device{Name: "gone-fw", IPAddress: "192.168.7.9", RetiredAt: &at}
	if err := h.db.Gorm().Create(d).Error; err != nil {
		t.Fatalf("seed retired device: %v", err)
	}
	return d
}

func TestCreateDeviceConnection_RejectsRetiredEndpoint(t *testing.T) {
	h, _ := setupTestHandler(t)
	src, _ := seedConnectionEndpoints(t, h)
	gone := seedRetiredDevice(t, h)

	for _, body := range []map[string]interface{}{
		{"name": "to gone", "source_device_id": src.ID, "dest_device_id": gone.ID},
		{"name": "from gone", "source_device_id": gone.ID, "dest_device_id": src.ID},
	} {
		w := doCreateConnectionRequest(t, h, body)
		if w.Code != 400 {
			t.Errorf("%s: status = %d, want 400; body: %s", body["name"], w.Code, w.Body.String())
		}
	}
	var n int64
	h.db.Gorm().Model(&models.DeviceConnection{}).Count(&n)
	if n != 0 {
		t.Errorf("%d connection(s) created to a retired device", n)
	}
}

func TestUpdateDeviceConnection_RejectsRetiredEndpoint(t *testing.T) {
	h, _ := setupTestHandler(t)
	src, dst := seedConnectionEndpoints(t, h)
	gone := seedRetiredDevice(t, h)
	conn := &models.DeviceConnection{Name: "link", SourceDeviceID: src.ID, DestDeviceID: dst.ID, ConnectionType: "ipsec"}
	if err := h.db.Gorm().Create(conn).Error; err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	for _, field := range []string{"source_device_id", "dest_device_id"} {
		w := doPartialUpdateRequest(t, h.UpdateDeviceConnection, "/api/connections/:id", conn.ID,
			map[string]interface{}{field: gone.ID})
		if w.Code != 400 {
			t.Errorf("%s -> retired: status = %d, want 400; body: %s", field, w.Code, w.Body.String())
		}
	}
	var stored models.DeviceConnection
	h.db.Gorm().First(&stored, conn.ID)
	if stored.SourceDeviceID != src.ID || stored.DestDeviceID != dst.ID {
		t.Errorf("endpoints changed to %d/%d", stored.SourceDeviceID, stored.DestDeviceID)
	}
}

func TestConnectionDetailEndpoints_404ForRetiredEndpoint(t *testing.T) {
	h, _ := setupTestHandler(t)
	_, dst := seedConnectionEndpoints(t, h)
	gone := seedRetiredDevice(t, h)
	ghost := &models.DeviceConnection{Name: "? ↔ fw-dst", SourceDeviceID: gone.ID, DestDeviceID: dst.ID, ConnectionType: "ipsec", AutoDetected: true}
	if err := h.db.Gorm().Create(ghost).Error; err != nil {
		t.Fatalf("seed ghost: %v", err)
	}

	router := gin.New()
	router.GET("/c/:id", h.GetConnectionDetail)
	router.GET("/c/:id/traffic", h.GetConnectionTraffic)
	router.GET("/c/:id/events", h.GetConnectionEvents)
	router.GET("/c/:id/flows", h.GetConnectionFlows)
	for _, suffix := range []string{"", "/traffic", "/events", "/flows"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/c/%d%s", ghost.ID, suffix), nil))
		if w.Code != 404 {
			t.Errorf("GET connection%s: status = %d, want 404; body: %s", suffix, w.Code, w.Body.String())
		}
	}

	w := doPartialUpdateRequest(t, h.UpdateDeviceConnection, "/api/connections/:id", ghost.ID,
		map[string]interface{}{"name": "renamed"})
	if w.Code != 404 {
		t.Errorf("PUT connection: status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestGetDashboardAll_HidesConnectionsToRetiredDevices(t *testing.T) {
	h, _ := setupTestHandler(t)
	src, dst := seedConnectionEndpoints(t, h)
	gone := seedRetiredDevice(t, h)
	for _, c := range []*models.DeviceConnection{
		{Name: "live", SourceDeviceID: src.ID, DestDeviceID: dst.ID, ConnectionType: "ipsec"},
		{Name: "? ↔ fw-dst", SourceDeviceID: gone.ID, DestDeviceID: dst.ID, ConnectionType: "ipsec", AutoDetected: true},
	} {
		if err := h.db.Gorm().Create(c).Error; err != nil {
			t.Fatalf("seed connection: %v", err)
		}
	}

	router := gin.New()
	router.GET("/dashboard/all", h.GetDashboardAll)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/dashboard/all", nil))
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Dashboard struct {
				Connections []models.DeviceConnection `json:"connections"`
			} `json:"dashboard"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	conns := resp.Data.Dashboard.Connections
	if len(conns) != 1 || conns[0].Name != "live" {
		t.Errorf("dashboard connections = %+v, want only the live one", conns)
	}
}

// The production shape: the surviving OPNsense still reports the tunnel that
// was provisioned to the now-retired FortiGate. The map's VPN panel must show
// it unmatched, not as a link to the retired device's page.
func TestGetVPNMapData_RetiredProvisionedPeerIsUnmatched(t *testing.T) {
	h, _ := setupTestHandler(t)
	_, opn := seedConnectionEndpoints(t, h)
	gone := seedRetiredDevice(t, h)

	in := &ipsec.TunnelIntent{Name: "fwm-t12", Enabled: true, IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased}
	in.Ends[0] = ipsec.EndpointSpec{DeviceID: gone.ID, Vendor: "fortigate", EgressIface: "port1", ProtectedSubnets: []string{"192.168.113.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{DeviceID: opn.ID, Vendor: "opnsense", EgressIface: "wan", ProtectedSubnets: []string{"192.168.150.0/24"}}
	m, err := database.IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	m.Status = "rollback_failed"
	if err := h.db.Gorm().Create(m).Error; err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := h.db.Gorm().Create(&models.VPNStatus{DeviceID: opn.ID, TunnelName: "fwm-t12", TunnelType: "ipsec",
		RemoteIP: gone.IPAddress, Status: "down", Timestamp: time.Now()}).Error; err != nil {
		t.Fatalf("save vpn: %v", err)
	}

	router := gin.New()
	router.GET("/vpn-map", h.GetVPNMapData)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/vpn-map", nil))
	var out struct {
		Data map[string]struct {
			Tunnels []struct {
				TunnelName   string `json:"tunnel_name"`
				MatchedDevID uint   `json:"matched_device_id"`
			} `json:"tunnels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%d)", err, w.Code)
	}
	found := false
	for _, dev := range out.Data {
		for _, tun := range dev.Tunnels {
			if tun.TunnelName != "fwm-t12" {
				continue
			}
			found = true
			if tun.MatchedDevID != 0 {
				t.Errorf("tunnel matched to device %d; a retired provisioned peer must be unmatched (and never an IP fallback)", tun.MatchedDevID)
			}
		}
	}
	if !found {
		t.Fatalf("fwm-t12 not in the map payload; the fixture no longer exercises the case: %s", w.Body.String())
	}
}
