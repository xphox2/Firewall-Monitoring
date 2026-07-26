package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// The group chart exists because one tunnel is reported as several vpn_status
// rows under unrelated names. The handler's job is to turn a group LABEL back
// into that set of names, scoped to one device. These cover the parts the
// database-layer tests cannot: routing, the query parameter, and the failure
// shapes.

func doGroupChart(t *testing.T, h *Handler, deviceID uint, query string) (int, []database.VPNChartBucket) {
	t.Helper()
	router := gin.New()
	// The real route shape. A wildcard like /x/*any would leave c.Param("id")
	// empty and httputil.ParseID would reject before any of this is exercised.
	router.GET("/devices/:id/vpn-group-chart", h.GetVPNGroupChart)

	req := httptest.NewRequest("GET", "/devices/"+strconv.FormatUint(uint64(deviceID), 10)+"/vpn-group-chart"+query, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp struct {
		Data []database.VPNChartBucket `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp.Data
}

// seedGroupedTunnel writes the production shape: a config-derived row carrying
// the provisioned name but NO counters, and its counter-bearing sibling under a
// synthesized name with an empty phase1_name. Plus the provisioning record that
// is what unites them.
func seedGroupedTunnel(t *testing.T, db *database.Database) {
	t.Helper()
	if err := db.Gorm().Create(&models.IPSecTunnel{
		Name: "fwm-t11", Status: "up", ADeviceID: 1, BDeviceID: 2,
		AVendor: "fortigate", BVendor: "opnsense",
		IntentJSON: `{"name":"fwm-t11","ends":[{"device_id":1,"vendor":"fortigate","protected_subnets":["192.168.13.0/24"]},{"device_id":2,"vendor":"opnsense","protected_subnets":["192.168.50.0/24"]}]}`,
	}).Error; err != nil {
		t.Fatalf("seed tunnel: %v", err)
	}

	base := time.Now().Add(-30 * time.Minute)
	rows := []models.VPNStatus{}
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		// SSH-sourced: the name, no counters.
		rows = append(rows, models.VPNStatus{
			DeviceID: 1, TunnelName: "fwm-t11", Phase1Name: "fwm-t11",
			TunnelType: "ipsec", Status: "unknown", Timestamp: ts,
		})
		// SNMP-sourced: the counters, no phase1 name.
		rows = append(rows, models.VPNStatus{
			DeviceID: 1, TunnelName: "dialup-76.66.145.98", TunnelType: "ipsec-dialup",
			Status: "up", RemoteIP: "76.66.145.98",
			LocalSubnet: "192.168.13.0/24", RemoteSubnet: "192.168.50.0/24",
			BytesIn: uint64(1000 + i*100), BytesOut: uint64(2000 + i*200), Timestamp: ts,
		})
	}
	if err := db.SaveVPNStatuses(rows); err != nil {
		t.Fatalf("seed vpn: %v", err)
	}
}

// The point of the endpoint: the group resolves to BOTH member names, so the
// counter-bearing row is included and the chart has data.
//
// Note the trap this asserts past: the handler answers 200 with an empty array
// when nothing resolves, so a status-code-only assertion would pass while
// exercising the fallback path instead of the group path.
func TestGetVPNGroupChart_ResolvesGroupMembersAndReturnsData(t *testing.T) {
	h, db := setupTestHandler(t)
	seedGroupedTunnel(t, db)

	code, buckets := doGroupChart(t, h, 1, "?group=fwm-t11&range=24h")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(buckets) == 0 {
		t.Fatal("no buckets — the group resolved to no counter-bearing member, which is " +
			"the blank-chart symptom this endpoint exists to remove")
	}
	var total float64
	for _, b := range buckets {
		total += b.InBytes + b.OutBytes
	}
	if total == 0 {
		t.Error("buckets carry no traffic; the counter-bearing sibling was not included")
	}
}

// Group labels are unique per provisioned tunnel, NOT per device. Asking under
// the wrong device must not leak another device's series.
func TestGetVPNGroupChart_IsScopedToTheRequestedDevice(t *testing.T) {
	h, db := setupTestHandler(t)
	seedGroupedTunnel(t, db) // all rows are on device 1

	code, buckets := doGroupChart(t, h, 2, "?group=fwm-t11&range=24h")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(buckets) != 0 {
		t.Errorf("device 2 has no rows for this group; returning %d buckets means the query "+
			"is not device-scoped", len(buckets))
	}
}

// An unknown group is not an error — the page may ask for one whose rows just
// aged out — but it must return nothing rather than everything.
func TestGetVPNGroupChart_UnknownGroupIsEmptyNotEverything(t *testing.T) {
	h, db := setupTestHandler(t)
	seedGroupedTunnel(t, db)

	code, buckets := doGroupChart(t, h, 1, "?group=does-not-exist&range=24h")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(buckets) != 0 {
		t.Errorf("an unknown group must resolve to no members, got %d buckets — an empty "+
			"member list must never widen to 'all tunnels on this device'", len(buckets))
	}
}

// A missing group is a client error, distinct from a group with no data.
func TestGetVPNGroupChart_MissingGroupIsRejected(t *testing.T) {
	h, db := setupTestHandler(t)
	seedGroupedTunnel(t, db)

	if code, _ := doGroupChart(t, h, 1, "?range=24h"); code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — no group is a malformed request, not an empty result", code)
	}
}
