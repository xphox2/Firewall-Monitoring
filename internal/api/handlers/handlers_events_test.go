package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestGetNetEvents_Shape seeds one net_event and asserts the handler returns a
// 200 with the events/total/total_capped envelope the Events page reads.
func TestGetNetEvents_Shape(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-1", IPAddress: "10.0.0.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	row := &models.NetEvent{
		Ts:       time.Now(),
		DeviceID: dev.ID,
		Activity: 3,
		Action:   1,
	}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed net_event: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x?hours=24", "")
	h.GetNetEvents(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Events      []models.NetEvent `json:"events"`
			Total       int64             `json:"total"`
			TotalCapped bool              `json:"total_capped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || resp.Data.Total != 1 || len(resp.Data.Events) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

// TestGetNetEvents_BadNumericParams asserts non-numeric numeric filters are
// rejected with 400 before being bound against uint/smallint columns (AUDIT-251
// / 22P02). Only the first offending filter matters for the assertion; each is
// exercised independently.
func TestGetNetEvents_BadNumericParams(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, param := range []string{"device_id", "probe_id", "site_id", "activity", "action"} {
		c, rec := jsonReq(http.MethodGet, "/x?"+param+"=not-a-number", "")
		h.GetNetEvents(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetNetEvents(%s=not-a-number) = %d, want 400", param, rec.Code)
		}
	}
}

// TestGetNetEvents_BadIPParams asserts a malformed src_ip/dst_ip is rejected
// with 400 (not a 500 from an invalid inet cast on Postgres) before it reaches
// the query, while a valid bare IP or CIDR passes.
func TestGetNetEvents_BadIPParams(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, tc := range []struct{ param, val string }{
		{"src_ip", "not-an-ip"},
		{"src_ip", "10.0.0.0/99"},
		{"dst_ip", "999.999.999.999"},
		{"dst_ip", "10.0.0.0/8/8"},
	} {
		c, rec := jsonReq(http.MethodGet, "/x?"+tc.param+"="+tc.val, "")
		h.GetNetEvents(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetNetEvents(%s=%q) = %d, want 400", tc.param, tc.val, rec.Code)
		}
	}
	for _, ok := range []string{"10.0.0.5", "10.0.0.0/24", "2001:db8::1"} {
		c, rec := jsonReq(http.MethodGet, "/x?src_ip="+ok, "")
		h.GetNetEvents(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetNetEvents(src_ip=%q) = %d, want 200", ok, rec.Code)
		}
	}
}

// TestGetSecEvents_Shape seeds one sec_event and asserts the handler returns a
// 200 with the events/total/total_capped envelope the Security tab reads.
func TestGetSecEvents_Shape(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-1", IPAddress: "10.0.0.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	sev := int16(5)
	row := &models.SecEvent{Ts: time.Now(), DeviceID: dev.ID, Class: 2004, Severity: &sev}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed sec_event: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x?hours=24&class=2004", "")
	h.GetSecEvents(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Events      []models.SecEvent `json:"events"`
			Total       int64             `json:"total"`
			TotalCapped bool              `json:"total_capped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || resp.Data.Total != 1 || len(resp.Data.Events) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

// TestGetSecEvents_BadNumericParams asserts non-numeric numeric filters are
// rejected with 400 before being bound against uint/smallint columns (AUDIT-251
// / 22P02).
func TestGetSecEvents_BadNumericParams(t *testing.T) {
	h, _ := setupTestHandler(t)
	for _, param := range []string{"device_id", "probe_id", "class", "activity", "action", "severity"} {
		c, rec := jsonReq(http.MethodGet, "/x?"+param+"=not-a-number", "")
		h.GetSecEvents(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetSecEvents(%s=not-a-number) = %d, want 400", param, rec.Code)
		}
	}
}

// TestGetNetEventRollups_Shape asserts the handler returns a 200 with the six
// analytics series the Events page charts, even with no rollup rows seeded (the
// empty series must be [] not null).
func TestGetNetEventRollups_Shape(t *testing.T) {
	h, _ := setupTestHandler(t)

	c, rec := jsonReq(http.MethodGet, "/x?days=30", "")
	h.GetNetEventRollups(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			PolicyHits    []json.RawMessage `json:"policy_hits"`
			PolicyBytes   []json.RawMessage `json:"policy_bytes"`
			Deny          []json.RawMessage `json:"deny"`
			AppCategories []json.RawMessage `json:"app_categories"`
			Directions    []json.RawMessage `json:"directions"`
			Rulesets      []json.RawMessage `json:"rulesets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false: %s", rec.Body.String())
	}
	// Every series must be present and a non-nil slice (so the UI maps it
	// without a null guard).
	for name, s := range map[string][]json.RawMessage{
		"policy_hits":    resp.Data.PolicyHits,
		"policy_bytes":   resp.Data.PolicyBytes,
		"deny":           resp.Data.Deny,
		"app_categories": resp.Data.AppCategories,
		"directions":     resp.Data.Directions,
		"rulesets":       resp.Data.Rulesets,
	} {
		if s == nil {
			t.Fatalf("%s is null, want []", name)
		}
	}
}

// TestGetNetEventRollups_BadParams asserts an out-of-range or non-integer days
// and a non-numeric device_id/site_id are rejected with 400 (AUDIT-251
// discipline: a bad value is a 400, never a 500).
func TestGetNetEventRollups_BadParams(t *testing.T) {
	h, _ := setupTestHandler(t)

	for _, tc := range []struct{ name, qs string }{
		{"days too large", "days=366"},
		{"days zero", "days=0"},
		{"days negative", "days=-1"},
		{"days non-integer", "days=abc"},
		{"device_id non-numeric", "device_id=not-a-number"},
		{"site_id non-numeric", "site_id=not-a-number"},
	} {
		c, rec := jsonReq(http.MethodGet, "/x?"+tc.qs, "")
		h.GetNetEventRollups(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetNetEventRollups(%s) = %d, want 400 (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// A valid days value (and the default) pass.
	for _, qs := range []string{"", "days=1", "days=365", "days=30&device_id=1&site_id=2"} {
		c, rec := jsonReq(http.MethodGet, "/x?"+qs, "")
		h.GetNetEventRollups(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetNetEventRollups(%q) = %d, want 200 (body=%s)", qs, rec.Code, rec.Body.String())
		}
	}
}

// TestGetNetEventAnalytics_Shape asserts the handler returns a 200 with the
// nine short-window analytics series the Events page charts, even with no rows
// seeded (the empty series must be [] not null).
func TestGetNetEventAnalytics_Shape(t *testing.T) {
	h, _ := setupTestHandler(t)

	c, rec := jsonReq(http.MethodGet, "/x?hours=24", "")
	h.GetNetEventAnalytics(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			GeoSrc        []json.RawMessage `json:"geo_src"`
			GeoDst        []json.RawMessage `json:"geo_dst"`
			Identity      []json.RawMessage `json:"identity"`
			Users         []json.RawMessage `json:"users"`
			Apps          []json.RawMessage `json:"apps"`
			AppCategories []json.RawMessage `json:"app_categories"`
			WebCategories []json.RawMessage `json:"web_categories"`
			DNS           []json.RawMessage `json:"dns"`
			NAT           []json.RawMessage `json:"nat"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false: %s", rec.Body.String())
	}
	for name, s := range map[string][]json.RawMessage{
		"geo_src":        resp.Data.GeoSrc,
		"geo_dst":        resp.Data.GeoDst,
		"identity":       resp.Data.Identity,
		"users":          resp.Data.Users,
		"apps":           resp.Data.Apps,
		"app_categories": resp.Data.AppCategories,
		"web_categories": resp.Data.WebCategories,
		"dns":            resp.Data.DNS,
		"nat":            resp.Data.NAT,
	} {
		if s == nil {
			t.Fatalf("%s is null, want []", name)
		}
	}
}

// TestGetNetEventAnalytics_BadParams asserts an out-of-range or non-integer
// hours and a non-numeric device_id/site_id are rejected with 400 (AUDIT-251
// discipline: a bad value is a 400, never a 500).
func TestGetNetEventAnalytics_BadParams(t *testing.T) {
	h, _ := setupTestHandler(t)

	for _, tc := range []struct{ name, qs string }{
		{"hours zero", "hours=0"},
		{"hours too large", "hours=721"},
		{"hours negative", "hours=-1"},
		{"hours non-integer", "hours=abc"},
		{"device_id non-numeric", "device_id=not-a-number"},
		{"site_id non-numeric", "site_id=not-a-number"},
	} {
		c, rec := jsonReq(http.MethodGet, "/x?"+tc.qs, "")
		h.GetNetEventAnalytics(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetNetEventAnalytics(%s) = %d, want 400 (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// A valid hours value (and the default) pass.
	for _, qs := range []string{"", "hours=1", "hours=720", "hours=24&device_id=1&site_id=2"} {
		c, rec := jsonReq(http.MethodGet, "/x?"+qs, "")
		h.GetNetEventAnalytics(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetNetEventAnalytics(%q) = %d, want 200 (body=%s)", qs, rec.Code, rec.Body.String())
		}
	}
}

// TestGetSecEventAnalytics_Shape asserts the handler returns a 200 with the
// twelve class-scoped analytics series the Security tab charts, even with no
// rows seeded (the empty series must be [] not null).
func TestGetSecEventAnalytics_Shape(t *testing.T) {
	h, _ := setupTestHandler(t)

	c, rec := jsonReq(http.MethodGet, "/x?days=30", "")
	h.GetSecEventAnalytics(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Findings        []json.RawMessage `json:"findings"`
			TopSignatures   []json.RawMessage `json:"top_signatures"`
			AdminLogins     []json.RawMessage `json:"admin_logins"`
			TopAdminUsers   []json.RawMessage `json:"top_admin_users"`
			TopAdminSrcIPs  []json.RawMessage `json:"top_admin_src_ips"`
			ConfigChanges   []json.RawMessage `json:"config_changes"`
			TopConfigPaths  []json.RawMessage `json:"top_config_paths"`
			TopConfigAdmins []json.RawMessage `json:"top_config_admins"`
			VPNSessions     []json.RawMessage `json:"vpn_sessions"`
			TopTunnels      []json.RawMessage `json:"top_tunnels"`
			TopTunnelPeers  []json.RawMessage `json:"top_tunnel_peers"`
			WanHealth       []json.RawMessage `json:"wan_health"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false: %s", rec.Body.String())
	}
	for name, s := range map[string][]json.RawMessage{
		"findings":          resp.Data.Findings,
		"top_signatures":    resp.Data.TopSignatures,
		"admin_logins":      resp.Data.AdminLogins,
		"top_admin_users":   resp.Data.TopAdminUsers,
		"top_admin_src_ips": resp.Data.TopAdminSrcIPs,
		"config_changes":    resp.Data.ConfigChanges,
		"top_config_paths":  resp.Data.TopConfigPaths,
		"top_config_admins": resp.Data.TopConfigAdmins,
		"vpn_sessions":      resp.Data.VPNSessions,
		"top_tunnels":       resp.Data.TopTunnels,
		"top_tunnel_peers":  resp.Data.TopTunnelPeers,
		"wan_health":        resp.Data.WanHealth,
	} {
		if s == nil {
			t.Fatalf("%s is null, want []", name)
		}
	}
}

// TestGetSecEventAnalytics_BadParams asserts an out-of-range or non-integer
// days/hours and a non-numeric device_id/site_id are rejected with 400
// (AUDIT-251 discipline: a bad value is a 400, never a 500).
func TestGetSecEventAnalytics_BadParams(t *testing.T) {
	h, _ := setupTestHandler(t)

	for _, tc := range []struct{ name, qs string }{
		{"days zero", "days=0"},
		{"days too large", "days=366"},
		{"days non-integer", "days=abc"},
		{"hours zero", "hours=0"},
		{"hours too large", "hours=721"},
		{"hours non-integer", "hours=abc"},
		{"device_id non-numeric", "device_id=not-a-number"},
		{"site_id non-numeric", "site_id=not-a-number"},
	} {
		c, rec := jsonReq(http.MethodGet, "/x?"+tc.qs, "")
		h.GetSecEventAnalytics(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GetSecEventAnalytics(%s) = %d, want 400 (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// A valid window (and the default) pass.
	for _, qs := range []string{"", "days=1", "days=365", "hours=720", "days=30&device_id=1&site_id=2"} {
		c, rec := jsonReq(http.MethodGet, "/x?"+qs, "")
		h.GetSecEventAnalytics(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetSecEventAnalytics(%q) = %d, want 200 (body=%s)", qs, rec.Code, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Event detail getters (Phase 2, PR 8)
// ---------------------------------------------------------------------------

// eventDetailIDParam sets the gin :id param on the test context.
func eventDetailIDParam(c *gin.Context, id string) {
	c.Params = gin.Params{{Key: "id", Value: id}}
}

// TestGetNetEvent_Shape seeds one net_event (with raw_id provenance) and asserts
// the detail handler returns it under `data`, enriched, with raw_id intact.
func TestGetNetEvent_Shape(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-1", IPAddress: "10.0.0.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	rawID := int64(5)
	row := &models.NetEvent{Ts: time.Now(), DeviceID: dev.ID, Activity: 3, Action: 1, RawID: &rawID}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed net_event: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x", "")
	eventDetailIDParam(c, strconv.Itoa(int(row.ID)))
	h.GetNetEvent(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			ID         uint   `json:"id"`
			DeviceName string `json:"device_name"`
			RawID      *int64 `json:"raw_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || resp.Data.ID != row.ID {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Data.DeviceName != "fw-1" {
		t.Fatalf("device_name = %q, want fw-1 (enrichment must run)", resp.Data.DeviceName)
	}
	if resp.Data.RawID == nil || *resp.Data.RawID != 5 {
		t.Fatalf("raw_id = %v, want 5 (provenance for the raw syslog link)", resp.Data.RawID)
	}
}

// TestGetNetEvent_BadID asserts a malformed :id is a 400 (httputil.ParseID),
// never a 500 from binding it against the uint PK.
func TestGetNetEvent_BadID(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/x", "")
	eventDetailIDParam(c, "not-a-number")
	h.GetNetEvent(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GetNetEvent(bad id) = %d, want 400", rec.Code)
	}
}

// TestGetNetEvent_NotFound asserts an unknown :id is a 404.
func TestGetNetEvent_NotFound(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/x", "")
	eventDetailIDParam(c, "999999")
	h.GetNetEvent(c)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GetNetEvent(999999) = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestGetSecEvent_Shape mirrors TestGetNetEvent_Shape for the security detail.
func TestGetSecEvent_Shape(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-1", IPAddress: "10.0.0.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	sev := int16(5)
	row := &models.SecEvent{Ts: time.Now(), DeviceID: dev.ID, Class: 2004, Severity: &sev}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed sec_event: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x", "")
	eventDetailIDParam(c, strconv.Itoa(int(row.ID)))
	h.GetSecEvent(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			ID         uint   `json:"id"`
			Class      int16  `json:"class"`
			DeviceName string `json:"device_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || resp.Data.ID != row.ID || resp.Data.Class != 2004 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Data.DeviceName != "fw-1" {
		t.Fatalf("device_name = %q, want fw-1 (enrichment must run)", resp.Data.DeviceName)
	}
}

// TestGetSecEvent_BadID asserts a malformed :id is a 400.
func TestGetSecEvent_BadID(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/x", "")
	eventDetailIDParam(c, "not-a-number")
	h.GetSecEvent(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GetSecEvent(bad id) = %d, want 400", rec.Code)
	}
}

// TestGetSecEvent_NotFound asserts an unknown :id is a 404.
func TestGetSecEvent_NotFound(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/x", "")
	eventDetailIDParam(c, "999999")
	h.GetSecEvent(c)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GetSecEvent(999999) = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}
