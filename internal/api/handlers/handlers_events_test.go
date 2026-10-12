package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
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
