package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"

	"github.com/gin-gonic/gin"
)

func getCapabilities(t *testing.T, h *Handler, path string, params gin.Params) (int, map[string]interface{}) {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil)
	c.Params = params
	if params == nil {
		h.GetCapabilities(c)
	} else {
		h.GetDeviceCapabilities(c)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v (%s)", path, err, rec.Body.String())
	}
	return rec.Code, body
}

func fieldState(t *testing.T, body map[string]interface{}, field string) string {
	t.Helper()
	data, _ := body["data"].(map[string]interface{})
	fields, _ := data["fields"].(map[string]interface{})
	cell, ok := fields[field].(map[string]interface{})
	if !ok {
		t.Fatalf("field %q missing from %v", field, fields)
	}
	s, _ := cell["state"].(string)
	return s
}

// TestCapabilityAPI_States pins the effective-state join of the static
// profile with the observed half: a Meraki device cannot supply nat_src_ip at
// all (unsupported), a FortiGate that has not sent rule_uid within the window
// is inactive for it, and one that has sent src_ip is native; a
// config_dependent cell the device does send reports config_dependent; a
// NetFlow-sourced cell (Meraki bytes) reports its static state because the
// syslog ingest cannot observe it; and the feature verdicts fold the same
// way. Rows older than the 24 h window do not count.
func TestCapabilityAPI_States(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	now := time.Now()
	rows := []models.DeviceFieldObserved{
		{DeviceID: f.dev["fortigate"].ID, Class: int16(normalize.ClassNetwork), Field: "src_ip", Count: 12, LastSeen: now},
		{DeviceID: f.dev["fortigate"].ID, Class: int16(normalize.ClassNetwork), Field: "dst_ip", Count: 12, LastSeen: now},
		{DeviceID: f.dev["fortigate"].ID, Class: int16(normalize.ClassNetwork), Field: "action", Count: 12, LastSeen: now},
		{DeviceID: f.dev["fortigate"].ID, Class: int16(normalize.ClassNetwork), Field: "rule_key", Count: 12, LastSeen: now},
		{DeviceID: f.dev["fortigate"].ID, Class: int16(normalize.ClassNetwork), Field: "bytes_in", Count: 12, LastSeen: now},
		// rule_uid was last seen two days ago: outside the window → inactive.
		{DeviceID: f.dev["fortigate"].ID, Class: int16(normalize.ClassNetwork), Field: "rule_uid", Count: 3, LastSeen: now.Add(-48 * time.Hour)},
		{DeviceID: f.dev["meraki"].ID, Class: int16(normalize.ClassNetwork), Field: "src_ip", Count: 5, LastSeen: now},
		{DeviceID: f.dev["meraki"].ID, Class: int16(normalize.ClassNetwork), Field: "dst_ip", Count: 5, LastSeen: now},
		{DeviceID: f.dev["meraki"].ID, Class: int16(normalize.ClassNetwork), Field: "action", Count: 5, LastSeen: now},
		{DeviceID: f.dev["meraki"].ID, Class: int16(normalize.ClassNetwork), Field: "rule_key", Count: 5, LastSeen: now},
	}
	if err := f.db.FlushFieldObserved(rows); err != nil {
		t.Fatal(err)
	}

	fgID := gin.Params{{Key: "id", Value: itoa(f.dev["fortigate"].ID)}}
	code, body := getCapabilities(t, f.h, "/admin/api/devices/x/capabilities", fgID)
	if code != http.StatusOK {
		t.Fatalf("fortigate capabilities status = %d: %v", code, body)
	}
	for field, want := range map[string]string{
		"src_ip":   "native",
		"rule_uid": "inactive",         // supplyable, not seen within 24 h
		"bytes_in": "config_dependent", // FortiGate bytes need logtraffic all; seen → the option is on
		"user":     "inactive",         // supplyable, never seen
	} {
		if got := fieldState(t, body, field); got != want {
			t.Errorf("fortigate %s state = %q, want %q", field, got, want)
		}
	}
	data := body["data"].(map[string]interface{})
	if v, _ := data["vendor"].(string); v != "fortigate" {
		t.Errorf("vendor = %q, want fortigate", v)
	}
	features := data["features"].(map[string]interface{})
	if s := features["deny_analytics"].(map[string]interface{})["state"]; s != "supported" {
		t.Errorf("fortigate deny_analytics = %v, want supported (action, src_ip, dst_ip all native)", s)
	}
	if s := features["user_attribution"].(map[string]interface{})["state"]; s != "inactive" {
		t.Errorf("fortigate user_attribution = %v, want inactive (user never observed)", s)
	}
	if s := features["policy_bytes"].(map[string]interface{})["state"]; s != "inactive" {
		// rule_key + bytes_in observed, bytes_out not: inactive outranks the
		// config_dependent degradation.
		t.Errorf("fortigate policy_bytes = %v, want inactive (bytes_out not observed)", s)
	}

	mkID := gin.Params{{Key: "id", Value: itoa(f.dev["meraki"].ID)}}
	code, body = getCapabilities(t, f.h, "/admin/api/devices/x/capabilities", mkID)
	if code != http.StatusOK {
		t.Fatalf("meraki capabilities status = %d: %v", code, body)
	}
	if got := fieldState(t, body, "nat_src_ip"); got != "unsupported" {
		t.Errorf("meraki nat_src_ip state = %q, want unsupported (no source at all)", got)
	}
	if got := fieldState(t, body, "bytes_in"); got != "native" {
		t.Errorf("meraki bytes_in state = %q, want native (NetFlow-sourced: static, not observed by syslog)", got)
	}
	if got := fieldState(t, body, "src_ip"); got != "native" {
		t.Errorf("meraki src_ip state = %q, want native", got)
	}
	data = body["data"].(map[string]interface{})
	if hw, _ := data["hardware"].(string); hw == "" {
		t.Error("meraki profile must report its untested-on-hardware label")
	}
	features = data["features"].(map[string]interface{})
	if s := features["nat_forensics"].(map[string]interface{})["state"]; s != "unsupported" {
		t.Errorf("meraki nat_forensics = %v, want unsupported", s)
	}
	if s := features["policy_bytes"].(map[string]interface{})["state"]; s != "degraded" {
		t.Errorf("meraki policy_bytes = %v, want degraded (rule_key observed but config_dependent; bytes static native)", s)
	}

	// Unknown device → 404.
	if code, _ := getCapabilities(t, f.h, "/admin/api/devices/x/capabilities", gin.Params{{Key: "id", Value: "999999"}}); code != http.StatusNotFound {
		t.Errorf("unknown device status = %d, want 404", code)
	}

	// Fleet view for one feature.
	code, body = getCapabilities(t, f.h, "/admin/api/capabilities?feature=deny_analytics", nil)
	if code != http.StatusOK {
		t.Fatalf("fleet capabilities status = %d: %v", code, body)
	}
	data = body["data"].(map[string]interface{})
	devices, _ := data["devices"].([]interface{})
	states := map[float64]string{}
	for _, d := range devices {
		row := d.(map[string]interface{})
		states[row["device_id"].(float64)] = row["state"].(string)
	}
	if len(states) != len(f.dev) {
		t.Errorf("fleet rows = %d, want one per active device (%d)", len(states), len(f.dev))
	}
	if s := states[float64(f.dev["fortigate"].ID)]; s != "supported" {
		t.Errorf("fleet fortigate deny_analytics = %q, want supported", s)
	}
	if s := states[float64(f.dev["pfsense"].ID)]; s != "inactive" {
		t.Errorf("fleet pfsense deny_analytics = %q, want inactive (nothing observed)", s)
	}
	if s := states[float64(f.dev["meraki"].ID)]; s != "degraded" {
		t.Errorf("fleet meraki deny_analytics = %q, want degraded (action is config_dependent on the per-rule syslog box, and observed)", s)
	}

	// Unknown feature → 400 naming the vocabulary; no parameter → the list.
	if code, body := getCapabilities(t, f.h, "/admin/api/capabilities?feature=nope", nil); code != http.StatusBadRequest {
		t.Errorf("unknown feature status = %d, want 400 (%v)", code, body)
	}
	code, body = getCapabilities(t, f.h, "/admin/api/capabilities", nil)
	if code != http.StatusOK {
		t.Fatalf("feature list status = %d", code)
	}
	data = body["data"].(map[string]interface{})
	if feats, _ := data["features"].(map[string]interface{}); feats["deny_analytics"] == nil {
		t.Errorf("feature list missing deny_analytics: %v", feats)
	}
}
