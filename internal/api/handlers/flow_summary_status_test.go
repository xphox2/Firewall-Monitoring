package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestGetFlowSummaryStatus: the endpoint repeats what the poller stored and
// judges nothing itself.
func TestGetFlowSummaryStatus(t *testing.T) {
	h, db := setupTestHandler(t)

	code, body := callHandler(t, h.GetFlowSummaryStatus, "GET")
	if code != http.StatusOK {
		t.Fatalf("status %d before anything is stored", code)
	}
	tiers := body["tiers"].(map[string]interface{})
	for _, iv := range []string{"1h", "1d"} {
		if v := tiers[iv].(map[string]interface{})["verdict"]; v != database.FlowSummaryUnknown {
			t.Fatalf("%s verdict with nothing stored = %v, want unknown", iv, v)
		}
	}

	lastOK := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	stored := database.FlowSummaryHealth{EvaluatedAt: time.Now().UTC(), Tiers: map[string]database.FlowSummaryTierHealth{
		"1h": {Verdict: database.FlowSummaryStalled, LastOKAt: lastOK, CaughtUp: true, LastErrorClass: "timeout"},
		"1d": {Verdict: database.FlowSummaryOK, CaughtUp: true},
	}}
	if err := db.SaveFlowSummaryHealth(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	_, data := callHandler(t, h.GetFlowSummaryStatus, "GET")
	hourly := data["tiers"].(map[string]interface{})["1h"].(map[string]interface{})
	if hourly["verdict"] != database.FlowSummaryStalled || hourly["last_error_class"] != "timeout" || hourly["caught_up"] != true {
		t.Fatalf("hourly tier: %v", hourly)
	}
	if got, _ := time.Parse(time.RFC3339, hourly["last_ok_at"].(string)); !got.Equal(lastOK) {
		t.Fatalf("last_ok_at = %v, want %v", hourly["last_ok_at"], lastOK)
	}
	if data["stale"] != false {
		t.Fatalf("a fresh evaluation is marked stale: %v", data["stale"])
	}

	stored.EvaluatedAt = time.Now().UTC().Add(-16 * time.Minute)
	if err := db.SaveFlowSummaryHealth(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	_, data = callHandler(t, h.GetFlowSummaryStatus, "GET")
	if data["stale"] != true {
		t.Fatal("an evaluation 16 minutes old is not marked stale")
	}
}

// TestUpdateSettings_FlowSummaryStallMinutes: 0 or 30-1440. A threshold of a
// few minutes would fire and clear on every cycle of a healthy install.
func TestUpdateSettings_FlowSummaryStallMinutes(t *testing.T) {
	h, db := setupTestHandler(t)
	post := func(v string) int {
		t.Helper()
		w := doSettingsRequest(t, h.UpdateSettings, "POST", []map[string]string{
			{"key": "flow_summary_stall_alert_minutes", "value": v, "category": "alerts", "type": "string"}})
		return w.Code
	}
	for _, v := range []string{"0", "30", "60", "1440"} {
		if code := post(v); code != http.StatusOK {
			t.Errorf("value %s rejected with %d", v, code)
		}
		var s models.SystemSetting
		if err := db.Gorm().Where(`"key" = ?`, "flow_summary_stall_alert_minutes").First(&s).Error; err != nil || s.Value != v {
			t.Errorf("value %s not stored: %q err=%v", v, s.Value, err)
		}
	}
	for _, v := range []string{"1", "5", "29", "1441", "-1", "soon", ""} {
		if code := post(v); code != http.StatusBadRequest {
			t.Errorf("value %q accepted with %d", v, code)
		}
	}
}
