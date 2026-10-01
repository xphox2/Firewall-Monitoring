package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func callHandler(t *testing.T, fn gin.HandlerFunc, method string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/x", nil)
	fn(c)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp.Data
}

// TestReapplyFlowClassification bumps the revision and rebuilds the ingest set
// before returning, so no new row is stamped with the old revision under the
// new target; the status then reports the run as pending.
func TestReapplyFlowClassification(t *testing.T) {
	h, db := setupTestHandler(t)
	if got := h.internalNets.Load().Rev(); got != 1 {
		t.Fatalf("initial set revision %d, want 1", got)
	}
	code, data := callHandler(t, h.ReapplyFlowClassification, "POST")
	if code != http.StatusOK {
		t.Fatalf("reapply: %d %v", code, data)
	}
	if db.FlowReclassTargetRev() != 2 {
		t.Errorf("target = %d, want 2", db.FlowReclassTargetRev())
	}
	if got := h.internalNets.Load().Rev(); got != 2 {
		t.Errorf("ingest set revision %d after Reapply, want 2 — it must be rebuilt before returning", got)
	}
	if data["phase"] != "pending" || data["target"].(float64) != 2 {
		t.Errorf("status after Reapply = %v, want pending for target 2", data)
	}

	db.Gorm().Model(&models.SystemSetting{}).Where(`"key" = ?`, database.FlowReclassTargetRevKey).Update("value", "65535")
	if code, _ := callHandler(t, h.ReapplyFlowClassification, "POST"); code != http.StatusConflict {
		t.Errorf("reapply at the revision limit: %d, want 409", code)
	}
}

// TestGetFlowReclassStatus_Done: with the target's run complete the status is
// done at 100%.
func TestGetFlowReclassStatus_Done(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.FlowReclassDoneRevKey, Value: "1"}).Error; err != nil {
		t.Fatal(err)
	}
	code, data := callHandler(t, h.GetFlowReclassStatus, "GET")
	if code != http.StatusOK || data["phase"] != "done" || data["percent"].(float64) != 100 {
		t.Errorf("status = %d %v, want done at 100", code, data)
	}
}

// TestFlowIngest_RevisionZeroLeavesARearmMark: rows stamped before any
// internal-network set loaded are revision 0; ingest records that so the
// reclassification job revisits them.
func TestFlowIngest_RevisionZeroLeavesARearmMark(t *testing.T) {
	h, db := setupTestHandler(t)
	h.internalNets.Store(nil)
	flow := []map[string]interface{}{{"sampler_address": "10.9.1.1", "src_addr": "198.19.9.156", "dst_addr": "203.0.113.9",
		"src_port": 443, "dst_port": 51234, "protocol": 6, "bytes": 100, "packets": 1}}
	postFlows(t, h, db, "rearm", flow)
	if v, ok := db.GetSettingValue(database.FlowReclassRearmKey); !ok || v == "" {
		t.Fatal("ingest stamped revision 0 without leaving a re-arm mark")
	}
	if !h.rearmMarked.Load() {
		t.Error("the mark flag was not set after a successful write")
	}
}

// TestGetFlowReclassStatus_StaleRunIsPending: right after a Reapply the last
// status belongs to the previous revision's run; showing its percentage would
// claim progress on a run that has not started.
func TestGetFlowReclassStatus_StaleRunIsPending(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.FlowReclassStatusKey,
		Value: `{"rev":1,"phase":"reclassifying","rows":42,"estimate":127}`}).Error; err != nil {
		t.Fatal(err)
	}
	if _, data := callHandler(t, h.GetFlowReclassStatus, "GET"); data["phase"] != "reclassifying" {
		t.Fatalf("the current run's status = %v, want reclassifying", data)
	}
	if _, err := db.BumpFlowReclassTargetRev(); err != nil {
		t.Fatal(err)
	}
	if _, data := callHandler(t, h.GetFlowReclassStatus, "GET"); data["phase"] != "pending" || data["rows"].(float64) != 0 {
		t.Errorf("status after a Reapply = %v, want pending with no rows", data)
	}
}

// TestGetFlowReclassStatus_Rebuilding: once history is reclassified, a pending
// summary rebuild is reported per tier — the daily walk first.
func TestGetFlowReclassStatus_Rebuilding(t *testing.T) {
	h, db := setupTestHandler(t)
	for k, v := range map[string]string{
		database.FlowReclassDoneRevKey:  "1",
		"flow_summary_recompute_1d":     "1|2026-08-01T00:00:00Z",
		"flow_summary_recompute_status": `{"rev":1,"tiers":{"1d":{"state":"rebuilding","remaining_buckets":30,"done_buckets":10,"buckets_per_cycle":2},"1h":{"state":"waiting"}}}`,
	} {
		if err := db.Gorm().Create(&models.SystemSetting{Key: k, Value: v}).Error; err != nil {
			t.Fatal(err)
		}
	}
	_, data := callHandler(t, h.GetFlowReclassStatus, "GET")
	if data["phase"] != "rebuilding" || data["rebuild_tier"] != "daily" || data["percent"].(float64) != 25 {
		t.Errorf("status = %v, want rebuilding the daily tier at 25%%", data)
	}
	if eta, _ := data["eta_hours"].(float64); eta < 1.2 || eta > 1.3 {
		t.Errorf("eta_hours = %v, want 30 buckets / 2 per 5-minute cycle = 1.25 h", data["eta_hours"])
	}
}
