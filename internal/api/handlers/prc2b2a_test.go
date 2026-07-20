package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// makeOpnsenseDevice seeds an OPNsense device with a collector + key:secret token.
func makeOpnsenseDevice(t *testing.T, db *database.Database, probeID uint, ip string) *models.Device {
	t.Helper()
	dev := &models.Device{Name: "opn-" + ip, IPAddress: ip, Vendor: "opnsense", ProbeID: &probeID, APIToken: "key:secret", APIPort: 443}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	return dev
}

func deployStateOf(t *testing.T, db *database.Database, id uint) ipsec.DeployState {
	t.Helper()
	row, _ := db.GetIPSecTunnel(id)
	var st ipsec.DeployState
	if row.DeployJSON != "" {
		if err := json.Unmarshal([]byte(row.DeployJSON), &st); err != nil {
			t.Fatalf("deploy state: %v", err)
		}
	}
	return st
}

func pollDeploy(t *testing.T, h *Handler, id uint) map[string]any {
	t.Helper()
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDeployResult(c)
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("poll decode: %v (%s)", err, rec.Body.String())
	}
	return resp.Data
}

func TestApplyRunnerSupported_OPNsense(t *testing.T) {
	if !ipsecApplyRunnerSupported("opnsense") || !ipsecApplyRunnerSupported("fortigate") {
		t.Fatal("both fortigate and opnsense must be apply-runner supported")
	}
	if ipsecApplyRunnerSupported("cisco_asa") {
		t.Fatal("cisco_asa must not be apply-runner supported")
	}
}

func TestDeploy_TwoEnd_FortiGateOPNsense_EnqueuesBoth(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", devA.ID, devB.ID, 1)

	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("two-end deploy = %d, want 200", code)
	}
	st := deployStateOf(t, db, id)
	if len(st.Ends) != 2 {
		t.Fatalf("want 2 deployed ends (fortigate + opnsense), got %d", len(st.Ends))
	}
	for _, e := range st.Ends {
		cmd, _ := db.GetProbeCommandByCommandID(e.CommandID)
		if cmd == nil || cmd.Type != database.ProbeCommandTypeIPSecApply {
			t.Errorf("end %d apply command not enqueued", e.End)
		}
	}
}

func TestDeploy_409_WhenDeployRecordExists(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("first deploy = %d", code)
	}
	// Move to error but KEEP the deploy record (a partial-failure state).
	_ = db.UpdateIPSecTunnelStatus(id, "error", "boom")
	if _, code := deployReq(t, h, id); code != http.StatusConflict {
		t.Fatalf("deploy while a deploy record exists = %d, want 409", code)
	}
}

func TestAutoRollback_OnPartialFailure(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	st := deployStateOf(t, db, id)
	// End A applied+verified; end B failed → partial → auto-rollback.
	_, _, _ = db.CompleteProbeCommand(probe.ID, st.Ends[0].CommandID, "succeeded", `{"applied":true,"verified":true}`)
	_, _, _ = db.CompleteProbeCommand(probe.ID, st.Ends[1].CommandID, "succeeded", `{"applied":true,"verified":false,"error":"verify failed"}`)

	data := pollDeploy(t, h, id)
	if data["status"] != "rolling_back" {
		t.Fatalf("partial failure must auto-rollback → rolling_back, got %v", data["status"])
	}
	st2 := deployStateOf(t, db, id)
	if st2.Rollback == nil || !st2.Rollback.Auto {
		t.Fatalf("auto-rollback must set RollbackState.Auto: %+v", st2.Rollback)
	}
	if len(st2.Rollback.CommandIDs) != 2 {
		t.Errorf("want a remove command per end (2), got %d", len(st2.Rollback.CommandIDs))
	}
	for _, cid := range st2.Rollback.CommandIDs {
		cmd, _ := db.GetProbeCommandByCommandID(cid)
		if cmd == nil || cmd.Type != database.ProbeCommandTypeIPSecRemove {
			t.Errorf("auto-rollback remove command not enqueued")
		}
	}
	// One-shot: a second poll must not re-enqueue (status already rolling_back).
	_ = pollDeploy(t, h, id)
	st3 := deployStateOf(t, db, id)
	if len(st3.Rollback.CommandIDs) != 2 {
		t.Errorf("auto-rollback must fire once, got %d remove commands", len(st3.Rollback.CommandIDs))
	}
}

func TestAutoRollback_OPNsenseUnknownEnd_RollbackUnproven(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	st := deployStateOf(t, db, id)
	// FortiGate end A good; OPNsense end B command EXPIRED (collector offline) with
	// no captured UUIDs → its outcome is unknown and its rollback can't prove clean.
	var fgEnd, opnEnd ipsec.DeployEndState
	for _, e := range st.Ends {
		if e.Vendor == "fortigate" {
			fgEnd = e
		} else {
			opnEnd = e
		}
	}
	_, _, _ = db.CompleteProbeCommand(probe.ID, fgEnd.CommandID, "succeeded", `{"applied":true,"verified":true}`)
	if err := db.Gorm().Model(&models.ProbeCommand{}).Where("command_id = ?", opnEnd.CommandID).
		Update("status", "expired").Error; err != nil {
		t.Fatalf("expire opn command: %v", err)
	}

	if data := pollDeploy(t, h, id); data["status"] != "rolling_back" {
		t.Fatalf("want auto-rollback, got %v", data["status"])
	}
	st2 := deployStateOf(t, db, id)
	var opnMarked bool
	for _, e := range st2.Ends {
		if e.Vendor == "opnsense" {
			opnMarked = e.RollbackUnproven
		}
		if e.Vendor == "fortigate" && e.RollbackUnproven {
			t.Errorf("FortiGate end must NOT be marked RollbackUnproven (deterministic remove)")
		}
	}
	if !opnMarked {
		t.Fatalf("OPNsense unknown+no-uuid end must be marked RollbackUnproven")
	}
	// Complete both auto-rollback removes as clean; the marked OPNsense end must
	// still force rollback_failed (its clean skip proves nothing).
	for _, cid := range st2.Rollback.CommandIDs {
		_, _, _ = db.CompleteProbeCommand(probe.ID, cid, "succeeded", `{"applied":true}`)
	}
	if data := pollDeploy(t, h, id); data["status"] != "rollback_failed" {
		t.Fatalf("a RollbackUnproven end must land rollback_failed, got %v", data["status"])
	}
}

func TestForceReset_FromRecordBearingTerminalOnly(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	// Complete apply commands (terminal) so no command is "live", then wedge in
	// rollback_failed with the record kept.
	st := deployStateOf(t, db, id)
	for _, e := range st.Ends {
		_, _, _ = db.CompleteProbeCommand(probe.ID, e.CommandID, "failed", "boom")
	}
	_ = db.UpdateIPSecTunnelStatus(id, "rollback_failed", "wedged")

	reset := func() int {
		c, rec := jsonReq(http.MethodPost, "/x", "")
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
		h.ForceResetIPSecDeploy(c)
		return rec.Code
	}
	if code := reset(); code != http.StatusOK {
		t.Fatalf("reset from rollback_failed = %d, want 200", code)
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.Status != "draft" || row.DeployJSON != "" {
		t.Fatalf("reset must clear the record → draft, got status=%s recordEmpty=%v", row.Status, row.DeployJSON == "")
	}

	// A working (degraded) tunnel must refuse reset.
	_ = db.MarkIPSecTunnelDeployed(id, "degraded", "")
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.ForceResetIPSecDeploy(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("reset from degraded = %d, want 409", rec.Code)
	}
}
