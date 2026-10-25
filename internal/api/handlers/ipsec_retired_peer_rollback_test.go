package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// The retired-peer rollback path (IPSec retired-peer cleanup).
//
// The IPSec subsystem had NO notion of a retired peer: a decommissioned
// FortiGate is still a device row (soft-retired) or is gone entirely (purged),
// and neither can be cleaned. The remove command could not even be BUILT for
// such an end, and one unbuildable end aborted the WHOLE rollback — so the
// LIVE end (the OPNsense) never got cleaned, the tunnel stayed "provisioned"
// forever, and the phantom peer was re-manufactured on every telemetry cycle.

// rollbackReq drives the rollback handler for one tunnel.
func rollbackReq(t *testing.T, h *Handler, id uint) *httptest.ResponseRecorder {
	t.Helper()
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.RollbackIPSecTunnel(c)
	return rec
}

// deployAndSettle deploys a tunnel and parks it in a rollback-able status with
// its deploy record intact — the shape the rollback consumes. The apply
// commands are completed as failures so they are DEAD: the concurrency guard
// (ipsecHasLiveCommand) refuses a rollback while one is still in flight.
func deployAndSettle(t *testing.T, h *Handler, db *database.Database, id uint, status string) {
	t.Helper()
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d, want 200", code)
	}
	st := deployStateOf(t, db, id)
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probeIDOf(t, db, e.CommandID), e.CommandID, "failed", "apply did not run"); err != nil {
			t.Fatalf("complete apply: %v", err)
		}
	}
	if err := db.UpdateIPSecTunnelStatus(id, status, ""); err != nil {
		t.Fatalf("set tunnel status: %v", err)
	}
}

// probeIDOf returns the probe a command belongs to (the deploy's ends all
// target the same probe in these tests).
func probeIDOf(t *testing.T, db *database.Database, commandID string) uint {
	t.Helper()
	cmd, err := db.GetProbeCommandByCommandID(commandID)
	if err != nil || cmd == nil {
		t.Fatalf("read command %s: %v", commandID, err)
	}
	return cmd.ProbeID
}

// captureUUIDs merges captured UUIDs into one end of the deploy record — what
// the deploy poll does with the apply report. An OPNsense end WITH captures is
// proven (its remove can address the objects it created); one WITHOUT them is
// unproven (its remove would skip every step and report a false clean).
func captureUUIDs(t *testing.T, db *database.Database, id uint, end int, uuids map[string]string) {
	t.Helper()
	st := deployStateOf(t, db, id)
	found := false
	for i := range st.Ends {
		if st.Ends[i].End == end {
			st.Ends[i].CapturedUUIDs = uuids
			found = true
		}
	}
	if !found {
		t.Fatalf("no end %d in the deploy record", end)
	}
	blob, err := json.Marshal(&st)
	if err != nil {
		t.Fatalf("marshal deploy state: %v", err)
	}
	if err := db.Gorm().Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Update("deploy_json", string(blob)).Error; err != nil {
		t.Fatalf("write deploy record: %v", err)
	}
}

// completeRemove marks a rollback's remove command as a clean success.
func completeRemove(t *testing.T, db *database.Database, probeID uint, commandID string) {
	t.Helper()
	if commandID == "" {
		t.Fatal("completeRemove: empty command id")
	}
	if _, _, err := db.CompleteProbeCommand(probeID, commandID, "succeeded", `{"applied":true,"verified":true}`); err != nil {
		t.Fatalf("complete remove command: %v", err)
	}
}

func TestRollback_RetiredPeerEnd_SkipsAndCleansLiveEnd(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	dead := makeFortiDevice(t, db, probe.ID, "203.0.113.9")     // the decommissioned peer
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7") // the end that must be cleaned
	id := createTunnelRow(t, db, "fortigate", "opnsense", dead.ID, live.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})
	if err := db.RetireDevice(dead.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st := deployStateOf(t, db, id)
	if st.Rollback == nil {
		t.Fatal("no rollback state written")
	}
	if len(st.Rollback.Ends) != 2 {
		t.Fatalf("want 2 per-end rollback states, got %d", len(st.Rollback.Ends))
	}
	if !st.Rollback.Ends[0].Skipped {
		t.Error("the retired end must be SKIPPED, not attempted")
	}
	if st.Rollback.Ends[0].CommandID != "" {
		t.Error("a skipped end must not carry a command id")
	}
	if st.Rollback.Ends[0].SkipReason == "" {
		t.Error("a skipped end must carry the reason it was skipped")
	}
	if st.Rollback.Ends[1].Skipped || st.Rollback.Ends[1].CommandID == "" {
		t.Error("the live end must be rolled back, not skipped")
	}
	// No remove command may be enqueued for the retired device.
	cmds, _ := db.GetProbeCommands(probe.ID, 50)
	for _, cmd := range cmds {
		if cmd.Type == database.ProbeCommandTypeIPSecRemove && cmd.DeviceID == dead.ID {
			t.Error("no remove command may be enqueued for a retired end")
		}
	}

	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)
	data := pollDeploy(t, h, id)
	if data["status"] != "rolled_back" {
		t.Fatalf("want rolled_back, got %v (note: %v)", data["status"], data["note"])
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.DeployJSON != "" {
		t.Error("a clean rollback must clear the deploy record")
	}
}

func TestRollback_PurgedPeerEnd_SkipsAndCleansLiveEnd(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	gone := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", gone.ID, live.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})
	if err := db.DeleteDevice(gone.ID); err != nil {
		t.Fatalf("purge peer: %v", err)
	}

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st := deployStateOf(t, db, id)
	if st.Rollback == nil || len(st.Rollback.Ends) != 2 {
		t.Fatalf("want 2 per-end rollback states, got %+v", st.Rollback)
	}
	if !st.Rollback.Ends[0].Skipped {
		t.Error("a purged end must be SKIPPED (nothing can clean a device that no longer exists)")
	}
	if st.Rollback.Ends[1].CommandID == "" {
		t.Error("the live end must still be rolled back")
	}
	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)
	if data := pollDeploy(t, h, id); data["status"] != "rolled_back" {
		t.Fatalf("want rolled_back, got %v (note: %v)", data["status"], data["note"])
	}
}

func TestRollback_AllEndsSkipped_ReachesRolledBack(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	a := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	b := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", a.ID, b.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	if err := db.RetireDevice(a.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	if err := db.RetireDevice(b.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.Status != "rolled_back" {
		t.Fatalf("every end skipped → rolled_back, got %s", row.Status)
	}
	if row.DeployJSON != "" {
		t.Error("a clean rollback must clear the deploy record")
	}
	// Nothing may have been enqueued.
	cmds, _ := db.GetProbeCommands(probe.ID, 50)
	for _, cmd := range cmds {
		if cmd.Type == database.ProbeCommandTypeIPSecRemove {
			t.Error("no remove command may be enqueued when every end is skipped")
		}
	}
}

func TestRollback_LiveEndNoCollector_IsPerEndFailure(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	live := makeFortiDevice(t, db, probe.ID, "203.0.113.9") // gets its collector removed below
	other := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", live.ID, other.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})
	// Strip the collector from ONE live end: it is a real device that genuinely
	// cannot be cleaned — a per-end failure, not a reason to abandon the other.
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", live.ID).Update("probe_id", nil).Error; err != nil {
		t.Fatalf("strip collector: %v", err)
	}

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st := deployStateOf(t, db, id)
	if st.Rollback == nil || len(st.Rollback.Ends) != 2 {
		t.Fatalf("want 2 per-end rollback states, got %+v", st.Rollback)
	}
	if st.Rollback.Ends[0].Skipped {
		t.Error("a LIVE device without a collector is a failure, not a skip")
	}
	if st.Rollback.Ends[0].FailReason == "" {
		t.Error("the failed end must carry its reason")
	}
	if st.Rollback.Ends[1].CommandID == "" {
		t.Fatal("the other end must STILL be enqueued and cleaned")
	}
	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)
	data := pollDeploy(t, h, id)
	if data["status"] != "rollback_failed" {
		t.Fatalf("want rollback_failed (one end failed), got %v (note: %v)", data["status"], data["note"])
	}
}

// A live OPNsense end with NO captured UUIDs: its remove addresses the objects
// by the UUIDs the apply captured, so with none stored every step is skipped
// and the collector reports "applied: true" — a FALSE CLEAN. The rollback must
// land on rollback_failed with an explicit "verify manually" reason.
func TestRollback_OPNsenseEndEmptyCapturedUUIDs_ForcesRollbackFailed(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st := deployStateOf(t, db, id)
	if st.Rollback == nil || len(st.Rollback.Ends) != 2 {
		t.Fatalf("want 2 per-end rollback states, got %+v", st.Rollback)
	}
	// End B is the OPNsense end and it captured no UUIDs → unproven.
	if !st.Ends[1].RollbackUnproven {
		t.Error("a live OPNsense end with no captured UUIDs must be marked RollbackUnproven")
	}
	// Even a CLEAN report must not turn it into a clean rollback.
	completeRemove(t, db, probe.ID, st.Rollback.Ends[0].CommandID)
	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)
	data := pollDeploy(t, h, id)
	if data["status"] != "rollback_failed" {
		t.Fatalf("an unproven end must force rollback_failed, got %v (note: %v)", data["status"], data["note"])
	}
	note, _ := data["note"].(string)
	if note == "" {
		t.Error("the failure must carry a reason")
	}
}

func TestRollback_FromDeploying_IsAllowed(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	a := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	b := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", a.ID, b.ID, 1)
	deployAndSettle(t, h, db, id, "deploying")
	// The apply commands are dead (the FortiGate was decommissioned mid-deploy).
	st := deployStateOf(t, db, id)
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "failed", "collector unreachable"); err != nil {
			t.Fatalf("complete apply: %v", err)
		}
	}

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback from deploying = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRollback_Still409_WhenCommandLive(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	a := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	b := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", a.ID, b.ID, 1)
	// Deliberately NOT deployAndSettle: the apply commands stay in flight, so
	// the concurrency guard must refuse the rollback.
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d, want 200", code)
	}
	if err := db.UpdateIPSecTunnelStatus(id, "up", ""); err != nil {
		t.Fatalf("set tunnel status: %v", err)
	}
	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusConflict {
		t.Fatalf("rollback with a live command = %d, want 409; body: %s", rec.Code, rec.Body.String())
	}
}

// The captured UUIDs are merged in exactly ONE place — the deploy poll. A
// tunnel wedged in `deploying` (its peer was decommissioned mid-deploy, so
// nobody ever polls it) has NONE in its record, even though the collector
// captured them and the apply command's result still holds them.
//
// The rollback must recover them from there and clean the device for real —
// this is the difference between "roll it back yourself" and "roll it back".
func TestRollback_RecoversCapturedUUIDsFromTheApplyResult(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	// Deploy and park it in `deploying` WITHOUT polling it — the deploy record
	// therefore keeps no captured UUIDs.
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d, want 200", code)
	}
	if err := db.UpdateIPSecTunnelStatus(id, "deploying", ""); err != nil {
		t.Fatalf("set tunnel status: %v", err)
	}
	// The OPNsense end's apply COMPLETED on the device and the collector
	// captured the UUIDs; the FortiGate end failed. The report holds the
	// captures, the deploy record does not.
	const capturedConn = "11111111-2222-3333-4444-555555555555"
	st := deployStateOf(t, db, id)
	for _, e := range st.Ends {
		if e.Vendor == "opnsense" {
			if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "succeeded",
				`{"applied":true,"verified":true,"captured_uuids":{"conn":"`+capturedConn+`"}}`); err != nil {
				t.Fatalf("complete opnsense apply: %v", err)
			}
			continue
		}
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "failed", "peer unreachable"); err != nil {
			t.Fatalf("complete fortigate apply: %v", err)
		}
	}
	if got := len(deployStateOf(t, db, id).Ends[1].CapturedUUIDs); got != 0 {
		t.Fatalf("the fixture must start with NO captured UUIDs (the poll never ran), got %d", got)
	}

	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st2 := deployStateOf(t, db, id)
	if len(st2.Ends[1].CapturedUUIDs) == 0 {
		t.Fatal("the rollback must recover the captured UUIDs from the apply command's result")
	}
	if st2.Ends[1].CapturedUUIDs["conn"] != capturedConn {
		t.Errorf("recovered conn uuid = %q, want %q", st2.Ends[1].CapturedUUIDs["conn"], capturedConn)
	}
	if st2.Ends[1].RollbackUnproven {
		t.Error("a RECOVERED end is proven — it must not be marked unproven")
	}
	// The remove command must carry the recovered UUID as its substitution:
	// without it the collector skips every delete and reports a false clean.
	cmd, _ := db.GetProbeCommandByCommandID(st2.Rollback.Ends[1].CommandID)
	if cmd == nil {
		t.Fatal("no remove command was enqueued for the OPNsense end")
	}
	if !strings.Contains(cmd.Payload, capturedConn) {
		t.Errorf("the remove command must carry the recovered UUID as its substitution: %s", cmd.Payload)
	}
	// And the rollback settles cleanly.
	completeRemove(t, db, probe.ID, st2.Rollback.Ends[0].CommandID)
	completeRemove(t, db, probe.ID, st2.Rollback.Ends[1].CommandID)
	if data := pollDeploy(t, h, id); data["status"] != "rolled_back" {
		t.Fatalf("want rolled_back, got %v (note: %v)", data["status"], data["note"])
	}
}

// The captured UUIDs live in the apply command's result, and terminal command
// rows are pruned after 30 days — the deploy record is never pruned. So the
// reconciler banks them as soon as they exist: that is what makes a rollback
// possible years later instead of "the result is gone, clean it by hand".
func TestReconciler_BanksCapturedUUIDsIntoTheDeployRecord(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d, want 200", code)
	}
	if err := db.UpdateIPSecTunnelStatus(id, "deploying", ""); err != nil {
		t.Fatalf("set tunnel status: %v", err)
	}
	const capturedConn = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	st := deployStateOf(t, db, id)
	for _, e := range st.Ends {
		if e.Vendor == "opnsense" {
			if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "succeeded",
				`{"applied":true,"verified":true,"captured_uuids":{"conn":"`+capturedConn+`"}}`); err != nil {
				t.Fatalf("complete opnsense apply: %v", err)
			}
			continue
		}
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "failed", "peer unreachable"); err != nil {
			t.Fatalf("complete fortigate apply: %v", err)
		}
	}

	database.NewIPSecRollbackWorker(db).Tick(context.Background())

	st2 := deployStateOf(t, db, id)
	if len(st2.Ends[1].CapturedUUIDs) == 0 {
		t.Fatal("the reconciler must bank the apply's captured UUIDs into the deploy record")
	}
	if st2.Ends[1].CapturedUUIDs["conn"] != capturedConn {
		t.Errorf("banked conn uuid = %q, want %q", st2.Ends[1].CapturedUUIDs["conn"], capturedConn)
	}
	// Banking is bookkeeping, NOT a saga transition: the status must not move.
	row, _ := db.GetIPSecTunnel(id)
	if row.Status != "deploying" {
		t.Errorf("banking must not move the tunnel's status, got %s", row.Status)
	}
}

// A deploy record written BEFORE the per-end rollback format carries only the
// index-aligned CommandIDs. It must still resolve — and it must resolve to a
// CLEAN rollback when its commands are real and clean, which is the actual
// backward-compatibility guarantee. (A legacy record whose commands are lost
// must fail honestly; that is the second half of this test.)
func TestRollback_LegacyRecordWithoutEnds_StillPolls(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	a := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	b := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", a.ID, b.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})

	// Start a rollback so REAL remove commands exist.
	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st := deployStateOf(t, db, id)
	if st.Rollback == nil || len(st.Rollback.Ends) != 2 {
		t.Fatalf("want 2 per-end rollback states, got %+v", st.Rollback)
	}
	legacyIDs := []string{st.Rollback.Ends[0].CommandID, st.Rollback.Ends[1].CommandID}

	// Rewrite the deploy record in the LEGACY shape: Rollback.CommandIDs only,
	// no Ends — exactly what a pre-change server wrote.
	legacy := ipsec.DeployState{DeployedAt: st.DeployedAt, Ends: st.Ends}
	legacy.Rollback = &ipsec.RollbackState{CommandIDs: legacyIDs}
	blob, err := json.Marshal(&legacy)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := db.Gorm().Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Update("deploy_json", string(blob)).Error; err != nil {
		t.Fatalf("write legacy record: %v", err)
	}

	// The legacy commands resolve cleanly → the legacy fallback must produce a
	// CLEAN rollback. A broken fallback (cid empty) would land on
	// rollback_failed, so this distinguishes the two.
	completeRemove(t, db, probe.ID, legacyIDs[0])
	completeRemove(t, db, probe.ID, legacyIDs[1])
	data := pollDeploy(t, h, id)
	if data["status"] != "rolled_back" {
		t.Fatalf("a legacy record with clean commands must roll back cleanly, got %v (note: %v)", data["status"], data["note"])
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.DeployJSON != "" {
		t.Error("a clean rollback must clear the deploy record")
	}
}

// A legacy record whose rollback commands are GONE (pruned) must fail
// honestly — never a silent clean.
func TestRollback_LegacyRecordWithLostCommands_FailsHonestly(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	a := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	b := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", a.ID, b.ID, 1)
	deployAndSettle(t, h, db, id, "up")

	st := deployStateOf(t, db, id)
	legacy := ipsec.DeployState{DeployedAt: st.DeployedAt, Ends: st.Ends}
	legacy.Rollback = &ipsec.RollbackState{CommandIDs: []string{"legacy-cmd-1", "legacy-cmd-2"}}
	blob, err := json.Marshal(&legacy)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := db.Gorm().Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Update("deploy_json", string(blob)).Error; err != nil {
		t.Fatalf("write legacy record: %v", err)
	}
	if err := db.UpdateIPSecTunnelStatus(id, "rolling_back", "operator-initiated rollback"); err != nil {
		t.Fatalf("set status: %v", err)
	}

	// The legacy command ids do not exist → the terminal is "result lost" →
	// rollback_failed (never a false clean).
	data := pollDeploy(t, h, id)
	if data["status"] != "rollback_failed" {
		t.Fatalf("a legacy record with lost commands must fail, got %v", data["status"])
	}
}

// --- bulk orphaned rollback -------------------------------------------------

// bulkRollback drives the bulk orphaned-rollback endpoint and returns the
// per-tunnel report.
func bulkRollback(t *testing.T, h *Handler) []map[string]any {
	t.Helper()
	c, rec := jsonReq(http.MethodPost, "/x", "")
	h.RollbackOrphanedIPSecTunnels(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Tunnels []map[string]any `json:"tunnels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode bulk report: %v (%s)", err, rec.Body.String())
	}
	return resp.Data.Tunnels
}

func TestBulkRollbackOrphaned_ReportsPerTunnel(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	orphan := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	orphanID := createTunnelRow(t, db, "fortigate", "opnsense", orphan.ID, live.ID, 1)
	deployAndSettle(t, h, db, orphanID, "up")
	captureUUIDs(t, db, orphanID, 1, map[string]string{"conn": "uuid-conn"})
	if err := db.RetireDevice(orphan.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	// A tunnel with a healthy peer must NOT be touched.
	okA := makeFortiDevice(t, db, probe.ID, "203.0.113.20")
	okB := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.20")
	healthyID := createTunnelRow(t, db, "fortigate", "opnsense", okA.ID, okB.ID, 1)
	deployAndSettle(t, h, db, healthyID, "up")

	report := bulkRollback(t, h)
	if len(report) != 1 {
		t.Fatalf("want exactly 1 orphan in the report, got %d: %+v", len(report), report)
	}
	entry := report[0]
	if got, _ := entry["tunnel_id"].(float64); uint(got) != orphanID {
		t.Errorf("report names tunnel %v, want %d", entry["tunnel_id"], orphanID)
	}
	if entry["action"] != "rolling_back" {
		t.Errorf("action = %v, want rolling_back", entry["action"])
	}
	skipped, _ := entry["skipped_ends"].([]any)
	if len(skipped) != 1 {
		t.Errorf("want 1 skipped end in the report, got %v", entry["skipped_ends"])
	}
	// The healthy tunnel must be untouched.
	row, _ := db.GetIPSecTunnel(healthyID)
	if row.Status != "up" {
		t.Errorf("a tunnel with a healthy peer must not be rolled back, got %s", row.Status)
	}
}

// A tunnel with NO deploy record cannot be rolled back by the server (the
// removal snapshot is gone). It must be REPORTED, not silently omitted.
func TestBulkRollbackOrphaned_ReportsNeedsManualCleanup(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	gone := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", gone.ID, live.ID, 1)
	if err := db.RetireDevice(gone.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	// A draft tunnel with no deploy record: nothing was ever deployed.

	report := bulkRollback(t, h)
	if len(report) != 1 {
		t.Fatalf("want the orphan reported, got %d entries: %+v", len(report), report)
	}
	if report[0]["action"] != "needs_manual_cleanup" {
		t.Errorf("action = %v, want needs_manual_cleanup", report[0]["action"])
	}
	if report[0]["error"] == "" {
		t.Error("a manual-cleanup entry must explain itself")
	}
	_ = id
}

// A cleanly rolled-back tunnel has NO deploy record (the rollback cleared it),
// so it must NOT be reported as needing manual cleanup — the live end is clean.
func TestBulkRollbackOrphaned_ReportsCleanlyRolledBackAsClean(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	gone := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", gone.ID, live.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})
	if err := db.RetireDevice(gone.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200", rec.Code)
	}
	st := deployStateOf(t, db, id)
	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)
	if data := pollDeploy(t, h, id); data["status"] != "rolled_back" {
		t.Fatalf("want rolled_back, got %v", data["status"])
	}

	report := bulkRollback(t, h)
	if len(report) != 1 {
		t.Fatalf("want the orphan reported, got %d entries: %+v", len(report), report)
	}
	if report[0]["action"] != "already_clean" {
		t.Errorf("action = %v, want already_clean (a cleanly rolled-back tunnel needs no manual cleanup)", report[0]["action"])
	}
}

// A tunnel left mid-rollback could never be re-driven (the rollback's
// fromStatuses exclude rolling_back) and it blocked the retired device's
// purge. The bulk endpoint must advance it.
func TestBulkRollbackOrphaned_ResolvesRollingBackOrphan(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	gone := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", gone.ID, live.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})
	if err := db.RetireDevice(gone.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	// Start a rollback, then park it mid-flight.
	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200", rec.Code)
	}
	st := deployStateOf(t, db, id)
	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)

	report := bulkRollback(t, h)
	if len(report) != 1 {
		t.Fatalf("want the orphan reported, got %d entries: %+v", len(report), report)
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.Status != "rolled_back" {
		t.Errorf("an already-rolling_back orphan must be advanced to a terminal, got %s", row.Status)
	}
}

// The terminal used to be advanced ONLY by the UI poll. The shared
// ResolveIPSecRollback must reach it with no HTTP request involved.
func TestResolveIPSecRollback_WorksWithoutUIPoll(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	gone := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", gone.ID, live.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	captureUUIDs(t, db, id, 1, map[string]string{"conn": "uuid-conn"})
	if err := db.RetireDevice(gone.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	rec := rollbackReq(t, h, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200", rec.Code)
	}
	st := deployStateOf(t, db, id)
	completeRemove(t, db, probe.ID, st.Rollback.Ends[1].CommandID)

	status, reason, done, err := db.ResolveIPSecRollback(id)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !done {
		t.Fatal("the rollback must be resolved")
	}
	if status != "rolled_back" {
		t.Fatalf("status = %s, want rolled_back (reason: %s)", status, reason)
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.DeployJSON != "" {
		t.Error("a clean rollback must clear the deploy record")
	}
}
