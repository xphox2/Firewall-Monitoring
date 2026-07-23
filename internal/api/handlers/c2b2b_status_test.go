package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"

	"github.com/gin-gonic/gin"
)

// c2b2bPoll is the full poll response shape the SA-liveness tests need.
type c2b2bPollResp struct {
	Data struct {
		Status    string `json:"status"`
		Note      string `json:"note"`
		SAPending bool   `json:"sa_pending"`
	} `json:"data"`
}

func c2b2bPoll(t *testing.T, h *Handler, id uint) c2b2bPollResp {
	t.Helper()
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDeployResult(c)
	var resp c2b2bPollResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("poll %d decode: %v (%s)", id, err, rec.Body.String())
	}
	return resp
}

// c2b2bToDegraded deploys a FG⇄FG tunnel, completes both apply commands as
// applied+verified, and polls once — landing the tunnel at degraded with the
// SA-liveness probes enqueued (C2b-2b). Returns the deploy state.
func c2b2bToDegraded(t *testing.T, h *Handler, db *database.Database, probeID uint) (uint, ipsec.DeployState) {
	t.Helper()
	devA := makeFortiDevice(t, db, probeID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probeID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	row, _ := db.GetIPSecTunnel(id)
	var st ipsec.DeployState
	if err := json.Unmarshal([]byte(row.DeployJSON), &st); err != nil {
		t.Fatalf("deploy state: %v", err)
	}
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probeID, e.CommandID, "succeeded", `{"applied":true,"verified":true}`); err != nil {
			t.Fatalf("complete apply: %v", err)
		}
	}
	if resp := c2b2bPoll(t, h, id); resp.Data.Status != "degraded" {
		t.Fatalf("post-apply status = %q, want degraded", resp.Data.Status)
	}
	return id, st
}

// c2b2bStatusState re-reads the deploy state (which gains StatusCommandIDs on
// the degraded transition).
func c2b2bStatusState(t *testing.T, db *database.Database, id uint) ipsec.DeployState {
	t.Helper()
	row, _ := db.GetIPSecTunnel(id)
	var st ipsec.DeployState
	if err := json.Unmarshal([]byte(row.DeployJSON), &st); err != nil {
		t.Fatalf("deploy state: %v", err)
	}
	return st
}

// TestDeployPoll_EnqueuesStatusChecks proves the all-good terminal enqueues one
// ipsec_status probe per end IN THE SAME transition, and flags them in flight.
func TestDeployPoll_EnqueuesStatusChecks(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	id, _ := c2b2bToDegraded(t, h, db, probe.ID)

	st := c2b2bStatusState(t, db, id)
	if len(st.Ends) != 2 {
		t.Fatalf("want 2 ends, got %d", len(st.Ends))
	}
	for _, e := range st.Ends {
		if e.StatusCommandID == "" {
			t.Fatalf("end %d has no StatusCommandID after the all-good terminal", e.End)
		}
		cmd, _ := db.GetProbeCommandByCommandID(e.StatusCommandID)
		if cmd == nil || cmd.Type != database.ProbeCommandTypeIPSecStatus {
			t.Errorf("end %d status command missing/wrong type: %+v", e.End, cmd)
		}
	}
}

// TestDeployPoll_SAUp_TransitionsUp drives the full arc: deploy → degraded →
// both SA probes report the tunnel up → up.
func TestDeployPoll_SAUp_TransitionsUp(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	id, _ := c2b2bToDegraded(t, h, db, probe.ID)
	name := fmt.Sprintf("fwm-t%d", id)

	doc := fmt.Sprintf(`{"vendor":"fortigate","steps":[{"path":"/x","status":200,"body":%q}]}`,
		fmt.Sprintf(`{"results":[{"name":"%s","connection-phase":"up","proxyid":[{"status":"up"}]}]}`, name))
	st := c2b2bStatusState(t, db, id)
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.StatusCommandID, "succeeded", doc); err != nil {
			t.Fatalf("complete status: %v", err)
		}
	}
	resp := c2b2bPoll(t, h, id)
	if resp.Data.Status != "up" {
		t.Fatalf("status = %q, want up (note %q)", resp.Data.Status, resp.Data.Note)
	}
	// up must KEEP the deploy record (rollback stays available).
	if row, _ := db.GetIPSecTunnel(id); row.DeployJSON == "" {
		t.Error("up must keep the deploy record")
	}
}

// TestDeployPoll_SADown_TransitionsDown: our tunnel is absent from the monitor
// document → definitively not established → down, with the reason persisted.
func TestDeployPoll_SADown_TransitionsDown(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	id, _ := c2b2bToDegraded(t, h, db, probe.ID)

	doc := `{"vendor":"fortigate","steps":[{"path":"/x","status":200,"body":"{\"results\":[{\"name\":\"other\",\"connection-phase\":\"up\",\"proxyid\":[{\"status\":\"up\"}]}]}"}]}`
	st := c2b2bStatusState(t, db, id)
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.StatusCommandID, "succeeded", doc); err != nil {
			t.Fatalf("complete status: %v", err)
		}
	}
	resp := c2b2bPoll(t, h, id)
	if resp.Data.Status != "down" {
		t.Fatalf("status = %q, want down", resp.Data.Status)
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.LastError == "" {
		t.Error("down must persist its reason in last_error")
	}
	// Rollback must be offered from down (server-side gate).
	cr, recR := jsonReq(http.MethodPost, "/x", "")
	cr.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.RollbackIPSecTunnel(cr)
	if recR.Code != http.StatusOK {
		t.Errorf("rollback from down = %d, want 200", recR.Code)
	}
}

// TestDeployPoll_SAInconclusive_StaysDegraded: the collector doesn't know
// ipsec_status (old version) → failed command → inconclusive → NEVER a guessed
// up/down; the tunnel stays degraded (today's pre-C2b-2b behavior).
func TestDeployPoll_SAInconclusive_StaysDegraded(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	id, _ := c2b2bToDegraded(t, h, db, probe.ID)

	st := c2b2bStatusState(t, db, id)
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.StatusCommandID, "failed", `unknown command type "ipsec_status"`); err != nil {
			t.Fatalf("complete status: %v", err)
		}
	}
	resp := c2b2bPoll(t, h, id)
	if resp.Data.Status != "degraded" {
		t.Fatalf("status = %q, want degraded (inconclusive must not guess)", resp.Data.Status)
	}
	if resp.Data.SAPending {
		t.Error("sa_pending must be false once every probe is terminal")
	}
	if resp.Data.Note == "" {
		t.Error("an inconclusive terminal must carry a note")
	}
}

// TestDeployPoll_SAPending_KeepsPolling: unreported probes keep the tunnel
// degraded with sa_pending so the modal keeps polling.
func TestDeployPoll_SAPending_KeepsPolling(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	id, _ := c2b2bToDegraded(t, h, db, probe.ID)

	resp := c2b2bPoll(t, h, id)
	if resp.Data.Status != "degraded" || !resp.Data.SAPending {
		t.Fatalf("pending probes: status=%q sa_pending=%v, want degraded+true", resp.Data.Status, resp.Data.SAPending)
	}
}

// TestDeployPoll_SATransitionIsOneShot: once up, re-polls don't regress or
// re-transition (the eval branch is degraded-guarded).
func TestDeployPoll_SATransitionIsOneShot(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	id, _ := c2b2bToDegraded(t, h, db, probe.ID)
	name := fmt.Sprintf("fwm-t%d", id)
	doc := fmt.Sprintf(`{"vendor":"fortigate","steps":[{"path":"/x","status":200,"body":%q}]}`,
		fmt.Sprintf(`{"results":[{"name":"%s","connection-phase":"up","proxyid":[{"status":"up"}]}]}`, name))
	st := c2b2bStatusState(t, db, id)
	for _, e := range st.Ends {
		_, _, _ = db.CompleteProbeCommand(probe.ID, e.StatusCommandID, "succeeded", doc)
	}
	if resp := c2b2bPoll(t, h, id); resp.Data.Status != "up" {
		t.Fatalf("status = %q, want up", resp.Data.Status)
	}
	// A second poll must stay up (no regression, no error).
	if resp := c2b2bPoll(t, h, id); resp.Data.Status != "up" {
		t.Fatalf("re-poll regressed to %q — up must be stable", resp.Data.Status)
	}
}
