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

// makeFortiDevice seeds a FortiGate device with a collector + API token so a
// deploy can enqueue against it.
func makeFortiDevice(t *testing.T, db *database.Database, probeID uint, ip string) *models.Device {
	t.Helper()
	dev := &models.Device{Name: "fg-" + ip, IPAddress: ip, Vendor: "fortigate", ProbeID: &probeID, APIToken: "tok", APIPort: 4433}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	return dev
}

// createTunnelRow persists a tunnel intent directly (both ends' vendors given),
// returning the row ID. nSubnetsA lets a test force a too-many-subnets block.
func createTunnelRow(t *testing.T, db *database.Database, vA, vB string, devA, devB uint, nSubnetsA int) uint {
	t.Helper()
	subs := []string{}
	for i := 0; i < nSubnetsA; i++ {
		subs = append(subs, "10."+strconv.Itoa(i)+".0.0/24")
	}
	m, _ := ipsec.PresetByName(ipsec.ProfileModern)
	// OPNsense supports policy-based only; FortiGate⇄FortiGate can be route-based.
	mode := ipsec.ModeRouteBased
	if vA == "opnsense" || vB == "opnsense" {
		mode = ipsec.ModePolicyBased
	}
	in := &ipsec.TunnelIntent{
		Enabled: true, IKEVersion: m.IKEVersion, Mode: mode,
		IKE: m.IKE, ESP: m.ESP, IKELifetimeSecs: m.IKELifetimeSecs, DPD: ipsec.DPD{DelaySecs: 30},
		PSK: "abcDEF012345678901234567890XYZ",
		Ends: [2]ipsec.EndpointSpec{
			{DeviceID: devA, Vendor: vA, PeerIP: "203.0.113.1", EgressIface: "port1", LANIface: "port3",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "a"}, ProtectedSubnets: subs, MSSClamp: 1350},
			{DeviceID: devB, Vendor: vB, PeerIP: "198.51.100.1", EgressIface: "wan", LANIface: "lan",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "b"}, ProtectedSubnets: []string{"192.168.50.0/24"}, MSSClamp: 1350},
		},
	}
	row, err := database.IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	row.Name = "fwm-new-tmp-" + vA + vB + strconv.Itoa(nSubnetsA)
	if err := db.CreateIPSecTunnel(row); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	in.ID = row.ID
	hydrateDerived(in)
	row2, _ := database.IPSecIntentToModel(in)
	row2.ID = row.ID
	row2.Name = in.Name
	row2.Status = "draft"
	if err := db.UpdateIPSecTunnel(row2); err != nil {
		t.Fatalf("finalize tunnel: %v", err)
	}
	return row.ID
}

func deployReq(t *testing.T, h *Handler, id uint) (*gin.Context, int) {
	t.Helper()
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.DeployIPSecTunnel(c)
	return c, rec.Code
}

func TestDeploy_NoDeployableEnd_400(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	// Both ends OPNsense → no FortiGate end → C2b-1 has nothing to deploy.
	id := createTunnelRow(t, db, "opnsense", "opnsense", 0, 0, 1)
	_ = probe
	if _, code := deployReq(t, h, id); code != http.StatusBadRequest {
		t.Fatalf("deploy with no FortiGate end = %d, want 400", code)
	}
}

func TestDeploy_HasBlock_409_NoEnqueue(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	// 60 protected subnets on end A → too_many_subnets BLOCK.
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 60)
	if _, code := deployReq(t, h, id); code != http.StatusConflict {
		t.Fatalf("deploy with a blocking finding = %d, want 409", code)
	}
	// No apply command should have been enqueued.
	cmds, _ := db.GetProbeCommands(probe.ID, 50)
	for _, cmd := range cmds {
		if cmd.Type == database.ProbeCommandTypeIPSecApply {
			t.Fatalf("no apply_ipsec should be enqueued on a blocked deploy")
		}
	}
}

func TestDeploy_Enqueues_Persists_ThenConcurrent409(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)

	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("first deploy = %d, want 200", code)
	}
	row, _ := db.GetIPSecTunnel(id)
	if row.Status != "deploying" {
		t.Errorf("status = %q, want deploying", row.Status)
	}
	if row.DeployJSON == "" {
		t.Fatal("DeployJSON must be persisted")
	}
	var st ipsec.DeployState
	if err := json.Unmarshal([]byte(row.DeployJSON), &st); err != nil {
		t.Fatalf("deploy state: %v", err)
	}
	if len(st.Ends) != 2 {
		t.Fatalf("want 2 deployable FortiGate ends, got %d", len(st.Ends))
	}
	for _, e := range st.Ends {
		if e.CommandID == "" || len(e.RemoveSteps) == 0 || e.RemoveChecksum == "" {
			t.Errorf("end %d incomplete deploy record: %+v", e.End, e)
		}
		cmd, _ := db.GetProbeCommandByCommandID(e.CommandID)
		if cmd == nil || cmd.Type != database.ProbeCommandTypeIPSecApply {
			t.Errorf("end %d apply command not enqueued", e.End)
		}
	}

	// A concurrent second deploy while status=deploying → 409 (optimistic lock).
	if _, code := deployReq(t, h, id); code != http.StatusConflict {
		t.Fatalf("second deploy while deploying = %d, want 409", code)
	}
}

func TestDeploy_EditDeleteGuarded_WhileDeploying(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d, want 200", code)
	}

	// Edit → 409.
	ce, recE := jsonReq(http.MethodPut, "/x", ipsecCreateBody())
	ce.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.UpdateIPSecTunnel(ce)
	if recE.Code != http.StatusConflict {
		t.Errorf("edit while deploying = %d, want 409", recE.Code)
	}
	// Delete → 409.
	cd, recD := jsonReq(http.MethodDelete, "/x", "")
	cd.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.DeleteIPSecTunnel(cd)
	if recD.Code != http.StatusConflict {
		t.Errorf("delete while deploying = %d, want 409", recD.Code)
	}
}

// TestDeployStatusPoll_SuccessAndTunnelScoped proves the poll reads each tunnel's
// OWN command IDs (not device+type): two tunnels share the same devices; tunnel1's
// commands report success and tunnel2's report failure, and the poll drives each
// to the correct terminal status without cross-contamination.
func TestDeployStatusPoll_SuccessAndTunnelScoped(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	t1 := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	t2 := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)

	if _, code := deployReq(t, h, t1); code != http.StatusOK {
		t.Fatalf("deploy t1 = %d", code)
	}
	if _, code := deployReq(t, h, t2); code != http.StatusOK {
		t.Fatalf("deploy t2 = %d", code)
	}

	complete := func(id uint, report string) {
		row, _ := db.GetIPSecTunnel(id)
		var st ipsec.DeployState
		_ = json.Unmarshal([]byte(row.DeployJSON), &st)
		for _, e := range st.Ends {
			if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "succeeded", report); err != nil {
				t.Fatalf("complete %s: %v", e.CommandID, err)
			}
		}
	}
	complete(t1, `{"applied":true,"verified":true}`)
	complete(t2, `{"applied":false,"aborted":true,"error":"boom"}`)

	poll := func(id uint) string {
		c, rec := jsonReq(http.MethodGet, "/x", "")
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
		h.GetIPSecDeployResult(c)
		var resp struct {
			Data struct {
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("poll %d decode: %v (%s)", id, err, rec.Body.String())
		}
		return resp.Data.Status
	}
	if s := poll(t1); s != "degraded" {
		t.Errorf("t1 status = %q, want degraded (applied+verified)", s)
	}
	if s := poll(t2); s != "error" {
		t.Errorf("t2 status = %q, want error (aborted report)", s)
	}
	// t1's last_deployed_at must be stamped on success.
	if row, _ := db.GetIPSecTunnel(t1); row.LastDeployedAt == nil {
		t.Error("t1 last_deployed_at must be set on a successful deploy")
	}
}

// TestEditDelete_BlockedByDeployRecord_EvenInErrorState guards against the
// edit-laundering hole: a partially-deployed tunnel sits in `error` WITH a deploy
// record; edit/delete must be refused (else editing resets it to draft, blocks
// rollback, and permits deleting the only remove snapshot → orphaned objects),
// while rollback stays available.
func TestEditDelete_BlockedByDeployRecord_EvenInErrorState(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	// Simulate a mid-write failure: the apply commands complete as failed
	// (terminal, so the live-command guard clears) and status→error, but the
	// deploy record is KEPT.
	row, _ := db.GetIPSecTunnel(id)
	if row.DeployJSON == "" {
		t.Fatal("precondition: error state must retain the deploy record")
	}
	var st ipsec.DeployState
	_ = json.Unmarshal([]byte(row.DeployJSON), &st)
	for _, e := range st.Ends {
		if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "failed", "boom"); err != nil {
			t.Fatalf("complete: %v", err)
		}
	}
	if err := db.UpdateIPSecTunnelStatus(id, "error", "write failed mid-sequence"); err != nil {
		t.Fatalf("set error: %v", err)
	}

	// Edit → 409 (must NOT launder to draft).
	ce, recE := jsonReq(http.MethodPut, "/x", ipsecCreateBody())
	ce.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.UpdateIPSecTunnel(ce)
	if recE.Code != http.StatusConflict {
		t.Errorf("edit of error-with-deploy-record = %d, want 409", recE.Code)
	}
	// Delete → 409.
	cd, recD := jsonReq(http.MethodDelete, "/x", "")
	cd.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.DeleteIPSecTunnel(cd)
	if recD.Code != http.StatusConflict {
		t.Errorf("delete of error-with-deploy-record = %d, want 409", recD.Code)
	}
	// Rollback → allowed (not 400/409) — the operator's real path out.
	cr, recR := jsonReq(http.MethodPost, "/x", "")
	cr.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.RollbackIPSecTunnel(cr)
	if recR.Code != http.StatusOK {
		t.Errorf("rollback of error-with-deploy-record = %d, want 200", recR.Code)
	}
}

func TestRollback_NothingDeployed_400(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.RollbackIPSecTunnel(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rollback with no deploy record = %d, want 400", rec.Code)
	}
}

func TestRecheck_NothingDeployed_400(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.RecheckIPSecTunnel(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("recheck with no deploy record = %d, want 400", rec.Code)
	}
}

// TestRecheck_DownRecoversToUp is the recovery loop for the fwm-t9 class of bug:
// the one-shot post-deploy check misread a tunnel that hadn't come up yet (or was
// misparsed) → terminal `down`. A recheck re-enqueues the read-only SA probes,
// returns the tunnel to degraded, and the fresh device state drives it to `up`.
func TestRecheck_DownRecoversToUp(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	row, _ := db.GetIPSecTunnel(id)
	tunnelName := row.Name

	// A FortiOS monitor document wrapped in the collector's status-report envelope.
	mkReport := func(monitor string) string {
		b, _ := json.Marshal(monitor)
		return `{"vendor":"fortigate","steps":[{"path":"/api/v2/monitor/vpn/ipsec","status":200,"body":` + string(b) + `}]}`
	}
	upDoc := mkReport(`{"results":[{"name":"` + tunnelName + `","connection-phase":"up","proxyid":[{"status":"up"}]}]}`)
	downDoc := mkReport(`{"results":[{"name":"other","proxyid":[]}]}`) // our tunnel absent → down

	completeApply := func() {
		r, _ := db.GetIPSecTunnel(id)
		var st ipsec.DeployState
		_ = json.Unmarshal([]byte(r.DeployJSON), &st)
		for _, e := range st.Ends {
			if _, _, err := db.CompleteProbeCommand(probe.ID, e.CommandID, "succeeded", `{"applied":true,"verified":true}`); err != nil {
				t.Fatalf("complete apply: %v", err)
			}
		}
	}
	completeStatus := func(report string) {
		r, _ := db.GetIPSecTunnel(id)
		var st ipsec.DeployState
		_ = json.Unmarshal([]byte(r.DeployJSON), &st)
		n := 0
		for _, e := range st.Ends {
			if e.StatusCommandID == "" {
				continue
			}
			if _, _, err := db.CompleteProbeCommand(probe.ID, e.StatusCommandID, "succeeded", report); err != nil {
				t.Fatalf("complete status: %v", err)
			}
			n++
		}
		if n == 0 {
			t.Fatal("no status probes were enqueued to complete")
		}
	}
	poll := func() string {
		c, rec := jsonReq(http.MethodGet, "/x", "")
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
		h.GetIPSecDeployResult(c)
		var resp struct {
			Data struct {
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("poll decode: %v (%s)", err, rec.Body.String())
		}
		return resp.Data.Status
	}
	recheck := func() int {
		c, rec := jsonReq(http.MethodPost, "/x", "")
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
		h.RecheckIPSecTunnel(c)
		return rec.Code
	}

	// Deploy applies + verifies → degraded, SA probes enqueued.
	completeApply()
	if s := poll(); s != "degraded" {
		t.Fatalf("post-apply status = %q, want degraded", s)
	}
	// First liveness read misfires (tunnel not present yet) → terminal down.
	completeStatus(downDoc)
	if s := poll(); s != "down" {
		t.Fatalf("status after down probe = %q, want down", s)
	}
	// The one-shot eval is terminal: a further poll must NOT re-evaluate.
	if s := poll(); s != "down" {
		t.Fatalf("re-poll of terminal down = %q, want down (no re-eval)", s)
	}

	// Recheck → back to degraded with fresh probes.
	if code := recheck(); code != http.StatusOK {
		t.Fatalf("recheck = %d, want 200", code)
	}
	if r, _ := db.GetIPSecTunnel(id); r.Status != "degraded" {
		t.Fatalf("post-recheck status = %q, want degraded", r.Status)
	}
	// This time the device reports the tunnel up → up.
	completeStatus(upDoc)
	if s := poll(); s != "up" {
		t.Fatalf("status after recheck up probe = %q, want up", s)
	}
}

// TestRecheck_WhileDeploying_409: a recheck must be refused while an apply is in
// flight (the tunnel isn't in a settled state).
func TestRecheck_WhileDeploying_409(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	id := createTunnelRow(t, db, "fortigate", "fortigate", devA.ID, devB.ID, 1)
	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d", code)
	}
	// Status is 'deploying' with apply commands pending — recheck must 409.
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.RecheckIPSecTunnel(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("recheck while deploying = %d, want 409", rec.Code)
	}
}
