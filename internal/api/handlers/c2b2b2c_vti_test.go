package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/ipsec/conformance"
)

// TestDeploy_PolicyBased_FortiGateVTIAddressed is the fwm-t4 regression pin:
// a policy-based FG⇄OPN tunnel built through the REAL app path (persist →
// hydrateDerived → deploy → render) must ship a system/interface step with a
// VALID "ip"/"remote-ip" pair — never the empty "ip": " 255.255.255.255" the
// device rejected with HTTP 500 — and net-device=enable so the VTI exists.
func TestDeploy_PolicyBased_FortiGateVTIAddressed(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	devA := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	devB := makeFortiDevice(t, db, probe.ID, "203.0.113.10")
	// FG⇄OPN forces policy-based (createTunnelRow) — the fwm-t4 shape.
	id := createTunnelRow(t, db, "fortigate", "opnsense", devA.ID, devB.ID, 1)

	if _, code := deployReq(t, h, id); code != http.StatusOK {
		t.Fatalf("deploy = %d, want 200", code)
	}
	row, _ := db.GetIPSecTunnel(id)
	var st ipsec.DeployState
	if err := json.Unmarshal([]byte(row.DeployJSON), &st); err != nil {
		t.Fatalf("deploy state: %v", err)
	}
	if len(st.Ends) != 2 {
		t.Fatalf("want 2 deployable ends, got %d", len(st.Ends))
	}

	// End A (fortigate): decode the apply payload and inspect the write bodies.
	cmd, _ := db.GetProbeCommandByCommandID(st.Ends[0].CommandID)
	if cmd == nil {
		t.Fatal("end A apply command not enqueued")
	}
	var payload ipsecApplyPayload
	if err := json.Unmarshal([]byte(cmd.Payload), &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}

	var ifaceBody, phase1Body string
	for _, s := range payload.Steps {
		if strings.Contains(s.Path, "system/interface") {
			ifaceBody = s.Body
		}
		if strings.Contains(s.Path, "phase1-interface") {
			phase1Body = s.Body
		}
	}
	if ifaceBody == "" {
		t.Fatal("no system/interface step shipped (FG keeps the VTI in both modes)")
	}
	if strings.Contains(ifaceBody, `"ip":" `) || strings.Contains(ifaceBody, `"ip":""`) {
		t.Errorf("fwm-t4 regression: interface step ships an EMPTY ip: %s", ifaceBody)
	}
	if !strings.Contains(ifaceBody, `"ip":"169.254.`) {
		t.Errorf("interface step must carry the allocated VTI address: %s", ifaceBody)
	}
	if !strings.Contains(ifaceBody, `"remote-ip":"169.254.`) {
		t.Errorf("interface step must carry the remote VTI address: %s", ifaceBody)
	}
	if !strings.Contains(phase1Body, `"net-device":"enable"`) {
		t.Errorf("phase1 must set net-device=enable (VTI kernel device): %s", phase1Body)
	}

	// The pre-dispatch conformance guard must ALSO accept this render (the new
	// ip_mask rules validate the pair form — a regression here would 400).
	if findings := conformance.Validate("fortigate", payload.Steps); len(findings) > 0 {
		t.Errorf("deploy render must pass conformance with the ip_mask rules: %v", findings)
	}
}
