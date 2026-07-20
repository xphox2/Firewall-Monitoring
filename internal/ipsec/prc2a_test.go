package ipsec_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// bodies concatenates every step's Method+Path+Body for substring assertions.
func stepsText(a ipsec.Artifact) string {
	var b strings.Builder
	for _, s := range a.Steps {
		b.WriteString(s.Method + " " + s.Path + " " + s.Body + "\n")
	}
	return b.String()
}

func render(t *testing.T, vendor string, self int, in *ipsec.TunnelIntent) ipsec.Artifact {
	t.Helper()
	d, ok := ipsec.Driver(vendor)
	if !ok {
		t.Fatalf("driver %s not registered", vendor)
	}
	art, err := d.Render(ipsec.ViewFor(in, self))
	if err != nil {
		t.Fatalf("%s render: %v", vendor, err)
	}
	return art
}

func renderRemove(t *testing.T, vendor string, self int, in *ipsec.TunnelIntent) ipsec.Artifact {
	t.Helper()
	d, _ := ipsec.Driver(vendor)
	art, err := d.RenderRemove(ipsec.ViewFor(in, self))
	if err != nil {
		t.Fatalf("%s renderRemove: %v", vendor, err)
	}
	return art
}

// TestFortiGate_RemoveIsRESTByKey pins that RenderRemove emits http_api DELETEs
// (phase1/phase2 by name, routes/policies by deterministic key) and NEVER an
// explicit system/interface delete (the VTI is reaped by the phase1 delete).
func TestFortiGate_RemoveIsRESTByKey(t *testing.T) {
	in := canonicalIntent()
	art := renderRemove(t, "fortigate", 0, in)
	for _, s := range art.Steps {
		if s.Kind != ipsec.StepHTTPAPI || s.Method != "DELETE" {
			t.Errorf("remove step %q: kind=%q method=%q, want http_api DELETE", s.Description, s.Kind, s.Method)
		}
	}
	all := stepsText(art)
	for _, want := range []string{
		"DELETE /api/v2/cmdb/vpn.ipsec/phase1-interface/" + in.Name,
		"DELETE /api/v2/cmdb/vpn.ipsec/phase2-interface/" + in.Name,
		"/api/v2/cmdb/firewall/policy/", "/api/v2/cmdb/router/static/",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("remove missing %q\n%s", want, all)
		}
	}
	if strings.Contains(all, "/api/v2/cmdb/system/interface/") {
		t.Errorf("remove must NOT explicitly delete the VTI interface (phase1 delete reaps it):\n%s", all)
	}
	// Delete keys must match the deterministic seq-nums Render uses (round-trip).
	for i := 0; i < len(in.Ends[1].ProtectedSubnets)*2; i++ {
		if !strings.Contains(all, "/router/static/"+strconv.Itoa(ipsec.FGRouteKey(in.ID, i))) {
			t.Errorf("remove missing route seq-num %d", ipsec.FGRouteKey(in.ID, i))
		}
	}
}

// TestPeerRoute_ConditionalBothVendors pins the /32 is emitted only when a routed
// subnet contains the peer IP AND a Gateway is set, on both vendors.
func TestPeerRoute_ConditionalBothVendors(t *testing.T) {
	// canonical: no routed subnet contains a peer IP → no /32 on either end.
	base := canonicalIntent()
	if s := render(t, "fortigate", 0, base); strings.Contains(s.PreviewText, "255.255.255.255") && strings.Contains(strings.ToLower(stepsText(s)), "self-lockout") {
		t.Error("fortigate: canonical intent should not emit a peer /32")
	}

	// FortiGate end (self=0): make the remote (end 1) protected subnet contain the
	// remote peer IP, and give end 0 a WAN gateway.
	fg := canonicalIntent()
	fg.Ends[1].Dynamic = false
	fg.Ends[1].PeerIP = "203.0.113.9"
	fg.Ends[1].ProtectedSubnets = []string{"203.0.113.0/24"}
	fg.Ends[0].Gateway = "66.179.9.1"
	art := render(t, "fortigate", 0, fg)
	if !strings.Contains(stepsText(art), `"dst":"203.0.113.9 255.255.255.255"`) || !strings.Contains(stepsText(art), `"gateway":"66.179.9.1"`) {
		t.Errorf("fortigate: expected peer /32 route via gateway; got:\n%s", stepsText(art))
	}
	// Same overlap but NO gateway → no /32 (validation will warn instead).
	// (Match the peer dst specifically — the VTI interface ip is also a /32.)
	fg.Ends[0].Gateway = ""
	if strings.Contains(stepsText(render(t, "fortigate", 0, fg)), `"dst":"203.0.113.9 255.255.255.255"`) {
		t.Error("fortigate: no gateway ⇒ no peer /32")
	}

	// OPNsense end (self=1): remote (end 0) subnet contains end 0's peer IP; end 1 gateway set.
	opn := canonicalIntent()
	opn.Ends[0].ProtectedSubnets = []string{"66.179.9.0/24"} // contains 66.179.9.155
	opn.Ends[1].Gateway = "192.168.5.1"
	oart := render(t, "opnsense", 1, opn)
	if !strings.Contains(stepsText(oart), "66.179.9.155/32") || !strings.Contains(stepsText(oart), "192.168.5.1") {
		t.Errorf("opnsense: expected peer /32 route + WAN gateway; got:\n%s", stepsText(oart))
	}
	if !strings.Contains(stepsText(oart), "-peer") {
		t.Error("opnsense: peer objects should be tagged desc-peer")
	}
}

// TestValidate_TooManySubnetsBlocks pins the deterministic-key cap: >Max
// protected subnets on an end is a hard block (would overrun the policy keys).
func TestValidate_TooManySubnetsBlocks(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}
	over := canonicalIntent()
	subs := make([]string, ipsec.MaxProtectedSubnetsPerEnd+1)
	for i := range subs {
		subs[i] = fmt.Sprintf("10.%d.0.0/24", i)
	}
	over.Ends[0].ProtectedSubnets = subs
	if !hasCode(ipsec.Validate(over, c), "too_many_subnets") {
		t.Errorf("expected too_many_subnets block at %d subnets", len(subs))
	}
	// Exactly Max is allowed.
	over.Ends[0].ProtectedSubnets = subs[:ipsec.MaxProtectedSubnetsPerEnd]
	if hasCode(ipsec.Validate(over, c), "too_many_subnets") {
		t.Errorf("%d subnets should be allowed", ipsec.MaxProtectedSubnetsPerEnd)
	}
}

// TestValidate_SelfLockoutClearedByGateway: the self_lockout WARN is present when
// the overlap has no gateway, and cleared when a gateway is supplied (the /32
// will be pinned).
func TestValidate_SelfLockoutClearedByGateway(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}
	in := canonicalIntent()
	in.Ends[0].ProtectedSubnets = []string{"66.179.9.0/24"} // contains end0 peer 66.179.9.155

	// No gateway on the end that routes it (end 1 installs end0's subnets) → warn.
	if !hasCode(ipsec.Validate(in, c), "self_lockout") {
		t.Fatal("expected self_lockout without a gateway")
	}
	// Supply end 1's WAN gateway → the /32 will be pinned → no self_lockout.
	in.Ends[1].Gateway = "192.168.5.1"
	if hasCode(ipsec.Validate(in, c), "self_lockout") {
		t.Error("self_lockout should be cleared once the routing end has a Gateway")
	}
}
