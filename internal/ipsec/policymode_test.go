package ipsec_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors"
)

// TestPolicyBased_OPNsense_NoVTIFootprint pins the policy-based OPNsense render:
// specific selectors + policies=1, and NO VTI/gateway/route/interface steps (the
// un-automatable footprint that blocked fwm-t3). canonicalIntent is policy-based.
func TestPolicyBased_OPNsense_NoVTIFootprint(t *testing.T) {
	art := render(t, "opnsense", 1, canonicalIntent())
	txt := stepsText(art)

	// Must NOT create any VTI/gateway/route/interface object.
	for _, banned := range []string{"/ipsec/vti/", "/routing/settings/addGateway", "/routes/routes/addroute", "ipsec3", "skip_fw"} {
		if strings.Contains(txt, banned) {
			t.Errorf("policy-based OPNsense must not emit %q:\n%s", banned, txt)
		}
	}
	// Must create the connection/child/PSK with policy-based child fields.
	all := allBodies(art)
	for _, want := range []string{`"policies":"1"`, `"local_ts":"192.168.50.0/24"`, `"remote_ts":"10.10.10.0/24"`} {
		if !strings.Contains(all, want) {
			t.Errorf("policy-based OPNsense child missing %q:\n%s", want, all)
		}
	}
	// No reqid on a policy-based child.
	if strings.Contains(all, `"reqid"`) {
		t.Errorf("policy-based OPNsense child must not carry a reqid:\n%s", all)
	}
	// RenderRemove must not try to delete VTI/gateway/route.
	drv, _ := ipsec.Driver("opnsense")
	rart, err := drv.RenderRemove(ipsec.ViewFor(canonicalIntent(), 1))
	if err != nil {
		t.Fatalf("RenderRemove: %v", err)
	}
	rtxt := stepsText(rart)
	for _, banned := range []string{"delGateway", "delroute", "vti/del"} {
		if strings.Contains(rtxt, banned) {
			t.Errorf("policy-based OPNsense remove must not emit %q:\n%s", banned, rtxt)
		}
	}
}

// TestPolicyBased_FortiGate_SpecificSelectors pins that FortiGate policy-based
// keeps the VTI + routes but narrows phase2 to the SPECIFIC selectors.
func TestPolicyBased_FortiGate_SpecificSelectors(t *testing.T) {
	in := canonicalIntent() // policy-based
	all := allBodies(render(t, "fortigate", 0, in))
	if !strings.Contains(all, `"src-subnet":"10.10.10.0 255.255.255.0"`) ||
		!strings.Contains(all, `"dst-subnet":"192.168.50.0 255.255.255.0"`) {
		t.Errorf("FortiGate policy-based phase2 must use specific selectors:\n%s", all)
	}
	if strings.Contains(all, `"src-subnet":"0.0.0.0 0.0.0.0"`) {
		t.Errorf("FortiGate policy-based must NOT use 0/0 selectors:\n%s", all)
	}
	// Route-based still uses 0/0.
	in.Mode = ipsec.ModeRouteBased
	in.VTISubnet = "169.254.1.28/30"
	allR := allBodies(render(t, "fortigate", 0, in))
	if !strings.Contains(allR, `"src-subnet":"0.0.0.0 0.0.0.0"`) {
		t.Errorf("FortiGate route-based must use 0/0 selectors:\n%s", allR)
	}
}
