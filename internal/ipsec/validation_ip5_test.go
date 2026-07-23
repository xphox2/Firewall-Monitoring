package ipsec_test

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestValidate_IP5_GatewayAndLifetimes covers the AUDIT IP5 additions: the WAN
// gateway is rendered into a FortiGate host-route, and IKE/child lifetimes drive
// vendor keylife ranges — surfacing bad values as validation findings beats a
// cryptic pre-dispatch 400.
func TestValidate_IP5_GatewayAndLifetimes(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}

	// Canonical intent stays clean (no new blocks/warns introduced by IP5).
	if fs := ipsec.Validate(canonicalIntent(), c); ipsec.HasBlock(fs) {
		t.Fatalf("canonical intent should have no blocks; got %+v", fs)
	}
	if hasCode(ipsec.Validate(canonicalIntent(), c), "ike_lifetime_range") {
		t.Error("canonical default IKE lifetime must not warn")
	}

	// Invalid WAN gateway → hard block; a valid one is accepted.
	badGW := canonicalIntent()
	badGW.Ends[0].Gateway = "not-an-ip"
	if !hasCode(ipsec.Validate(badGW, c), "gateway_invalid") {
		t.Error("expected gateway_invalid for a non-IP WAN gateway")
	}
	okGW := canonicalIntent()
	okGW.Ends[0].Gateway = "203.0.113.1"
	if hasCode(ipsec.Validate(okGW, c), "gateway_invalid") {
		t.Error("a valid gateway IP must not be flagged")
	}

	// Negative IKE lifetime → block; a wide-but-positive value → warn (not block).
	negLife := canonicalIntent()
	negLife.IKELifetimeSecs = -1
	if !hasCode(ipsec.Validate(negLife, c), "ike_lifetime_invalid") {
		t.Error("expected ike_lifetime_invalid for a negative lifetime")
	}
	wideLife := canonicalIntent()
	wideLife.IKELifetimeSecs = 999999
	wfs := ipsec.Validate(wideLife, c)
	if !hasCode(wfs, "ike_lifetime_range") || sevOf(wfs, "ike_lifetime_range") != ipsec.SeverityWarn {
		t.Errorf("expected an ike_lifetime_range WARNING for an out-of-window lifetime; got %+v", wfs)
	}
	if ipsec.HasBlock(wfs) {
		t.Errorf("an out-of-window (but positive) IKE lifetime must warn, not block; got %+v", wfs)
	}
}
