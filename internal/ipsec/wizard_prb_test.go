package ipsec_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors"
)

func bothCaps(t *testing.T) [2]ipsec.CapabilityDescriptor {
	return [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}
}

func stepsContain(steps []ipsec.ApplyStep, needle string) bool {
	for _, s := range steps {
		if strings.Contains(s.Body, needle) || strings.Contains(s.CLI, needle) {
			return true
		}
	}
	return false
}

// PR-B: an empty IKE identity must block (the wizard designs out IP-default IDs).
func TestValidate_IDMissingBlocks_PRB(t *testing.T) {
	in := canonicalIntent()
	in.Ends[1].LocalID.Value = ""
	fs := ipsec.Validate(in, bothCaps(t))
	if !hasCode(fs, "id_missing") {
		t.Fatalf("empty IKE identity must block with id_missing; got %+v", fs)
	}
	// A populated identity does not trip it.
	if hasCode(ipsec.Validate(canonicalIntent(), bothCaps(t)), "id_missing") {
		t.Fatal("canonical intent has explicit IDs and must not trip id_missing")
	}
}

// Egress is required on every end — an empty value renders an invalid interface
// binding downstream.
func TestValidate_EgressRequired(t *testing.T) {
	in := canonicalIntent()
	in.Ends[0].EgressIface = ""
	if !hasCode(ipsec.Validate(in, bothCaps(t)), "egress_missing") {
		t.Errorf("empty egress interface must block with egress_missing")
	}
	if hasCode(ipsec.Validate(canonicalIntent(), bothCaps(t)), "egress_missing") {
		t.Error("canonical intent has an egress interface and must not trip egress_missing")
	}
}

// A LAN interface is required only for vendors whose rules NAME one. FortiGate
// policies do; OPNsense's pass rules are floating and subnet-scoped, so demanding
// one there would ask for a value nothing reads.
//
// canonicalIntent's end 0 is FortiGate and end 1 is OPNsense, so this pins both
// directions — before UsesLANIface, clearing end 1 raised lan_missing.
func TestValidate_LANRequiredOnlyWhereRulesNameIt(t *testing.T) {
	fgEnd := ipsec.Validate(func() *ipsec.TunnelIntent {
		in := canonicalIntent()
		in.Ends[0].LANIface, in.Ends[0].LANIfaces = "", nil
		return in
	}(), bothCaps(t))
	if !hasCode(fgEnd, "lan_missing") {
		t.Errorf("FortiGate end with no LAN interface must block with lan_missing; got %+v", fgEnd)
	}

	opnEnd := ipsec.Validate(func() *ipsec.TunnelIntent {
		in := canonicalIntent()
		in.Ends[1].LANIface, in.Ends[1].LANIfaces = "", nil
		return in
	}(), bothCaps(t))
	if hasCode(opnEnd, "lan_missing") {
		t.Errorf("OPNsense end needs no LAN interface — its rules are floating; got %+v", opnEnd)
	}

	// A list of blank entries is as empty as no list: the effective set is what
	// counts, or a whitespace-only custom entry would render {"name": ""}.
	blank := canonicalIntent()
	blank.Ends[0].LANIface = ""
	blank.Ends[0].LANIfaces = []string{"", "   "}
	if !hasCode(ipsec.Validate(blank, bothCaps(t)), "lan_missing") {
		t.Error("a LAN list of only blank entries must still block with lan_missing")
	}

	// The legacy singular alone still satisfies it — this is the persisted shape.
	legacy := canonicalIntent()
	legacy.Ends[0].LANIfaces = nil
	legacy.Ends[0].LANIface = "port3"
	if hasCode(ipsec.Validate(legacy, bothCaps(t)), "lan_missing") {
		t.Error("an intent carrying only the legacy lan_iface must satisfy the requirement")
	}

	if hasCode(ipsec.Validate(canonicalIntent(), bothCaps(t)), "lan_missing") {
		t.Error("canonical intent must not trip lan_missing")
	}
}

// PR-B: OPNsense IKE rekey_time comes from the intent, and a missing lifetime
// defaults to 24h (never 0 = never-rekey); child reqid is pinned from the intent.
func TestOPNsense_RekeyAndReqidFromIntent_PRB(t *testing.T) {
	d, ok := ipsec.Driver("opnsense")
	if !ok {
		t.Fatal("opnsense driver not registered")
	}
	in := canonicalIntent()
	in.IKELifetimeSecs = 28800
	art, err := d.Render(ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !stepsContain(art.Steps, `"rekey_time":"28800"`) {
		t.Fatal("connection rekey_time should reflect the intent's IKE lifetime")
	}
	// Policy-based children carry NO reqid (strongSwan allocates one; reqid only
	// links a route-based VTI). Assert it's absent rather than pinned.
	if stepsContain(art.Steps, `"reqid"`) {
		t.Fatal("policy-based child must not carry a reqid")
	}

	in.IKELifetimeSecs = 0
	art0, _ := d.Render(ipsec.ViewFor(in, 1))
	if stepsContain(art0.Steps, `"rekey_time":"0"`) {
		t.Fatal("rekey_time must never render 0 (strongSwan reads it as never-rekey)")
	}
	if !stepsContain(art0.Steps, `"rekey_time":"86400"`) {
		t.Fatal("a missing IKE lifetime should default to 86400")
	}
}
