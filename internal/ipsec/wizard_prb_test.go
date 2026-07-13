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

// Egress + LAN interfaces are required — an empty value would render an invalid
// interface binding / firewall rule downstream, so it must block at validation.
func TestValidate_EgressLANRequired(t *testing.T) {
	in := canonicalIntent()
	in.Ends[0].EgressIface = ""
	in.Ends[1].LANIface = ""
	fs := ipsec.Validate(in, bothCaps(t))
	if !hasCode(fs, "egress_missing") {
		t.Errorf("empty egress interface must block with egress_missing; got %+v", fs)
	}
	if !hasCode(fs, "lan_missing") {
		t.Errorf("empty LAN interface must block with lan_missing; got %+v", fs)
	}
	// The canonical intent has both interfaces and must not trip either.
	clean := ipsec.Validate(canonicalIntent(), bothCaps(t))
	if hasCode(clean, "egress_missing") || hasCode(clean, "lan_missing") {
		t.Errorf("canonical intent has both interfaces set and must not trip: %+v", clean)
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
	if !stepsContain(art.Steps, `"reqid":"7"`) {
		t.Fatal("child reqid should be pinned from the intent, not auto (0)")
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
