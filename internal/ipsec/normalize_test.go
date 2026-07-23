package ipsec_test

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// capsFor returns each end's real vendor descriptor for a two-vendor pair.
func capsForPair(t *testing.T, a, b string) [2]ipsec.CapabilityDescriptor {
	t.Helper()
	ca, err := ipsec.Capabilities(a)
	if err != nil {
		t.Fatalf("caps %s: %v", a, err)
	}
	cb, err := ipsec.Capabilities(b)
	if err != nil {
		t.Fatalf("caps %s: %v", b, err)
	}
	return [2]ipsec.CapabilityDescriptor{ca, cb}
}

func intentWith(aType ipsec.IDType, aValue string, bType ipsec.IDType, bValue string) *ipsec.TunnelIntent {
	return &ipsec.TunnelIntent{
		Ends: [2]ipsec.EndpointSpec{
			{Vendor: "fortigate", LocalID: ipsec.IKEIdentity{Type: aType, Value: aValue}},
			{Vendor: "opnsense", LocalID: ipsec.IKEIdentity{Type: bType, Value: bValue}},
		},
	}
}

// A FortiGate⇄OPNsense tunnel stored with keyid must coerce BOTH ends to fqdn
// (OPNsense can't render keyid; the mutual set is {ip,fqdn}, values are non-IP).
func TestNormalizeIdentities_KeyIDToFQDN(t *testing.T) {
	caps := capsForPair(t, "fortigate", "opnsense")
	in := intentWith(ipsec.IDTypeKeyID, "FORTIGATE", ipsec.IDTypeKeyID, "OPNSENSE")
	ipsec.NormalizeIdentities(in, caps)
	if got := in.Ends[0].LocalID.Type; got != ipsec.IDTypeFQDN {
		t.Errorf("end A: got %q, want fqdn", got)
	}
	if got := in.Ends[1].LocalID.Type; got != ipsec.IDTypeFQDN {
		t.Errorf("end B: got %q, want fqdn", got)
	}
	// Values are never touched.
	if in.Ends[0].LocalID.Value != "FORTIGATE" || in.Ends[1].LocalID.Value != "OPNSENSE" {
		t.Errorf("identity values were altered: %+v", in.Ends)
	}
}

// An IP-literal identity value coerces to ip (not fqdn) when the mutual set has it.
func TestNormalizeIdentities_IPValueCoercesToIP(t *testing.T) {
	caps := capsForPair(t, "fortigate", "opnsense")
	in := intentWith(ipsec.IDTypeKeyID, "203.0.113.5", ipsec.IDTypeKeyID, "198.51.100.9")
	ipsec.NormalizeIdentities(in, caps)
	for i := range in.Ends {
		if got := in.Ends[i].LocalID.Type; got != ipsec.IDTypeIP {
			t.Errorf("end %d: got %q, want ip", i, got)
		}
	}
}

// A type both ends already support is left untouched (FortiGate⇄FortiGate keeps keyid).
func TestNormalizeIdentities_SupportedTypeUntouched(t *testing.T) {
	caps := capsForPair(t, "fortigate", "fortigate")
	in := &ipsec.TunnelIntent{
		Ends: [2]ipsec.EndpointSpec{
			{Vendor: "fortigate", LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "a"}},
			{Vendor: "fortigate", LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "b"}},
		},
	}
	ipsec.NormalizeIdentities(in, caps)
	for i := range in.Ends {
		if got := in.Ends[i].LocalID.Type; got != ipsec.IDTypeKeyID {
			t.Errorf("end %d: keyid should survive a FortiGate⇄FortiGate pair, got %q", i, got)
		}
	}
}

// After normalization the OPNsense driver renders without error (the regression
// this fix targets: a keyid intent previously reached Render and mis-authenticated).
func TestNormalizeIdentities_UnblocksOPNsenseRender(t *testing.T) {
	caps := capsForPair(t, "fortigate", "opnsense")
	in := canonicalIntent()
	// Force keyid to simulate a legacy stored intent.
	in.Ends[0].LocalID.Type = ipsec.IDTypeKeyID
	in.Ends[1].LocalID.Type = ipsec.IDTypeKeyID
	ipsec.NormalizeIdentities(in, caps)
	drv, _ := ipsec.Driver("opnsense")
	if _, err := drv.Render(ipsec.ViewFor(in, 1)); err != nil {
		t.Fatalf("opnsense render after normalize should succeed, got: %v", err)
	}
}
