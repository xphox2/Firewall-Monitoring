package snmp

import "testing"

// apiValidVendors mirrors validVendors in internal/api/handlers/handlers.go.
// internal/snmp cannot import the handlers package (dependency direction runs
// handlers → snmp), so the list is pinned here: if a vendor is added to
// handlers.go validVendors without a matching SNMP profile — or a profile is
// dropped — this test fails and the two lists must be re-synced by hand.
var apiValidVendors = []string{
	"fortigate",
	"paloalto",
	"cisco_asa",
	"sonicwall",
	"firewalla",
	"pfsense",
	"opnsense",
	"generic",
}

// TestVendorRegistry_EveryValidVendorHasProfile is the registry-completeness
// gate: every vendor an operator can select in the API/UI must resolve to a
// real registered SNMP profile, never to the FortiGate fallback (which would
// silently poll Fortinet enterprise OIDs on a non-Fortinet device).
func TestVendorRegistry_EveryValidVendorHasProfile(t *testing.T) {
	for _, v := range apiValidVendors {
		p := GetVendorProfile(v)
		if p == nil {
			t.Errorf("vendor %q is accepted by the API (handlers.go validVendors) but has no registered SNMP profile", v)
			continue
		}
		if p.Name() != v {
			t.Errorf("vendor %q resolved to profile %q — registry key/name mismatch", v, p.Name())
		}
	}
}

func TestResolveVendor_FallbackSemantics(t *testing.T) {
	s := &SNMPClient{} // resolveVendor does not touch connection state

	// Empty/legacy vendor stays FortiGate: Device.Vendor defaults to
	// "fortigate" and pre-vendor-column devices rely on this mapping.
	if got := s.resolveVendor("").Name(); got != "fortigate" {
		t.Errorf("resolveVendor(\"\") = %q, want fortigate (load-bearing legacy default)", got)
	}

	// Unknown vendor strings must resolve to the standards-only generic
	// profile, NOT to FortiGate enterprise OIDs.
	if got := s.resolveVendor("no-such-vendor").Name(); got != "generic" {
		t.Errorf("resolveVendor(unknown) = %q, want generic", got)
	}

	// Known vendors resolve to themselves.
	for _, v := range apiValidVendors {
		if got := s.resolveVendor(v).Name(); got != v {
			t.Errorf("resolveVendor(%q) = %q, want %q", v, got, v)
		}
	}
}
