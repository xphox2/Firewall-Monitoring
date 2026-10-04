package snmp

import (
	"reflect"
	"strings"
	"testing"
)

// TestUniFiMeraki_AreGenericClones: both profiles (0.11.291, built from
// vendor docs and untested on real hardware) are registered under their own
// name and poll exactly the generic, standards-only surface — the same system
// OIDs, no VPN / sensor / HA walks, no enterprise trap OIDs. The day either
// grows a verified vendor-specific OID this test is updated with it; until
// then it stops a copy-paste of an enterprise OID from another profile.
func TestUniFiMeraki_AreGenericClones(t *testing.T) {
	generic := GetVendorProfile("generic")
	if generic == nil {
		t.Fatal("generic profile not registered")
	}
	for _, name := range []string{"unifi", "meraki"} {
		p := GetVendorProfile(name)
		if p == nil {
			t.Errorf("%s: not registered", name)
			continue
		}
		if p.Name() != name {
			t.Errorf("%s: Name() = %q", name, p.Name())
		}
		if !reflect.DeepEqual(p.SystemOIDs(), generic.SystemOIDs()) {
			t.Errorf("%s: SystemOIDs = %v, want the generic set %v", name, p.SystemOIDs(), generic.SystemOIDs())
		}
		for _, oid := range p.SystemOIDs() {
			if !strings.HasPrefix(oid, ".1.3.6.1.2.1.") {
				t.Errorf("%s: OID %s is not under mib-2 — enterprise OIDs need hardware verification first", name, oid)
			}
		}
		if p.VPNBaseOID() != "" || p.HWSensorBaseOID() != "" || p.HABaseOID() != "" {
			t.Errorf("%s: VPN/HW/HA base OIDs = %q/%q/%q, want all empty", name, p.VPNBaseOID(), p.HWSensorBaseOID(), p.HABaseOID())
		}
		if p.ProcessorBaseOID() != generic.ProcessorBaseOID() {
			t.Errorf("%s: ProcessorBaseOID = %q, want %q", name, p.ProcessorBaseOID(), generic.ProcessorBaseOID())
		}
		if len(p.TrapOIDs()) != 0 {
			t.Errorf("%s: TrapOIDs = %v, want none", name, p.TrapOIDs())
		}
		// resolveVendor must hand back the clone, not fall through to generic:
		// the vendor name is what rules and capability profiles key on.
		if got := (&SNMPClient{}).resolveVendor(name).Name(); got != name {
			t.Errorf("resolveVendor(%s) = %q", name, got)
		}
	}
}
