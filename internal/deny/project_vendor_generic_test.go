package deny

import "testing"

// TestProjectVendor_UnknownVendorNeverProjects: only a vendor with a deny
// parser projects. A FortiGate deny line under "generic", "" or an unknown
// vendor must not reach denied_events — before 0.11.290 every non-pf vendor
// fell through to the FortiGate parser, so a device left as "generic" (now the
// default) would have been parsed as a FortiGate.
func TestProjectVendor_UnknownVendorNeverProjects(t *testing.T) {
	for _, vendor := range []string{"generic", "", "  ", "paloalto", "no-such-vendor", "GENERIC"} {
		if ev, ok := ProjectVendor(vendor, denyMsg(sampleDeny), nil, PatternConfig{}); ok {
			t.Errorf("ProjectVendor(%q) projected %+v, want no event", vendor, ev)
		}
	}
	// The explicit vendors still do (case-insensitive, like the pf arm).
	for _, vendor := range []string{"fortigate", "FortiGate"} {
		if _, ok := ProjectVendor(vendor, denyMsg(sampleDeny), nil, PatternConfig{}); !ok {
			t.Errorf("ProjectVendor(%q) did not project the deny line", vendor)
		}
	}
}
