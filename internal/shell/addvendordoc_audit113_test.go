package shell

import (
	"os"
	"strings"
	"testing"
)

// TestVendorDocCoversBothSides_AUDIT113 pins that the "how to add a vendor"
// guide documents BOTH halves of the vendor convention the audit named: the
// SNMP profile (register in internal/snmp) AND the config-diff normalizer
// (internal/configdiff). AUDIT-113 asked for an ADDING-A-VENDOR doc;
// docs/custom-vendor.md (shipped for AUDIT-170) is that doc — this guards
// that it keeps covering the configdiff side, not just SNMP.
func TestVendorDocCoversBothSides_AUDIT113(t *testing.T) {
	const path = "../../docs/custom-vendor.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("docs/custom-vendor.md not found (AUDIT-113/170): %v", err)
	}
	doc := string(data)

	for _, side := range []struct{ needle, why string }{
		{"internal/snmp", "the SNMP profile side (register the VendorProfile)"},
		{"RegisterVendor", "the profile registration call"},
		{"validVendors", "the API allow-list edit"},
		{"internal/configdiff", "the config-backup normalizer side (AUDIT-113 explicitly names normalize.go)"},
	} {
		if !strings.Contains(doc, side.needle) {
			t.Errorf("docs/custom-vendor.md does not cover %q — %s (AUDIT-113).", side.needle, side.why)
		}
	}
}
