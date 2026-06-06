package shell

import (
	"os"
	"strings"
	"testing"
)

// TestCustomVendorDoc_AUDIT170 pins that the "adding a custom vendor"
// tutorial exists and references the real extension points, so the doc can't
// drift into describing an API that no longer exists. It also checks the
// README links it (discoverability).
func TestCustomVendorDoc_AUDIT170(t *testing.T) {
	data, err := os.ReadFile("../../docs/custom-vendor.md")
	if err != nil {
		t.Fatalf("docs/custom-vendor.md not found (AUDIT-170): %v", err)
	}
	doc := string(data)

	// The tutorial must name the actual interface + registration + allow-list
	// touch points. These are the exact symbols a reader greps for in the code.
	for _, anchor := range []string{"VendorProfile", "RegisterVendor", "validVendors", "ParseSystemStatus", "init()"} {
		if !strings.Contains(doc, anchor) {
			t.Errorf("docs/custom-vendor.md does not mention %q (AUDIT-170): the tutorial must point at the real extension point.", anchor)
		}
	}

	readme, err := os.ReadFile("../../README.md")
	if err == nil && !strings.Contains(string(readme), "docs/custom-vendor.md") {
		t.Error("README.md does not link docs/custom-vendor.md (AUDIT-170): the tutorial should be discoverable from the README.")
	}
}
