package shell

import (
	"os"
	"strings"
	"testing"
)

// TestVendoredLibrariesPinned_AUDIT160 pins the provenance record for the
// committed, pre-minified browser libraries: VENDOR.md must list each library
// with a version, and package.json must carry the matching version pins. Guards
// against a vendored lib being added/refreshed without recording where it came
// from or which version it is.
func TestVendoredLibrariesPinned_AUDIT160(t *testing.T) {
	vendor, err := os.ReadFile("../../cmd/api/static/js/VENDOR.md")
	if err != nil {
		t.Fatalf("read VENDOR.md: %v", err)
	}
	v := string(vendor)
	for _, lib := range []string{"Chart.js", "chartjs-plugin-zoom", "Cytoscape.js", "GridStack.js", "Plot"} {
		if !strings.Contains(v, lib) {
			t.Errorf("VENDOR.md does not document %q (AUDIT-160).", lib)
		}
	}
	// Each documented version must also be pinned in package.json.
	pkg, err := os.ReadFile("../../package.json")
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	p := string(pkg)
	if !strings.Contains(p, "vendoredBrowserLibraries") {
		t.Error("package.json missing the vendoredBrowserLibraries pins (AUDIT-160).")
	}
	for _, ver := range []string{"4.4.7", "2.0.1", "3.30.4", "10.3.1", "1.6.31"} {
		if !strings.Contains(p, ver) {
			t.Errorf("package.json missing vendored version pin %q (AUDIT-160).", ver)
		}
		if !strings.Contains(v, ver) {
			t.Errorf("VENDOR.md missing version %q that package.json pins (AUDIT-160): keep them in sync.", ver)
		}
	}
}
