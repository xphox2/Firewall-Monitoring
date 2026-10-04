package normalize

import (
	"testing"

	"firewall-mon/internal/normalize/capability"
)

// TestCapabilityProfile_NoDrift (roadmap §1.4): a capability profile may not
// promise what the vendor's mapper does not deliver. For every profiled
// vendor that has fixtures, each field the profile sources from SYSLOG must
// be non-NULL in at least one golden Event of that vendor (fields sourced
// from NetFlow or the API are out of this package's reach and are skipped).
// Adding a syslog field to a profile therefore requires a fixture that
// produces it; removing a mapping that a profile relies on fails here before
// the golden diff is even read.
func TestCapabilityProfile_NoDrift(t *testing.T) {
	t.Parallel()
	vendors := map[string]bool{}
	for _, v := range fixtureVendors(t) {
		vendors[v] = true
	}
	for _, vendor := range capability.Vendors() {
		if !vendors[vendor] {
			t.Errorf("capability profile %q has no fixtures under testdata/%s — add cases or the profile is unverifiable", vendor, vendor)
			continue
		}
		produced := map[string]bool{}
		for _, f := range loadFixtures(t, vendor) {
			g := run(vendor, f)
			for k := range g.Event {
				produced[k] = true
			}
		}
		p := capability.Lookup(vendor)
		for field, spec := range p.Fields {
			if spec.Source != capability.SourceSyslog {
				continue
			}
			if !produced[FieldPrefix+string(field)] {
				t.Errorf("%s: profile claims %q from syslog (%s) but no fixture produces event.%s", vendor, field, spec.Completeness, field)
			}
		}
	}
	// And the inverse sanity check for the two documentation-built vendors:
	// their profiles must say so.
	for _, v := range []string{"unifi", "meraki"} {
		if capability.Lookup(v).Hardware == "" {
			t.Errorf("%s: profile must be labelled untested on real hardware", v)
		}
	}
}
