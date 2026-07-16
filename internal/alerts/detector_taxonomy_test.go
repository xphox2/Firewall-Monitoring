package alerts

import (
	"testing"

	"firewall-mon/internal/detect"
)

// TestSecurityDetectorTaxonomy_XOR (Tranche 4 guardrail): every
// CategorySecurity detector in the detect Registry must be EITHER in
// securityDetectorPriority (src-keyed — flows into the per-source
// SFLOW_SECURITY consolidation, where the winner tiebreak needs its rank) OR
// victim-keyed (routes down the per-detection path), never both, never
// neither. A security detector missing from both would consolidate with a
// zero priority and silently lose every winner tiebreak; one in both would be
// ranked for a path it never takes.
func TestSecurityDetectorTaxonomy_XOR(t *testing.T) {
	for _, det := range detect.Registry() {
		if det.Category() != detect.CategorySecurity {
			continue
		}
		name := det.Name()
		_, ranked := securityDetectorPriority[name]
		victim := detect.VictimKeyed(name)
		if ranked == victim {
			t.Errorf("security detector %q: ranked=%v victimKeyed=%v — must be exactly one (add to securityDetectorPriority or detect.victimKeyed)", name, ranked, victim)
		}
	}
}
