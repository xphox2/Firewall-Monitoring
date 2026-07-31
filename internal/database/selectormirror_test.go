package database

import "testing"

// selectorMirrors decides whether two rows, one from each end of a tunnel,
// describe the same path. It is the sole input to the UI's "both ends reported
// this" marker, so both a false negative (marker silently missing) and a false
// positive (marker asserting agreement that was never observed) are bugs the
// operator cannot detect by looking.
//
// The values below are the real ones from connection 23984 — a FortiGate with
// two LAN subnets against an OPNsense with two, 2x2 = four paths — plus the
// shapes the two vendors actually emit around them.
func TestSelectorMirrors(t *testing.T) {
	tests := []struct {
		name           string
		a, b           string
		allowNarrowing bool
		want           bool
	}{
		// The four provisioned pairs of fwm-t12. Disjoint /24s, so containment
		// degenerates to equality and the answer must not depend on the flag.
		{"exact pair, narrowing off", "192.168.25.0/24", "192.168.25.0/24", false, true},
		{"exact pair, narrowing on", "192.168.25.0/24", "192.168.25.0/24", true, true},
		{"different /24s never match", "192.168.25.0/24", "192.168.13.0/24", true, false},

		// IKEv2 narrowing: the FortiGate's SNMP dialup row reports the configured
		// /24 as the /32 actually in use. Within one logical tunnel that is the
		// same path; across tunnels we have no evidence that it is.
		{"narrowed /32 inside its /24", "192.168.50.0/32", "192.168.50.0/24", true, true},
		{"narrowed /32, other direction", "192.168.50.0/24", "192.168.50.0/32", true, true},
		{"narrowing rejected when not same tunnel", "192.168.50.0/32", "192.168.50.0/24", false, false},

		// FortiGate's SNMP walk serialises selectors as RANGES. net.ParseCIDR
		// cannot read them at all, so equality is the ONLY test that works —
		// without the equality-first ordering these pairs would silently stop
		// matching and the marker would vanish from every FortiGate SNMP row.
		{"identical range strings", "192.168.5.0 - 192.168.5.255", "192.168.5.0 - 192.168.5.255", true, true},
		{"identical range strings, narrowing off", "192.168.5.0 - 192.168.5.255", "192.168.5.0 - 192.168.5.255", false, true},
		{"different ranges", "192.168.5.0 - 192.168.5.255", "192.168.6.0 - 192.168.6.255", true, false},
		// Cross-vendor: a range against the CIDR that covers it. SelectorIP reads
		// a range's BASE address, so containment resolves in the direction where
		// the CIDR is the configured side — the two ends describe one network in
		// two dialects, and within a single logical tunnel that is the same path.
		// Refused without narrowing, because across tunnels there is no evidence.
		{"range vs covering CIDR, same tunnel", "192.168.5.0 - 192.168.5.255", "192.168.5.0/24", true, true},
		{"range vs covering CIDR, different tunnels", "192.168.5.0 - 192.168.5.255", "192.168.5.0/24", false, false},
		{"range vs unrelated CIDR", "192.168.5.0 - 192.168.5.255", "192.168.9.0/24", true, false},

		// The wildcard. A route-based tunnel negotiates 0.0.0.0/0, which CONTAINS
		// every other selector — so with narrowing allowed it matches anything.
		// That is why the caller only allows narrowing within one logical tunnel:
		// unbounded, this would pair rows of unrelated tunnels.
		{"route-based both ends", "0.0.0.0/0", "0.0.0.0/0", false, true},
		{"wildcard swallows a /24 when narrowing allowed", "0.0.0.0/0", "192.168.25.0/24", true, true},
		{"wildcard confined when narrowing refused", "0.0.0.0/0", "192.168.25.0/24", false, false},

		{"empty never matches a real selector", "", "192.168.25.0/24", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectorMirrors(tc.a, tc.b, tc.allowNarrowing); got != tc.want {
				t.Errorf("selectorMirrors(%q, %q, narrowing=%v) = %v, want %v",
					tc.a, tc.b, tc.allowNarrowing, got, tc.want)
			}
		})
	}
}

// The full 2x2 of connection 23984, matched the way GetConnectionDetail matches
// it. Four named children on each side must pair up one-to-one; the FortiGate's
// narrowed dialup row additionally pairs with the /24 it sits inside, which is
// correct and harmless to a per-row boolean — but it means the match count is 5,
// not 4, and a future reader should not "fix" that.
func TestSelectorMirrors_Conn23984FullMesh(t *testing.T) {
	type row struct{ local, remote string }
	fgt := []row{
		{"192.168.25.0/24", "192.168.50.0/24"},
		{"192.168.25.0/24", "192.168.12.0/24"},
		{"192.168.13.0/24", "192.168.50.0/24"},
		{"192.168.13.0/24", "192.168.12.0/24"},
		{"192.168.25.0/24", "192.168.50.0/32"}, // SNMP dialup, narrowed
	}
	opn := []row{
		{"192.168.50.0/24", "192.168.25.0/24"},
		{"192.168.12.0/24", "192.168.25.0/24"},
		{"192.168.50.0/24", "192.168.13.0/24"},
		{"192.168.12.0/24", "192.168.13.0/24"},
	}

	matches := 0
	namedPaired := 0
	for i, s := range fgt {
		for _, d := range opn {
			if selectorMirrors(s.local, d.remote, true) && selectorMirrors(s.remote, d.local, true) {
				matches++
				if i < 4 {
					namedPaired++
				}
			}
		}
	}
	if namedPaired != 4 {
		t.Errorf("named children paired %d times, want exactly 4 — every provisioned path "+
			"must be recognised as reported by both ends", namedPaired)
	}
	if matches != 5 {
		t.Errorf("total matches = %d, want 5 (four named pairs + the narrowed dialup row "+
			"against the /24 that contains it)", matches)
	}
}
