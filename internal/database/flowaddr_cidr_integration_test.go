//go:build integration

// The exact-CIDR address filter is PostgreSQL-only — postgresDialect.AddrInCIDR
// emits inet containment, sqliteDialect declines and the caller falls back to
// prefix matching. So the unit lane cannot see this code at all, and the bug it
// guards against is invisible until production data hits it.
//
// The bug: `”::inet` raises "invalid input syntax for type inet", which aborts
// the whole statement rather than skipping the row. Production carries 2,377
// flow_rollups rows whose src_addr and dst_addr are the empty string (protocol
// 0, all in the 1d tier, so every window over 30 days reads them). Without the
// NULLIF guard, any address filter that produces no LIKE prefix — every IPv6
// CIDR, and every IPv4 mask shorter than /8, which are exactly the cases the
// exact filter was added to fix — errors out and the page falls back to
// raw-only figures under a "some panels could not be aggregated" banner that
// misdiagnoses the cause.
package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestFlowAddrFilterIntegration_EmptyAddressDoesNotAbortQuery(t *testing.T) {
	d := NewIntegrationDB(t)
	now := time.Now()

	// A row with no address at all, exactly as production stores it.
	if err := d.db.Create(&models.FlowRollup{
		Timestamp: now.Add(-40 * 24 * time.Hour), DeviceID: 1, IntervalType: "1d",
		SrcAddr: "", DstAddr: "", DstPort: 0, Protocol: 0,
		BytesSum: 4242, PacketsSum: 7, FlowCount: 1,
	}).Error; err != nil {
		t.Fatalf("seed empty-address rollup: %v", err)
	}
	// A normal row inside the filter, so a passing test proves the filter still
	// matches rather than merely failing to explode.
	if err := d.db.Create(&models.FlowRollup{
		Timestamp: now.Add(-40 * 24 * time.Hour), DeviceID: 1, IntervalType: "1d",
		SrcAddr: "10.1.2.3", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: 5000, PacketsSum: 9, FlowCount: 2,
	}).Error; err != nil {
		t.Fatalf("seed normal rollup: %v", err)
	}

	cases := []struct {
		name      string
		filter    string
		wantMatch bool
	}{
		// No LIKE prefix is produced for these, so the inet predicate stands
		// alone and meets the empty-address rows unguarded.
		{"ipv6 cidr", "2001:db8::/32", false},
		{"ipv4 mask wider than /8", "10.0.0.0/6", true},
		// These do get a prefix, but must still not error.
		{"non-octet mask", "10.1.2.0/25", true},
		{"exact host", "10.1.2.3/32", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := d.GetFlowStats(2160, FlowStatsFilter{SrcAddr: tc.filter})
			if err != nil {
				t.Fatalf("GetFlowStats(SrcAddr=%q): %v", tc.filter, err)
			}
			if res.Degraded {
				t.Fatalf("SrcAddr=%q left the result degraded (%v) — the address filter errored "+
					"on the empty-address rows instead of excluding them", tc.filter, res.DegradedBlocks)
			}
			if got := res.TotalFlows > 0; got != tc.wantMatch {
				t.Errorf("SrcAddr=%q matched=%v (TotalFlows=%d), want matched=%v",
					tc.filter, got, res.TotalFlows, tc.wantMatch)
			}
		})
	}

	// A /25 must not quietly widen to the enclosing /24, which is what prefix
	// matching alone did.
	res, err := d.GetFlowStats(2160, FlowStatsFilter{SrcAddr: "10.1.2.128/25"})
	if err != nil {
		t.Fatalf("GetFlowStats(/25 excluding the host): %v", err)
	}
	if res.TotalFlows != 0 {
		t.Errorf("10.1.2.128/25 matched %d flows; 10.1.2.3 is outside it. Prefix matching alone "+
			"rounds the mask up to the whole /24 and returns twice the address space asked for",
			res.TotalFlows)
	}
}
