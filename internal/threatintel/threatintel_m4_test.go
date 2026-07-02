package threatintel

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestMatcher_LongestPrefixWins_M4 pins the bucketed-lookup rewrite (M4 of the
// 2026-07-01 audit): overlapping prefixes must return the MOST SPECIFIC match,
// and lookups must work for both families plus 4-in-6 mapped addresses.
func TestMatcher_LongestPrefixWins_M4(t *testing.T) {
	m := New([]models.ThreatIntel{
		{CIDR: "10.0.0.0/8", Category: "broad", Severity: "info"},
		{CIDR: "10.1.2.0/24", Category: "narrow", Severity: "critical"},
		{CIDR: "203.0.113.7", Category: "host", Severity: "warning"}, // bare IP → /32
		{CIDR: "2001:db8::/32", Category: "v6", Severity: "warning"},
	}, time.Now())

	if hit, ok := m.Match("10.1.2.99"); !ok || hit.Category != "narrow" {
		t.Errorf("10.1.2.99 → %+v ok=%v, want the /24 (most specific), not the /8", hit, ok)
	}
	if hit, ok := m.Match("10.200.0.1"); !ok || hit.Category != "broad" {
		t.Errorf("10.200.0.1 → %+v ok=%v, want the /8", hit, ok)
	}
	if hit, ok := m.Match("203.0.113.7"); !ok || hit.Category != "host" {
		t.Errorf("host prefix miss: %+v ok=%v", hit, ok)
	}
	if _, ok := m.Match("203.0.113.8"); ok {
		t.Error("adjacent host must not match a /32")
	}
	if hit, ok := m.Match("2001:db8:1::1"); !ok || hit.Category != "v6" {
		t.Errorf("v6 miss: %+v ok=%v", hit, ok)
	}
	if hit, ok := m.Match("::ffff:10.1.2.5"); !ok || hit.Category != "narrow" {
		t.Errorf("4-in-6 mapped address must match the IPv4 buckets: %+v ok=%v", hit, ok)
	}
	if _, ok := m.Match("not-an-ip"); ok {
		t.Error("garbage must not match")
	}
	if m.Len() != 4 {
		t.Errorf("Len = %d, want 4", m.Len())
	}
}

// BenchmarkMatcher_Miss_M4 documents the reason for the rewrite: a miss (the
// common case at ingest) is O(#distinct prefix lengths), not O(feed size).
func BenchmarkMatcher_Miss_M4(b *testing.B) {
	rows := make([]models.ThreatIntel, 0, 50000)
	for i := 0; i < 50000; i++ {
		rows = append(rows, models.ThreatIntel{CIDR: fmt.Sprintf("%d.%d.%d.0/24", 1+i%223, (i/223)%256, i%256)})
	}
	m := New(rows, time.Now())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("240.0.0.1") // never matches
	}
}
