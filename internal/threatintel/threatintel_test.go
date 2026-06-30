package threatintel

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestMatcher(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	rows := []models.ThreatIntel{
		{CIDR: "203.0.113.0/24", Category: "c2", Severity: "warning"},
		{CIDR: "198.51.100.7", Category: "scanner", Severity: "info"},                    // bare IP -> /32
		{CIDR: "2001:db8::/32", Category: "malware", Severity: "warning"},                // ipv6
		{CIDR: "10.0.0.0/8", Category: "expired", Severity: "warning", ExpiresAt: &past}, // expired -> skipped
		{CIDR: "192.0.2.0/24", Category: "active", Severity: "warning", ExpiresAt: &future},
		{CIDR: "not-a-cidr", Category: "junk", Severity: "info"}, // skipped
	}
	m := New(rows, now)
	if m.Len() != 4 {
		t.Fatalf("Len = %d, want 4 (expired + junk excluded)", m.Len())
	}

	cases := []struct {
		ip      string
		wantOK  bool
		wantCat string
	}{
		{"203.0.113.55", true, "c2"},
		{"198.51.100.7", true, "scanner"},
		{"198.51.100.8", false, ""},
		{"2001:db8::dead", true, "malware"},
		{"192.0.2.10", true, "active"},
		{"10.1.2.3", false, ""}, // expired entry must not match
		{"8.8.8.8", false, ""},
		{"bad-ip", false, ""},
	}
	for _, tc := range cases {
		hit, ok := m.Match(tc.ip)
		if ok != tc.wantOK || hit.Category != tc.wantCat {
			t.Errorf("Match(%q) = (%+v, %v), want cat=%q ok=%v", tc.ip, hit, ok, tc.wantCat, tc.wantOK)
		}
	}
}

func TestNilMatcherSafe(t *testing.T) {
	var m *Matcher
	if _, ok := m.Match("8.8.8.8"); ok {
		t.Error("nil matcher matched")
	}
	if m.Len() != 0 {
		t.Error("nil matcher Len != 0")
	}
}

func TestHolder(t *testing.T) {
	var h Holder
	// Zero holder: nil matcher, safe.
	if _, ok := h.Match("203.0.113.9"); ok {
		t.Error("empty holder matched")
	}
	h.Store(New([]models.ThreatIntel{{CIDR: "203.0.113.0/24", Category: "c2", Severity: "warning"}}, time.Now()))
	if hit, ok := h.Match("203.0.113.9"); !ok || hit.Category != "c2" {
		t.Errorf("holder match = (%+v,%v), want c2/true", hit, ok)
	}
	if h.Len() != 1 {
		t.Errorf("holder Len = %d, want 1", h.Len())
	}
}
