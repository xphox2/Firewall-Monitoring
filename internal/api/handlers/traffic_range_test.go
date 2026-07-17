package handlers

import "testing"

// TestParseTrafficRangeHours pins the connection-traffic range parsing: the
// detail page's dropdown sends numeric hours (0.25 … 8760), the endpoint's
// launch tokens stay valid for URL back-compat, and garbage falls back to 24.
// The pre-fix whitelist accepted only the tokens, so every dropdown selection
// silently served the 24h window.
func TestParseTrafficRangeHours(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"1h", 1}, {"24h", 24}, {"7d", 168}, {"30d", 720},
		{"0.25", 0.25}, {"0.5", 0.5}, {"1", 1}, {"6", 6}, {"12", 12},
		{"24", 24}, {"168", 168}, {"720", 720}, {"2160", 2160}, {"8760", 8760},
		{"", 24}, {"abc", 24}, {"0", 24}, {"-6", 24}, {"NaN", 24},
	}
	for _, c := range cases {
		if got := parseTrafficRangeHours(c.in); got != c.want {
			t.Errorf("parseTrafficRangeHours(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
