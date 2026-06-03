package database

import (
	"strings"
	"testing"
)

// TestCIDRToLikePattern_AUDIT148 — regression test for the audit: the
// helper's output is consumed by a SQL LIKE clause, and the audit
// flagged that:
//   - The output is built from net.ParseIP / net.ParseCIDR-validated
//     input, so today's patterns can't contain user-controlled `%`
//     or `_` (only an intentional trailing `%` as the "any" wildcard).
//   - But the LIKE clause at the call site didn't carry an
//     `ESCAPE '\'` modifier, so a future change to the helper that
//     emits literal `%` or `_` (e.g. a typo, a refactor that drops
//     the validation, an IPv6 input that survives parsing) would
//     silently widen the match.
//
// The fix: add `ESCAPE '\'` at the call site, plus this test that
// pins the helper's output for every shape the function accepts. If
// a future change alters the output, this test fails first.
func TestCIDRToLikePattern_AUDIT148(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want string
	}{
		// Empty / too-broad / unparseable inputs all return "".
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
		{"default route", "0.0.0.0/0", ""},
		{"invalid CIDR", "10.0.0.0/33", ""},
		{"non-CIDR text", "not-an-ip", ""},
		{"unparseable IP range", "abc - def", ""},
		// /32 returns the exact IP (no wildcard).
		{"ipv4 /32", "10.0.0.5/32", "10.0.0.5"},
		// /24, /16, /8 use the trailing-% wildcard.
		{"ipv4 /24", "10.0.1.0/24", "10.0.1.%"},
		{"ipv4 /16", "10.0.0.0/16", "10.0.%"},
		{"ipv4 /8", "10.0.0.0/8", "10.%"},
		// /0 (the default route, special-cased above) is the only
		// prefix that returns ""; /1-/7 are still too broad and
		// also return "".
		{"ipv4 /4 too broad", "10.0.0.0/4", ""},
		// IP range format with the " - " separator.
		{"ip range begin only", "10.0.1.0 - 10.0.1.255", "10.0.1.%"},
		// Single IP literal (no slash) — exact match.
		{"single ipv4", "192.168.1.1", "192.168.1.1"},
		// IPv6 inputs fail To4() check and return "".
		{"ipv6 /64", "2001:db8::/64", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cidrToLikePattern(tc.cidr)
			if got != tc.want {
				t.Errorf("cidrToLikePattern(%q) = %q, want %q", tc.cidr, got, tc.want)
			}
		})
	}
}

// TestCIDRToLikePattern_NeverEmitsEscapableLiteral_AUDIT148 is the
// defense-in-depth check: regardless of the input shape, the output
// must never contain a literal `%` or `_` that isn't the intentional
// trailing wildcard. A future refactor that accidentally emitted
// `10.0._.%` (a pattern that, without ESCAPE, would match any device
// on 10.0.<any>.<any>) would fail this test.
//
// We allow at most ONE `%`, and only at the end of the string. `_` is
// never allowed in the output (it's a single-char LIKE wildcard; the
// helper never needs it).
func TestCIDRToLikePattern_NeverEmitsEscapableLiteral_AUDIT148(t *testing.T) {
	// A broad set of inputs that all parse cleanly. If any of them
	// yields a pattern with a `_` or with a non-trailing `%`, the
	// LIKE query (with or without ESCAPE) would match a wider set
	// of rows than intended.
	inputs := []string{
		"10.0.0.5/32", "10.0.1.0/24", "10.0.0.0/16", "10.0.0.0/8",
		"192.168.1.1", "10.0.1.0 - 10.0.1.255",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			got := cidrToLikePattern(in)
			if got == "" {
				return // input rejected, nothing to check
			}
			if strings.Contains(got, "_") {
				t.Errorf("pattern %q for input %q contains '_' (single-char LIKE wildcard); the helper must never emit this", got, in)
			}
			// Count `%` — must be at most one, and it must be at the end.
			percentCount := strings.Count(got, "%")
			if percentCount > 1 {
				t.Errorf("pattern %q for input %q contains %d '%%' chars; at most 1 (trailing wildcard) is allowed", got, in, percentCount)
			}
			if percentCount == 1 && !strings.HasSuffix(got, "%") {
				t.Errorf("pattern %q for input %q has '%%' in a non-trailing position; only a trailing wildcard is intentional", got, in)
			}
		})
	}
}
