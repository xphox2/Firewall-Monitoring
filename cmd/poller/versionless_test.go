package main

import "testing"

// versionLess decides whether a collector is too old to run a command. Getting
// it wrong is silent in both directions: too strict and the feature never
// starts, too loose and every cycle produces a failed row.
func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		why  string
	}{
		{"1.3.29", "1.3.30", true, "one patch behind"},
		{"1.3.30", "1.3.30", false, "equal is not older"},
		{"1.3.31", "1.3.30", false, "newer"},
		// The reason this is not a string compare: "1.3.9" > "1.3.30"
		// lexically, which would wrongly admit an older collector.
		{"1.3.9", "1.3.30", true, "9 < 30 numerically, though not lexically"},
		{"1.4.0", "1.3.30", false, "minor bump beats patch"},
		{"2.0.0", "1.3.30", false, "major bump"},
		{"1.3", "1.3.30", true, "shorter prefix is older"},
		// An unparseable segment must NOT read as old: refusing on a format we
		// do not recognise is how a feature quietly never starts.
		{"1.3.30-rc1", "1.3.30", false, "unparseable segment is not older"},
		{"weird", "1.3.30", false, "garbage is not older"},
		{"", "1.3.30", false, "empty is not older (unknown is handled by the caller)"},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q, %q) = %v, want %v — %s", c.a, c.b, got, c.want, c.why)
		}
	}
}
