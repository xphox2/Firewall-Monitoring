package normalize

import "testing"

// TestAtoiOverflow pins D-28: a value that overflows int64 must be rejected,
// not silently wrap to a small (possibly in-range) number that then passes the
// callers' range checks.
func TestAtoiOverflow(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0", 0, true},
		{"123", 123, true},
		{"-123", -123, true},
		{"9223372036854775807", 9223372036854775807, true}, // MaxInt64
		{"9223372036854775808", 0, false},                  // MaxInt64+1 overflows
		{"9999999999999999999", 0, false},                  // 19 nines overflow
		{"-9999999999999999999", 0, false},
		{"abc", 0, false},
		{"12a", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := atoi(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("atoi(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
