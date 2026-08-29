package deny

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// AUDIT-272 / AUDIT-312: deny.Project is the only DeniedEvent write path, and
// several of its stored fields are attacker-controlled syslog text. src/dst
// must parse as real IPs (they land in INDEXED columns — a multi-KB "srcip"
// can overflow the PG btree row limit and fail the whole insert batch), and
// the remaining free-text fields must be capped rune-safely.

func TestProject_UnparseableIPRejected(t *testing.T) {
	cases := []string{
		// Garbage src.
		`srcip=not-an-ip dstip=66.179.9.150 dstport=3389 proto=6 action="deny"`,
		// Garbage dst.
		`srcip=203.0.113.9 dstip=garbage dstport=3389 proto=6 action="deny"`,
		// A multi-KB "srcip" — the btree-overflow shape from the audit.
		`srcip=` + strings.Repeat("A", 4096) + ` dstip=66.179.9.150 proto=6 action="deny"`,
	}
	for _, msg := range cases {
		if ev, ok := Project(denyMsg(msg), nil, PatternConfig{}); ok {
			t.Errorf("unparseable IP projected: %q -> src=%q dst=%q", msg[:60], ev.SrcAddr, ev.DstAddr)
		}
	}
	// Valid IPs (v4 and v6) still project.
	v6 := `srcip=2001:db8::9 dstip=66.179.9.150 dstport=3389 proto=6 action="deny"`
	if _, ok := Project(denyMsg(v6), nil, PatternConfig{}); !ok {
		t.Errorf("valid IPv6 src must still project")
	}
}

func TestProject_PolicyNameServiceCapped(t *testing.T) {
	// 10KB policyname; "é" (2 bytes) starts at byte 63, so it straddles the
	// 64-byte cut — the cut must back up to the rune boundary, not split it.
	long := strings.Repeat("a", 63) + "é" + strings.Repeat("b", 10*1024)
	msg := `srcip=203.0.113.9 dstip=66.179.9.150 dstport=3389 proto=6 action="deny" ` +
		`policyname="` + long + `" service="` + long + `"`
	ev, ok := Project(denyMsg(msg), nil, PatternConfig{})
	if !ok {
		t.Fatal("expected projection")
	}
	for name, got := range map[string]string{"PolicyName": ev.PolicyName, "Service": ev.Service} {
		if len(got) > 64 {
			t.Errorf("%s stored %d bytes, want <= 64", name, len(got))
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s cap split a UTF-8 rune: %q", name, got)
		}
		if !strings.HasPrefix(got, strings.Repeat("a", 63)) {
			t.Errorf("%s = %q, want the leading 63 a's kept", name, got)
		}
	}
	// The straddling rune is dropped whole: 63 bytes, not 64 or 65.
	if len(ev.PolicyName) != 63 {
		t.Errorf("PolicyName len = %d, want 63 (the straddling 2-byte rune dropped whole)", len(ev.PolicyName))
	}
}

func TestCapStr_RuneSafe(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 64, "short"},                                 // under the cap: unchanged
		{"abcdef", 4, "abcd"},                                  // ASCII: plain byte cut
		{"abéf", 3, "ab"},                                      // 2-byte rune straddles → dropped whole
		{"abéf", 4, "abé"},                                     // rune fits exactly
		{"a\U0001F512bcd", 3, "a"},                             // 4-byte rune straddling a mid-rune cut
		{"a\U0001F512bcd", 5, "a\U0001F512"},                   // 4-byte rune fits exactly
		{strings.Repeat("é", 40), 64, strings.Repeat("é", 32)}, // even cut on 2-byte runes
	}
	for _, c := range cases {
		got := capStr(c.in, c.max)
		if got != c.want {
			t.Errorf("capStr(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("capStr(%q, %d) produced invalid UTF-8: %q", c.in, c.max, got)
		}
	}
}
