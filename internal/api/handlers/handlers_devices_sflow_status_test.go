package handlers

import "testing"

// TestSflowIfStatus pins the sFlow v5 ifStatus bit decode (bit 0 = ifAdminStatus
// up, bit 1 = ifOperStatus up) into the SNMP poller's Status / AdminStatus
// vocabulary. Pre-change every non-zero value rendered as "up", so an
// admin-up / oper-down interface (ifStatus 1) was shown up (fails on revert:
// value 1 -> "up").
func TestSflowIfStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		bits      uint32
		status    string
		admin     string
		rationale string
	}{
		{0, "unknown", "", "both bits clear is also the omitempty 'absent' encoding"},
		{1, "down", "up", "admin up, oper down — the link is down"},
		{2, "up", "down", "oper up while admin down: faithful to the wire, however odd"},
		{3, "up", "up", "the normal case"},
		{0xFF, "up", "up", "reserved high bits are ignored"},
		{0x4, "down", "down", "only a reserved bit set: present but neither up"},
	}
	for _, tc := range cases {
		status, admin := sflowIfStatus(tc.bits)
		if status != tc.status || admin != tc.admin {
			t.Errorf("sflowIfStatus(%#x) = (%q, %q), want (%q, %q) — %s",
				tc.bits, status, admin, tc.status, tc.admin, tc.rationale)
		}
	}
}
