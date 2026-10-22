package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestSNMPCommunity_NoPublicDefault pins that neither the entrypoint nor the
// example config seeds a default SNMP community of "public". Shipping the
// world's best-known community string as a default meant a fresh deploy polled
// every device with a publicly-known credential. The default must be EMPTY so
// the operator sets their real read-only community (mirroring SNMP_TRAP_COMMUNITY
// in AUDIT-012).
func TestSNMPCommunity_NoPublicDefault(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"../../entrypoint.sh", `${SNMP_COMMUNITY:-public}`},
		{"../../config.env.example", "SNMP_COMMUNITY=public"},
	} {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Skipf("%s not found: %v", c.path, err)
		}
		if strings.Contains(string(data), c.want) {
			t.Errorf("%s seeds a default SNMP community of %q — the default must be empty so the operator sets their own community (see SNMP_TRAP_COMMUNITY, AUDIT-012).", c.path, c.want)
		}
	}
}
