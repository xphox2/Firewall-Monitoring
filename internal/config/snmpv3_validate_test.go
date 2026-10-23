package config

import (
	"strings"
	"testing"
)

// TestValidate_SNMPv3RequiresAuth pins D-19: SNMPv3 with no authentication
// (noAuthNoPriv) is a fatal startup error, since it is indistinguishable from a
// cleartext community. SNMP_V3_ALLOW_NOAUTH=true is the escape hatch.
func TestValidate_SNMPv3RequiresAuth(t *testing.T) {
	t.Setenv("SNMP_VERSION", "3")
	t.Setenv("SNMP_V3_AUTH_TYPE", "")
	t.Setenv("SNMP_V3_AUTH_PASS", "")
	t.Setenv("SNMP_V3_ALLOW_NOAUTH", "")

	err := Load().Validate()
	if err == nil || !strings.Contains(err.Error(), "SNMP_VERSION=3") {
		t.Fatalf("SNMPv3 without auth must be fatal, got: %v", err)
	}

	t.Setenv("SNMP_V3_ALLOW_NOAUTH", "1")
	if err := Load().Validate(); err != nil {
		t.Fatalf("SNMP_V3_ALLOW_NOAUTH=1 must allow noAuthNoPriv, got: %v", err)
	}
}
