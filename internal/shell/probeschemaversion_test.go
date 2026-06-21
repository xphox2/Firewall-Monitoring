package shell

import (
	"strings"
	"testing"
)

// TestProbeSchemaVersionHandshake pins the probe↔server schema_version
// handshake so it can't silently regress:
//
//   - internal/relay/relay.go defines the SchemaVersionMin/SchemaVersionMax
//     consts, carries SchemaVersion on both the request and response DTOs,
//     and the relay client advertises SchemaVersionMax on register.
//   - the RegisterProbe handler validates the field against that range and
//     rejects an out-of-range version with 426 + the supported-range header.
//
// (Re-implements the intent of the closed PR #8 on current master. The PR
// mislabeled itself "AUDIT-065", which is an unrelated, already-resolved
// frontend finding — this feature is intentionally not tied to that ID.)
func TestProbeSchemaVersionHandshake(t *testing.T) {
	// internal/relay/relay.go is now the wire-contract definitions only (the
	// bundled probe client that advertised SchemaVersionMax on register was
	// removed with cmd/probe). It still owns the consts and the SchemaVersion
	// field on the request/response DTOs; the production probe lives in the
	// Firewall-Collector repo.
	relaySrc := readFile(t, "../../internal/relay/relay.go")
	for _, needle := range []string{
		"SchemaVersionMin = 1",
		"SchemaVersionMax = 1",
		"SchemaVersion int `json:\"schema_version,omitempty\"`",
	} {
		if !strings.Contains(relaySrc, needle) {
			t.Errorf("internal/relay/relay.go missing %q (schema_version handshake)", needle)
		}
	}

	handlerSrc := readFile(t, "../../internal/api/handlers/handlers_probes.go")
	for _, needle := range []string{
		"relay.SchemaVersionMin",
		"relay.SchemaVersionMax",
		"http.StatusUpgradeRequired",
		"X-Probe-Schema-Version-Supported",
		"\"schema_version\": selectedVersion",
	} {
		if !strings.Contains(handlerSrc, needle) {
			t.Errorf("handlers_probes.go missing %q (schema_version validation)", needle)
		}
	}
}
