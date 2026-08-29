package shell

import (
	"strings"
	"testing"
)

// TestProbeSchemaVersionHandshake pins the probe↔server schema_version
// handshake so it can't silently regress:
//
//   - internal/relay/relay.go defines the SchemaVersionMin/SchemaVersionMax
//     consts (the supported-range source of truth).
//   - the RegisterProbe handler binds the request's schema_version field,
//     validates it against that range, and rejects an out-of-range version
//     with 426 + the supported-range header.
//
// The wire DTOs themselves are NOT in internal/relay: the register handler
// binds schema_version on its own inline request struct, and the telemetry
// shapes live in internal/models (server receiver) and the Firewall-Collector
// repo's internal/relay (sender). The former relay.RegistrationRequest /
// RegistrationResponse DTOs were dead, drifted duplicates removed by AUDIT-211.
//
// (Re-implements the intent of the closed PR #8 on current master. The PR
// mislabeled itself "AUDIT-065", which is an unrelated, already-resolved
// frontend finding — this feature is intentionally not tied to that ID.)
func TestProbeSchemaVersionHandshake(t *testing.T) {
	// internal/relay/relay.go owns the supported-range consts (and the v4
	// command-channel DTOs). The production probe lives in the
	// Firewall-Collector repo.
	relaySrc := readFile(t, "../../internal/relay/relay.go")
	for _, needle := range []string{
		"SchemaVersionMin = 1",
		// v5 = L2 topology snapshots (topology-entries + topology-neighbors,
		// the port-to-port connection map). Bump this needle in LOCKSTEP with
		// the collector repo's relay.SchemaVersionMax and the MIGRATING.md /
		// SUPPORT-MATRIX.md / COMPATIBILITY.md tables.
		"SchemaVersionMax = 5",
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
		// the register handler binds the schema_version field on its own
		// inline request struct (not a relay DTO).
		"SchemaVersion *int `json:\"schema_version\"`",
		"\"schema_version\": selectedVersion",
		// v4 command channel: the heartbeat must gate pending_commands
		// delivery on the probe's PERSISTED negotiated schema version.
		"probe.SchemaVersion >= 4",
		"pending_commands",
	} {
		if !strings.Contains(handlerSrc, needle) {
			t.Errorf("handlers_probes.go missing %q (schema_version validation)", needle)
		}
	}
}
