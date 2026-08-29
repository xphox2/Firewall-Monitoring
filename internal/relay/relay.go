// Package relay holds the two pieces of the cross-repo probe↔server contract
// the server binary actually consumes: the schema-version handshake constants
// (SchemaVersionMin/SchemaVersionMax) and the v4 command-channel DTOs
// (PendingCommand / CommandResultRequest) that flow server→collector on the
// heartbeat response and back on POST /api/probes/:id/command-result.
//
// This package is NOT the source of truth for the telemetry wire format. The
// authoritative wire-contract types are:
//   - the SERVER RECEIVER: internal/models (e.g. models.FlowSample, bound in
//     internal/api/handlers/handlers_data.go), which defines the shapes the
//     server actually unmarshals and persists; and
//   - the SENDER: the Firewall-Collector repo's internal/relay package, which
//     defines what the production collector encodes on the wire.
//
// The schema-version consts here MUST stay in lockstep with the same consts in
// the Firewall-Collector repo; the command-channel DTOs mirror the collector's.
// The bundled probe *client* (RelayClient and its send/registration machinery)
// was removed — the production probe is the Firewall-Collector repo, and the
// in-repo cmd/probe was a stale fork that no longer ships.
package relay

import "time"

// Schema-version handshake. schema_version is the relay-wire-format version the
// probe speaks; the server rejects anything outside [SchemaVersionMin,
// SchemaVersionMax] with HTTP 426 (Upgrade Required) and advertises the
// supported range in the X-Probe-Schema-Version-Supported header. These MUST
// stay in lockstep with the same constants in the Firewall-Collector repo.
//
// Version history (what each bump negotiates — the payload types live in the
// collector and are bound server-side as internal/models, not in this file):
//   - v2 (R5) adds the sFlow interface counter-samples telemetry type (the
//     /probes/:id/flow-counters endpoint). The collector gates counter sends on
//     a negotiated v2, so a v1-only server never receives them.
//   - v4 adds the server→collector COMMAND CHANNEL: the heartbeat response
//     carries pending_commands (PendingCommand, declared below) and the
//     collector reports outcomes to POST /api/probes/:id/command-result
//     (CommandResultRequest, declared below). The server persists the
//     negotiated version on the Probe row at register and only attaches
//     pending_commands for probes that negotiated ≥ 4, so a v3 collector never
//     sees the field; a v4 collector against a v3 server gates its result sends
//     the same way.
//   - v5 adds L2 TOPOLOGY snapshots for the port-to-port connection map: ARP +
//     MAC-table/FDB rows to POST /probes/:id/topology-entries and LLDP/CDP rows
//     to POST /probes/:id/topology-neighbors. These are STATE snapshots —
//     ingestion REPLACES the device's rows per (device, entry_type/protocol)
//     scope. The collector gates both sends on a negotiated ≥ 5 and never
//     spools them.
//
// v1 stays supported (Min=1) throughout for mixed-version deploys.
const (
	SchemaVersionMin = 1
	SchemaVersionMax = 5
)

// PendingCommand is one queued server→collector command as delivered on the
// heartbeat response (schema v4). Payload is the command's type-specific JSON
// document — it is encrypted at rest on the server and decrypted only for
// this authenticated, HTTPS-carried delivery; it may contain credentials for
// later command types, so the collector must never log it. The collector
// executes the command (skipping any CommandID it has already executed) and
// reports the outcome via CommandResultRequest.
type PendingCommand struct {
	CommandID string    `json:"command_id"`
	DeviceID  uint      `json:"device_id"`
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CommandResultRequest is the body of POST /api/probes/:id/command-result
// (schema v4): the collector's outcome report for one PendingCommand. Status
// must be "succeeded" or "failed". Idempotent by CommandID — the server keeps
// the FIRST terminal result and no-ops replays, so collector retries and
// heartbeat redelivery races are safe.
type CommandResultRequest struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	Result    string `json:"result"`
}
