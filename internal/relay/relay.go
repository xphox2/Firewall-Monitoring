// Package relay holds the cross-repo probe↔server wire contract: the
// schema-version handshake constants and the JSON DTO definitions that mirror
// what the remote collector (the separate Firewall-Collector repo) sends and
// receives. These are the human-readable source of truth referenced by
// MIGRATING.md and docs/SUPPORT-MATRIX.md.
//
// The server consumes only SchemaVersionMin/SchemaVersionMax (see
// internal/api/handlers/handlers_probes.go); the DTO structs document the wire
// format. The bundled probe *client* (RelayClient and its send/registration
// machinery) was removed — the production probe is the Firewall-Collector repo,
// and the in-repo cmd/probe was a stale fork that no longer ships.
package relay

import "time"

// Schema-version handshake. SchemaVersion is the relay-wire-format version the
// probe speaks; the server rejects anything outside [SchemaVersionMin,
// SchemaVersionMax] with HTTP 426 (Upgrade Required) and advertises the
// supported range in the X-Probe-Schema-Version-Supported header. These MUST
// stay in lockstep with the same constants in the Firewall-Collector repo.
// v2 (R5) adds the sFlow interface counter-samples telemetry type (the
// /probes/:id/flow-counters endpoint). The collector gates counter sends on a
// negotiated v2, so a v1-only server never receives them. v1 stays supported
// (Min=1) for mixed-version deploys.
// v4 adds the server→collector COMMAND CHANNEL: the heartbeat response
// carries `pending_commands` (PendingCommand) and the collector reports
// outcomes to POST /api/probes/:id/command-result (CommandResultRequest).
// The server persists the negotiated version on the Probe row at register
// and only attaches pending_commands for probes that negotiated ≥ 4, so a
// v3 collector never sees the new field; a v4 collector against a v3 server
// gates its result sends the same way. v1–v3 stay supported (Min=1).
// v5 adds L2 TOPOLOGY snapshots for the port-to-port connection map:
// TopologyEntry rows (ARP + MAC-table/FDB) to POST /probes/:id/topology-entries
// and TopologyNeighbor rows (LLDP/CDP) to POST /probes/:id/topology-neighbors.
// These are STATE snapshots — ingestion REPLACES the device's rows per
// (device, entry_type/protocol) scope. The collector gates both sends on a
// negotiated ≥ 5 and never spools them. v1–v4 stay supported (Min=1).
const (
	SchemaVersionMin = 1
	SchemaVersionMax = 5
)

type TrapEvent struct {
	ID        uint      `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	DeviceID  uint      `json:"device_id"`
	ProbeID   uint      `json:"probe_id"`
	SourceIP  string    `json:"source_ip"`
	TrapOID   string    `json:"trap_oid"`
	TrapType  string    `json:"trap_type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
}

type PingResult struct {
	ID           uint      `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id"`
	ProbeID      uint      `json:"probe_id"`
	TargetIP     string    `json:"target_ip"`
	Success      bool      `json:"success"`
	Latency      float64   `json:"latency"`
	PacketLoss   float64   `json:"packet_loss"`
	TTL          int       `json:"ttl"`
	ErrorMessage string    `json:"error_message"`
}

type SyslogMessage struct {
	ID             uint      `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"app_name"`
	ProcessID      string    `json:"process_id"`
	MessageID      string    `json:"message_id"`
	StructuredData string    `json:"structured_data"`
	Message        string    `json:"message"`
	Priority       int       `json:"priority"`
	Facility       int       `json:"facility"`
	Severity       int       `json:"severity"`
	SourceIP       string    `json:"source_ip"`
}

type FlowSample struct {
	ID              uint      `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	DeviceID        uint      `json:"device_id"`
	ProbeID         uint      `json:"probe_id"`
	SamplerAddress  string    `json:"sampler_address"`
	SequenceNumber  uint32    `json:"sequence_number"`
	SamplingRate    uint32    `json:"sampling_rate"`
	SamplePool      uint32    `json:"sample_pool"`
	SampleAlgorithm uint8     `json:"sample_algorithm"`
	EngineID        uint8     `json:"engine_id"`
	EngineType      uint8     `json:"engine_type"`
	SrcAddr         string    `json:"src_addr"`
	DstAddr         string    `json:"dst_addr"`
	SrcPort         uint16    `json:"src_port"`
	DstPort         uint16    `json:"dst_port"`
	Protocol        uint8     `json:"protocol"`
	Bytes           uint64    `json:"bytes"`
	Packets         uint64    `json:"packets"`
	InputIfIndex    uint32    `json:"input_if_index"`
	OutputIfIndex   uint32    `json:"output_if_index"`
	SrcAS           uint32    `json:"src_as"`
	DstAS           uint32    `json:"dst_as"`
	SrcMask         uint8     `json:"src_mask"`
	DstMask         uint8     `json:"dst_mask"`
	TOS             uint8     `json:"tos"`
	TCPFlags        uint8     `json:"tcp_flags"`
	// Drops is the sFlow v5 §3.1.1 sample-pool drops counter (RFC 3176):
	// the running count of packets the agent had to discard between this
	// sample and the previous one because it couldn't keep up. Added to
	// the wire contract in v0.10.473 (collector v1.2.131); omitempty
	// keeps the contract forward-compatible — pre-adopting collectors
	// see no `drops` key and continue to function unchanged.
	Drops uint64 `json:"drops,omitempty"`
}

type RegistrationRequest struct {
	RegistrationKey string `json:"registration_key"`
	ProbeName       string `json:"probe_name"`
	SiteID          uint   `json:"site_id"`
	// SchemaVersion is the relay-wire-format version the probe speaks.
	// Zero / absent is treated as v1 (the pre-handshake format) so
	// already-deployed collectors keep working unchanged. The server
	// rejects anything outside [SchemaVersionMin, SchemaVersionMax] with
	// HTTP 426 (Upgrade Required).
	SchemaVersion int `json:"schema_version,omitempty"`
}

type RegistrationResponse struct {
	Approved bool   `json:"approved"`
	ProbeID  uint   `json:"probe_id"`
	Message  string `json:"message"`
	// SchemaVersion is the version the server has *selected* for this
	// probe. Pre-handshake servers may not return it at all (zero value),
	// in which case the collector must assume v1. On rejection the
	// /api/probes/register endpoint also advertises the supported range in
	// the X-Probe-Schema-Version-Supported response header.
	SchemaVersion int `json:"schema_version,omitempty"`
}

type HeartbeatRequest struct {
	ProbeID uint   `json:"probe_id"`
	Status  string `json:"status"`
	// ObservedHostKeys maps device ID -> the SSH host-key fingerprint the probe
	// last observed for it (SSH host-key change detection). Optional.
	ObservedHostKeys map[uint]string `json:"observed_host_keys,omitempty"`
}

// HeartbeatResponse documents the heartbeat reply (schema v4+). Pre-v4 the
// reply was just {"success": true}; v4 adds PendingCommands, attached ONLY
// for probes whose registered schema_version is ≥ 4. Selecting a command for
// delivery flips it pending→dispatched server-side; an unacknowledged
// dispatched command is re-delivered on a later heartbeat (at-least-once —
// the collector must dedupe by CommandID).
type HeartbeatResponse struct {
	Success         bool             `json:"success"`
	PendingCommands []PendingCommand `json:"pending_commands,omitempty"`
}

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

type DeviceInfo struct {
	ID              uint   `json:"id"`
	Name            string `json:"name"`
	IPAddress       string `json:"ip_address"`
	SNMPPort        int    `json:"snmp_port"`
	SNMPCommunity   string `json:"snmp_community"`
	SNMPVersion     string `json:"snmp_version"`
	SNMPV3Username  string `json:"snmpv3_username"`
	SNMPV3AuthType  string `json:"snmpv3_auth_type"`
	SNMPV3AuthPass  string `json:"snmpv3_auth_pass"`
	SNMPV3PrivType  string `json:"snmpv3_priv_type"`
	SNMPV3PrivPass  string `json:"snmpv3_priv_pass"`
	Enabled         bool   `json:"enabled"`
	Vendor          string `json:"vendor"`
	SSHUsername     string `json:"ssh_username"`
	SSHPassword     string `json:"ssh_password"`
	SSHPort         int    `json:"ssh_port"`
	SSHPollEnabled  bool   `json:"ssh_poll_enabled"`
	SSHPollInterval int    `json:"ssh_poll_interval"`
}

type DevicesResponse struct {
	Success bool         `json:"success"`
	Data    []DeviceInfo `json:"data"`
}

type ConfigRevision struct {
	ID         uint      `json:"id"`
	DeviceID   uint      `json:"device_id"`
	Timestamp  time.Time `json:"timestamp"`
	Checksum   string    `json:"checksum"`
	ConfigText string    `json:"config_text"`
	Length     int       `json:"length"`
}

type ProcessSnapshot struct {
	ID        uint          `json:"id"`
	DeviceID  uint          `json:"device_id"`
	Timestamp time.Time     `json:"timestamp"`
	Processes []ProcessInfo `json:"processes"`
}

type ProcessInfo struct {
	Name    string  `json:"name"`
	PID     int     `json:"pid"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"mem"`
	Command string  `json:"command"`
}

type InterfaceErrorSnapshot struct {
	ID          uint      `json:"id"`
	DeviceID    uint      `json:"device_id"`
	Timestamp   time.Time `json:"timestamp"`
	Interface   string    `json:"interface"`
	InErrors    uint64    `json:"in_errors"`
	InDiscards  uint64    `json:"in_discards"`
	OutErrors   uint64    `json:"out_errors"`
	OutDiscards uint64    `json:"out_discards"`
}
