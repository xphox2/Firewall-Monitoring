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
const (
	SchemaVersionMin = 1
	SchemaVersionMax = 1
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
