package ipsec

// DeployState is the per-deploy record persisted on a tunnel row
// (models.IPSecTunnel.DeployJSON). It carries NO secrets: per-end apply command
// IDs plus a body-less remove-steps snapshot (DELETE paths only — no PSK) plus
// the rollback command IDs. It is the spine that makes deploy status
// TUNNEL-SCOPED (poll the exact per-end command IDs, not device+type which bleeds
// across multiple tunnels on one box) and rollback SNAPSHOT-DRIVEN (reverse
// exactly what was deployed, even after a later intent edit).
type DeployState struct {
	DeployedAt string           `json:"deployed_at,omitempty"`
	Ends       []DeployEndState `json:"ends"`
	Rollback   *RollbackState   `json:"rollback,omitempty"`
}

// DeployEndState records one deployed end: the apply command sent to its
// collector and the exact steps (+ checksum) needed to reverse it. RemoveSteps
// are body-less DELETEs (FortiGate) or POST-by-<uuid:NAME> deletes (OPNsense), so
// this struct never contains the PSK.
type DeployEndState struct {
	End            int         `json:"end"`
	DeviceID       uint        `json:"device_id"`
	Vendor         string      `json:"vendor"`
	CommandID      string      `json:"command_id"`
	RemoveSteps    []ApplyStep `json:"remove_steps"`
	RemoveChecksum string      `json:"remove_checksum"`

	// CapturedUUIDs maps a <uuid:NAME> token to the device-assigned UUID captured
	// when this end applied (OPNsense; empty for FortiGate). Merged from the apply
	// report at the terminal poll and used as the remove Substitutions so rollback
	// can delete exactly the objects that were created. Persisted (deploy_json is
	// never pruned) since the apply command result is pruned at 30d.
	CapturedUUIDs map[string]string `json:"captured_uuids,omitempty"`

	// StatusCommandID is the ipsec_status SA-liveness probe enqueued when this
	// end applied+verified (C2b-2b). The degraded poll reads it to drive the
	// tunnel to up/down; empty when the probe couldn't be built (the tunnel
	// stays degraded, SA unknown — never a guessed transition).
	StatusCommandID string `json:"status_command_id,omitempty"`

	// RollbackUnproven marks an end whose apply outcome is UNKNOWN (command
	// expired/lost/pruned) AND that captured no UUIDs — so its remove will skip
	// every step and report clean, byte-indistinguishable from an end that
	// genuinely wrote nothing. The rollback poll forces rollback_failed for a
	// marked end ("verify device"), never a clean rolled_back.
	RollbackUnproven bool `json:"rollback_unproven,omitempty"`
}

// RollbackState records the in-flight/last rollback so its terminal status is
// poll-driven (never set at POST time). Auto is set when the server triggered a
// compensating rollback after a partial/failed deploy (vs an operator POST).
type RollbackState struct {
	CommandIDs []string `json:"command_ids"`
	StartedAt  string   `json:"started_at,omitempty"`
	Auto       bool     `json:"auto,omitempty"`
}
