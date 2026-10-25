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
	// DiscoveryCommandID is the READ-ONLY probe that located (or is locating)
	// this tunnel's objects on the device.
	//
	// It exists for the vendors whose removal deletes objects by their
	// device-assigned UUID (OPNsense): when the apply's captured UUIDs are
	// gone, the only way to clean the device is to ASK the device what it
	// holds. The probe changes nothing — it only tells the server which UUIDs
	// the objects have, so the removal can address them.
	DiscoveryCommandID string `json:"discovery_command_id,omitempty"`
	// DiscoveryEnd is the deploy end the discovery probe looked up on.
	DiscoveryEnd int `json:"discovery_end,omitempty"`
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

// PreflightState is the per-preflight record persisted on a tunnel row
// (models.IPSecTunnel.PreflightJSON). Like DeployState it makes preflight status
// polling TUNNEL-SCOPED: it records the exact per-end preflight command ID from
// the latest run so GetIPSecPreflightResult reads each end's own command
// (GetProbeCommandByCommandID) rather than the device's latest preflight command,
// which would bleed across two tunnels on one box. It carries NO secrets.
type PreflightState struct {
	EnqueuedAt string              `json:"enqueued_at,omitempty"`
	Ends       []PreflightEndState `json:"ends"`
}

// PreflightEndState records one end's preflight command for the latest run.
type PreflightEndState struct {
	End       int    `json:"end"`
	DeviceID  uint   `json:"device_id"`
	CommandID string `json:"command_id"`
}

// RollbackEndState records ONE end's rollback outcome.
//
// The IPSec subsystem has no notion of a "retired" peer: a decommissioned
// FortiGate is still a device row (soft-retired) or is gone entirely (purged),
// and neither can be cleaned — there is nothing left to send a remove command
// to. Treating that as a rollback FAILURE aborted the whole rollback, so the
// LIVE end (the OPNsense) never got cleaned either and the tunnel stayed
// "provisioned" forever, re-manufacturing a phantom peer on every telemetry
// cycle.
//
// Skipped marks an end that CANNOT be rolled back because its device no longer
// exists (retired or purged). Nothing can clean a device that no longer
// exists, so its absence is NOT a rollback failure — it counts as done and its
// reason is surfaced on the terminal.
//
// FailReason records why an end that WAS attempted could not be (e.g. a live
// device with no collector assigned). Such an end is a genuine failure: the
// device is still there and still holds objects.
type RollbackEndState struct {
	End      int  `json:"end"`
	DeviceID uint `json:"device_id"`
	// CommandID is the remove command enqueued for this end. Empty when the end
	// was skipped or could not be built.
	CommandID string `json:"command_id,omitempty"`
	// Skipped marks an end that CANNOT be rolled back because its device is
	// gone (retired or purged). Nothing can clean a device that no longer
	// exists, so its absence is NOT a rollback failure.
	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
	// FailReason records why an attempted end could not be rolled back. Only
	// meaningful when Skipped is false and CommandID is empty.
	FailReason string `json:"fail_reason,omitempty"`
}

// RollbackState records the in-flight/last rollback so its terminal status is
// poll-driven (never set at POST time). Auto is set when the server triggered a
// compensating rollback after a partial/failed deploy (vs an operator POST).
type RollbackState struct {
	// CommandIDs is the LEGACY form: index-aligned with DeployState.Ends.
	// Records written before per-end rollbacks carry it and no Ends. It is
	// now READ-ONLY (the legacy fallback path) — Ends is authoritative.
	CommandIDs []string `json:"command_ids"`
	StartedAt  string   `json:"started_at,omitempty"`
	Auto       bool     `json:"auto,omitempty"`
	// Ends is the authoritative per-end rollback record. Empty on records
	// written before this change → the terminal evaluation falls back to the
	// index-aligned CommandIDs path. No schema migration: deploy_json is a text
	// column and the new field is additive.
	Ends []RollbackEndState `json:"ends,omitempty"`
}
