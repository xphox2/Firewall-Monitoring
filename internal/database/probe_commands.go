package database

import (
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Probe command channel (relay schema v4). The server enqueues ProbeCommand
// rows; the heartbeat handler calls ClaimProbeCommands to deliver them on the
// heartbeat response; the collector reports outcomes to the command-result
// endpoint, which calls CompleteProbeCommand (idempotent by command_id).
//
// SECURITY: Payload is encrypted at rest (it will later carry credentials —
// IPSec PSKs, API secrets). EnqueueProbeCommand encrypts; ClaimProbeCommands
// decrypts only for wire delivery to the authenticated probe. Payload
// contents must never be logged — log CommandID + Type only.

// Probe command lifecycle states.
const (
	ProbeCommandStatusPending    = "pending"
	ProbeCommandStatusDispatched = "dispatched"
	ProbeCommandStatusSucceeded  = "succeeded"
	ProbeCommandStatusFailed     = "failed"
	ProbeCommandStatusExpired    = "expired"
)

// Probe command types. The enqueue endpoint allow-lists these; the collector
// refuses anything else.
const (
	// ProbeCommandTypeNoop proves the command channel round-trip: the
	// collector completes it immediately WITHOUT contacting any device.
	ProbeCommandTypeNoop = "noop"

	// ProbeCommandTypeIPSecPreflight is a READ-ONLY IPSec deploy preflight: the
	// collector authenticates to the device's REST API and GETs the objects a
	// deploy would create (name/VTI/connection collision checks), reporting a
	// structured result. It performs NO device writes (PR-C1); the actual apply
	// (apply_ipsec) is a later sub-phase.
	ProbeCommandTypeIPSecPreflight = "ipsec_preflight"
)

// probeCommandDeviceTouching lists command types whose execution makes the
// collector contact the target device (SSH/API) — i.e. whose succeeded result
// is reachability evidence that should bump the device's last_polled. noop is
// explicitly false (it never leaves the collector). A future write command
// (IPSec apply) opts in here.
var probeCommandDeviceTouching = map[string]bool{
	ProbeCommandTypeNoop:           false,
	ProbeCommandTypeIPSecPreflight: true, // a successful REST read proves reachability
}

// ProbeCommandTouchesDevice reports whether a succeeded result for the given
// command type counts as device-reachability evidence. Unknown types never do
// until explicitly added to probeCommandDeviceTouching (fail-safe default).
func ProbeCommandTouchesDevice(cmdType string) bool {
	return probeCommandDeviceTouching[cmdType]
}

const (
	// DefaultProbeCommandTTL bounds how long an undelivered/unreported command
	// stays live. A stale write command (e.g. a future apply_ipsec) firing
	// hours after the operator queued it is dangerous, so anything past
	// expires_at is terminally expired, never delivered.
	DefaultProbeCommandTTL = 15 * time.Minute

	// ProbeCommandRedeliverAfter is how long a dispatched command may sit
	// without a reported result before the next heartbeat re-delivers it
	// (at-least-once). ~3 missed heartbeats at the default 60s cadence.
	ProbeCommandRedeliverAfter = 3 * time.Minute

	// ProbeCommandMaxAttempts caps delivery attempts; past it the command is
	// marked failed so a persistently crashing executor can't loop forever.
	ProbeCommandMaxAttempts = 5

	// probeCommandResultMaxLen bounds the stored result text so a misbehaving
	// collector can't bloat the table with megabytes of output per command.
	probeCommandResultMaxLen = 10000

	// probeCommandClaimBatch caps how many commands one heartbeat response
	// carries; the remainder rides the next heartbeat (60s later).
	probeCommandClaimBatch = 20
)

// probeCommandTerminal reports whether a status is terminal (no further
// transitions; results for it are dropped as idempotent replays).
func probeCommandTerminal(status string) bool {
	switch status {
	case ProbeCommandStatusSucceeded, ProbeCommandStatusFailed, ProbeCommandStatusExpired:
		return true
	}
	return false
}

// EnqueueProbeCommand queues a command for delivery to a probe on its next
// heartbeat. Fills CommandID (UUID), Status and ExpiresAt when unset, and
// encrypts Payload at rest. The caller's cmd is updated in place (CommandID,
// ID) but Payload on the caller's struct is left as the stored (encrypted)
// form on purpose — read paths must go through ClaimProbeCommands.
func (d *Database) EnqueueProbeCommand(cmd *models.ProbeCommand) error {
	if cmd.ProbeID == 0 {
		return errors.New("EnqueueProbeCommand: probe_id required")
	}
	if cmd.Type == "" {
		return errors.New("EnqueueProbeCommand: type required")
	}
	if cmd.CommandID == "" {
		cmd.CommandID = uuid.NewString()
	}
	if cmd.ExpiresAt.IsZero() {
		cmd.ExpiresAt = time.Now().Add(DefaultProbeCommandTTL)
	}
	cmd.Status = ProbeCommandStatusPending
	cmd.Attempts = 0
	cmd.Payload = d.EncryptField(cmd.Payload)
	return d.db.Create(cmd).Error
}

// ClaimProbeCommands returns the commands to deliver on a heartbeat response
// for the given probe, flipping each pending→dispatched and incrementing
// Attempts. It also:
//
//   - terminally EXPIRES any live command past its expires_at (never delivered);
//   - RE-DELIVERS a dispatched command whose result hasn't arrived within
//     ProbeCommandRedeliverAfter (at-least-once semantics);
//   - marks a command FAILED once redelivery would exceed
//     ProbeCommandMaxAttempts.
//
// Returned commands carry the DECRYPTED payload for wire delivery to the
// authenticated probe. Runs in one transaction so concurrent heartbeats
// (shouldn't happen, but the API is multi-instance-aware) don't double-claim.
func (d *Database) ClaimProbeCommands(probeID uint) ([]models.ProbeCommand, error) {
	now := time.Now()
	var claimed []models.ProbeCommand

	err := d.db.Transaction(func(tx *gorm.DB) error {
		// Expire anything live that outlived its TTL. Terminal — a stale
		// command must never fire late.
		if err := tx.Model(&models.ProbeCommand{}).
			Where("probe_id = ? AND status IN (?, ?) AND expires_at < ?",
				probeID, ProbeCommandStatusPending, ProbeCommandStatusDispatched, now).
			Updates(map[string]interface{}{
				"status": ProbeCommandStatusExpired,
				"result": "expired before completion",
			}).Error; err != nil {
			return fmt.Errorf("expire overdue commands: %w", err)
		}

		// Select deliverables: fresh pending commands plus dispatched ones
		// whose result is overdue (redelivery). updated_at is the dispatch
		// timestamp (GORM touches it on every update).
		var cmds []models.ProbeCommand
		if err := tx.
			Where("probe_id = ? AND (status = ? OR (status = ? AND updated_at < ?))",
				probeID, ProbeCommandStatusPending, ProbeCommandStatusDispatched,
				now.Add(-ProbeCommandRedeliverAfter)).
			Order("id").
			Limit(probeCommandClaimBatch).
			Find(&cmds).Error; err != nil {
			return fmt.Errorf("select deliverable commands: %w", err)
		}

		for i := range cmds {
			cmd := &cmds[i]
			// Every mutation below is guarded on the command still being
			// non-terminal (pending/dispatched). Under READ COMMITTED the SELECT
			// above and these UPDATEs are separate reads, so a concurrent
			// command-result POST can commit `succeeded`/`failed` in between; the
			// status guard + RowsAffected check make sure we never resurrect a
			// terminal command back to `dispatched` (which would later record a
			// succeeded command as failed).
			if cmd.Attempts+1 > ProbeCommandMaxAttempts {
				if err := tx.Model(&models.ProbeCommand{}).
					Where("id = ? AND status IN (?, ?)", cmd.ID, ProbeCommandStatusPending, ProbeCommandStatusDispatched).
					Updates(map[string]interface{}{
						"status": ProbeCommandStatusFailed,
						"result": "max delivery attempts exceeded without a reported result",
					}).Error; err != nil {
					return fmt.Errorf("fail over-attempted command: %w", err)
				}
				continue
			}
			res := tx.Model(&models.ProbeCommand{}).
				Where("id = ? AND status IN (?, ?)", cmd.ID, ProbeCommandStatusPending, ProbeCommandStatusDispatched).
				Updates(map[string]interface{}{
					"status":   ProbeCommandStatusDispatched,
					"attempts": cmd.Attempts + 1,
				})
			if res.Error != nil {
				return fmt.Errorf("dispatch command: %w", res.Error)
			}
			if res.RowsAffected == 0 {
				// A concurrent result completed this command between the SELECT
				// and here — don't deliver it or burn an attempt.
				continue
			}
			cmd.Status = ProbeCommandStatusDispatched
			cmd.Attempts++
			claimed = append(claimed, *cmd)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Decrypt payloads OUTSIDE the transaction, only for wire delivery.
	for i := range claimed {
		claimed[i].Payload = d.DecryptField(claimed[i].Payload)
	}
	return claimed, nil
}

// CompleteProbeCommand records a collector-reported outcome for a command,
// idempotent by command_id: a replayed result for an already-terminal command
// is a no-op (applied=false, no error), so collector retries and heartbeat
// redelivery races can't corrupt state. The probeID scope means a probe can
// only complete its OWN commands. status must be succeeded or failed. The
// completed command row is returned (Payload still encrypted) so the caller
// can act on its DeviceID/Type — e.g. count a succeeded device-touching
// command as reachability evidence.
func (d *Database) CompleteProbeCommand(probeID uint, commandID, status, result string) (cmd models.ProbeCommand, applied bool, err error) {
	if status != ProbeCommandStatusSucceeded && status != ProbeCommandStatusFailed {
		return cmd, false, fmt.Errorf("invalid command result status %q", status)
	}
	if len(result) > probeCommandResultMaxLen {
		result = result[:probeCommandResultMaxLen]
	}

	err = d.db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Where("command_id = ? AND probe_id = ?", commandID, probeID).
			First(&cmd).Error; e != nil {
			return e
		}
		if probeCommandTerminal(cmd.Status) {
			return nil // idempotent replay — first result wins
		}
		if e := tx.Model(&models.ProbeCommand{}).Where("id = ?", cmd.ID).
			Updates(map[string]interface{}{
				"status": status,
				"result": result,
			}).Error; e != nil {
			return e
		}
		applied = true
		return nil
	})
	return cmd, applied, err
}

// GetProbeCommands lists a probe's most recent commands (newest first) for the
// admin UI. Payload stays encrypted on the returned rows AND is json:"-", so
// it can never leak through an admin response.
func (d *Database) GetProbeCommands(probeID uint, limit int) ([]models.ProbeCommand, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var cmds []models.ProbeCommand
	err := d.db.Where("probe_id = ?", probeID).
		Order("id DESC").Limit(limit).Find(&cmds).Error
	return cmds, err
}

// GetLatestCommandByDeviceType returns the most recent command of the given
// type for a device (newest first), or nil if none exists. Payload stays
// encrypted + json:"-"; the Result field (structured JSON the collector
// returned) is plaintext and safe to surface. Used by the IPSec preflight GET.
func (d *Database) GetLatestCommandByDeviceType(deviceID uint, cmdType string) (*models.ProbeCommand, error) {
	var cmd models.ProbeCommand
	err := d.db.Where("device_id = ? AND type = ?", deviceID, cmdType).
		Order("id DESC").First(&cmd).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cmd, nil
}

// ExpireStaleProbeCommands terminally expires every non-terminal command whose
// TTL has passed, across all probes. ClaimProbeCommands only expires per-probe on
// a v4 heartbeat, so a command enqueued against an offline or sub-v4 probe would
// otherwise sit non-terminal forever (and never reach the terminal-row cleanup).
// The poller calls this every monitoring cycle. Returns the number expired.
func (d *Database) ExpireStaleProbeCommands() (int64, error) {
	res := d.db.Model(&models.ProbeCommand{}).
		Where("status IN (?, ?) AND expires_at < ?",
			ProbeCommandStatusPending, ProbeCommandStatusDispatched, time.Now()).
		Updates(map[string]interface{}{
			"status": ProbeCommandStatusExpired,
			"result": "expired before completion",
		})
	return res.RowsAffected, res.Error
}

// CancelProbeCommand is the admin force-cleanup: terminally expire a still-live
// command (e.g. one wedged against an offline probe). Scoped to the probe;
// no-op (applied=false) if the command is unknown or already terminal.
func (d *Database) CancelProbeCommand(probeID uint, commandID string) (applied bool, err error) {
	res := d.db.Model(&models.ProbeCommand{}).
		Where("command_id = ? AND probe_id = ? AND status IN (?, ?)",
			commandID, probeID, ProbeCommandStatusPending, ProbeCommandStatusDispatched).
		Updates(map[string]interface{}{
			"status": ProbeCommandStatusExpired,
			"result": "cancelled by admin",
		})
	return res.RowsAffected > 0, res.Error
}
