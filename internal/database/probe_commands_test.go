package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// Tests for the relay schema-v4 server→collector command channel
// (probe_commands.go): enqueue defaults, claim/dispatch semantics, expiry,
// at-least-once redelivery, the max-attempts cap, and result idempotency.

func seedCommand(t *testing.T, d *Database, probeID uint, mutate func(*models.ProbeCommand)) *models.ProbeCommand {
	t.Helper()
	cmd := &models.ProbeCommand{
		ProbeID:  probeID,
		DeviceID: 0,
		Type:     "noop",
		Payload:  `{"hello":"world"}`,
	}
	if mutate != nil {
		mutate(cmd)
	}
	if err := d.EnqueueProbeCommand(cmd); err != nil {
		t.Fatalf("EnqueueProbeCommand: %v", err)
	}
	return cmd
}

func TestEnqueueProbeCommand_Defaults(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 7, nil)

	if cmd.CommandID == "" {
		t.Error("EnqueueProbeCommand must generate a CommandID")
	}
	if cmd.Status != ProbeCommandStatusPending {
		t.Errorf("status = %q, want pending", cmd.Status)
	}
	if cmd.ExpiresAt.IsZero() {
		t.Error("EnqueueProbeCommand must default ExpiresAt")
	}

	var stored models.ProbeCommand
	if err := d.Gorm().Where("command_id = ?", cmd.CommandID).First(&stored).Error; err != nil {
		t.Fatalf("load stored command: %v", err)
	}
	// SECURITY: the payload column must not contain the plaintext. With no
	// encryption key configured (test DB) encryptField passes plaintext
	// through, so assert the ROUND-TRIP property instead when a key exists;
	// what we can always assert is that ClaimProbeCommands returns the
	// original plaintext (decrypt-on-claim).
	claimed, err := d.ClaimProbeCommands(7)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(claimed) != 1 || claimed[0].Payload != `{"hello":"world"}` {
		t.Fatalf("claimed = %+v, want 1 command with the original plaintext payload", claimed)
	}
}

// TestProbeCommandPayloadEncryptedAtRest pins the security property this
// channel exists for: with an encryption key configured, the payload column
// stores ciphertext ({enc} prefix), never the plaintext credential document,
// and ClaimProbeCommands transparently decrypts for wire delivery.
func TestProbeCommandPayloadEncryptedAtRest(t *testing.T) {
	d := NewDatabaseForTesting(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	d.encKeys = keyChain{current: key}

	const secret = `{"psk":"super-secret-psk"}`
	cmd := seedCommand(t, d, 3, func(c *models.ProbeCommand) { c.Payload = secret })

	var raw string
	if err := d.Gorm().Model(&models.ProbeCommand{}).
		Where("command_id = ?", cmd.CommandID).
		Pluck("payload", &raw).Error; err != nil {
		t.Fatalf("pluck payload: %v", err)
	}
	if raw == secret {
		t.Fatal("payload stored as PLAINTEXT — must be encrypted at rest")
	}
	if len(raw) < len(encPrefix) || raw[:len(encPrefix)] != encPrefix {
		t.Fatalf("payload %q lacks the %q encryption prefix", raw, encPrefix)
	}

	claimed, err := d.ClaimProbeCommands(3)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(claimed) != 1 || claimed[0].Payload != secret {
		t.Fatalf("claimed payload = %+v, want decrypted plaintext", claimed)
	}
}

func TestClaimProbeCommands_DispatchesAndScopes(t *testing.T) {
	d := NewDatabaseForTesting(t)
	mine := seedCommand(t, d, 1, nil)
	seedCommand(t, d, 2, nil) // another probe's command must not be claimed

	claimed, err := d.ClaimProbeCommands(1)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(claimed) != 1 || claimed[0].CommandID != mine.CommandID {
		t.Fatalf("claimed %d command(s), want exactly probe 1's", len(claimed))
	}
	if claimed[0].Status != ProbeCommandStatusDispatched || claimed[0].Attempts != 1 {
		t.Errorf("claimed status/attempts = %s/%d, want dispatched/1", claimed[0].Status, claimed[0].Attempts)
	}

	// A freshly-dispatched command must NOT be re-delivered on the next
	// heartbeat (only after ProbeCommandRedeliverAfter).
	again, err := d.ClaimProbeCommands(1)
	if err != nil {
		t.Fatalf("ClaimProbeCommands (2nd): %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("2nd claim returned %d command(s), want 0 (redelivery only after %v)", len(again), ProbeCommandRedeliverAfter)
	}
}

func TestClaimProbeCommands_ExpiresOverdue(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 5, func(c *models.ProbeCommand) {
		c.ExpiresAt = time.Now().Add(-time.Minute) // already past TTL
	})

	claimed, err := d.ClaimProbeCommands(5)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(claimed) != 0 {
		t.Fatalf("claimed %d command(s), want 0 — an expired command must NEVER be delivered", len(claimed))
	}
	var stored models.ProbeCommand
	if err := d.Gorm().Where("command_id = ?", cmd.CommandID).First(&stored).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored.Status != ProbeCommandStatusExpired {
		t.Errorf("status = %q, want expired", stored.Status)
	}
}

func TestClaimProbeCommands_RedeliversStaleDispatched(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 6, nil)
	if got, _ := d.ClaimProbeCommands(6); len(got) != 1 {
		t.Fatalf("first claim: %d, want 1", len(got))
	}

	// Backdate updated_at past the redelivery window (simulates N missed
	// heartbeats without a reported result).
	stale := time.Now().Add(-ProbeCommandRedeliverAfter - time.Minute)
	if err := d.Gorm().Model(&models.ProbeCommand{}).
		Where("command_id = ?", cmd.CommandID).
		UpdateColumn("updated_at", stale).Error; err != nil {
		t.Fatalf("backdate: %v", err)
	}

	again, err := d.ClaimProbeCommands(6)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(again) != 1 || again[0].CommandID != cmd.CommandID {
		t.Fatalf("redelivery claim = %d command(s), want the stale dispatched one", len(again))
	}
	if again[0].Attempts != 2 {
		t.Errorf("attempts = %d, want 2 after redelivery", again[0].Attempts)
	}
}

func TestClaimProbeCommands_MaxAttemptsFails(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 9, nil)

	// Simulate a command that has already burned every delivery attempt.
	stale := time.Now().Add(-ProbeCommandRedeliverAfter - time.Minute)
	if err := d.Gorm().Model(&models.ProbeCommand{}).
		Where("command_id = ?", cmd.CommandID).
		UpdateColumns(map[string]interface{}{
			"status":     ProbeCommandStatusDispatched,
			"attempts":   ProbeCommandMaxAttempts,
			"updated_at": stale,
		}).Error; err != nil {
		t.Fatalf("seed attempts: %v", err)
	}

	claimed, err := d.ClaimProbeCommands(9)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(claimed) != 0 {
		t.Fatalf("claimed %d command(s), want 0 past the attempt cap", len(claimed))
	}
	var stored models.ProbeCommand
	if err := d.Gorm().Where("command_id = ?", cmd.CommandID).First(&stored).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored.Status != ProbeCommandStatusFailed {
		t.Errorf("status = %q, want failed after exceeding %d attempts", stored.Status, ProbeCommandMaxAttempts)
	}
}

func TestCompleteProbeCommand_IdempotentByCommandID(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 4, nil)
	if got, _ := d.ClaimProbeCommands(4); len(got) != 1 {
		t.Fatalf("claim: %d, want 1", len(got))
	}

	applied, err := d.CompleteProbeCommand(4, cmd.CommandID, ProbeCommandStatusSucceeded, "ok")
	if err != nil || !applied {
		t.Fatalf("first result: applied=%v err=%v, want applied=true", applied, err)
	}

	// Replay (collector retry / redelivery race): must be a NO-OP that keeps
	// the first result — even a conflicting one.
	applied, err = d.CompleteProbeCommand(4, cmd.CommandID, ProbeCommandStatusFailed, "late duplicate")
	if err != nil {
		t.Fatalf("replay result: %v", err)
	}
	if applied {
		t.Error("replayed result was applied — must be idempotent by command_id")
	}
	var stored models.ProbeCommand
	if err := d.Gorm().Where("command_id = ?", cmd.CommandID).First(&stored).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored.Status != ProbeCommandStatusSucceeded || stored.Result != "ok" {
		t.Errorf("stored status/result = %s/%q, want the FIRST result (succeeded/ok)", stored.Status, stored.Result)
	}

	// Wrong probe scope: another probe cannot complete this command.
	if _, err := d.CompleteProbeCommand(999, cmd.CommandID, ProbeCommandStatusSucceeded, ""); err == nil {
		t.Error("completing another probe's command must error (record not found)")
	}

	// Invalid status is rejected.
	if _, err := d.CompleteProbeCommand(4, cmd.CommandID, "running", ""); err == nil {
		t.Error("invalid result status must be rejected")
	}
}

// TestExpireStaleProbeCommands: the global sweep terminally expires any
// non-terminal command past its TTL — for probes that are offline/pre-v4 and so
// never claim (where per-heartbeat expiry can't run).
func TestExpireStaleProbeCommands(t *testing.T) {
	d := NewDatabaseForTesting(t)
	fresh := seedCommand(t, d, 11, func(c *models.ProbeCommand) { c.ExpiresAt = time.Now().Add(time.Hour) })
	stale := seedCommand(t, d, 11, func(c *models.ProbeCommand) { c.ExpiresAt = time.Now().Add(-time.Minute) })

	n, err := d.ExpireStaleProbeCommands()
	if err != nil {
		t.Fatalf("ExpireStaleProbeCommands: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired %d, want 1 (only the past-TTL command)", n)
	}
	var gotStale, gotFresh models.ProbeCommand
	d.Gorm().Where("command_id = ?", stale.CommandID).First(&gotStale)
	if gotStale.Status != ProbeCommandStatusExpired {
		t.Errorf("stale command status = %q, want expired", gotStale.Status)
	}
	d.Gorm().Where("command_id = ?", fresh.CommandID).First(&gotFresh)
	if gotFresh.Status != ProbeCommandStatusPending {
		t.Errorf("fresh command status = %q, want pending (untouched)", gotFresh.Status)
	}
}

// TestCancelProbeCommand: admin force-cleanup expires a live command, is
// probe-scoped, and is a no-op once terminal.
func TestCancelProbeCommand(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 12, nil)

	if applied, err := d.CancelProbeCommand(12, cmd.CommandID); err != nil || !applied {
		t.Fatalf("cancel live command: applied=%v err=%v, want true/nil", applied, err)
	}
	var got models.ProbeCommand
	d.Gorm().Where("command_id = ?", cmd.CommandID).First(&got)
	if got.Status != ProbeCommandStatusExpired || got.Result != "cancelled by admin" {
		t.Errorf("cancelled command = %q/%q, want expired/'cancelled by admin'", got.Status, got.Result)
	}
	// Second cancel is a no-op (already terminal).
	if applied, _ := d.CancelProbeCommand(12, cmd.CommandID); applied {
		t.Error("cancelling an already-terminal command must be a no-op")
	}
	// Wrong probe scope.
	other := seedCommand(t, d, 12, nil)
	if applied, _ := d.CancelProbeCommand(999, other.CommandID); applied {
		t.Error("cancelling another probe's command must be a no-op")
	}
}

// TestClaimProbeCommands_TerminalNotResurrected: a command that completed
// (succeeded) is never re-delivered or flipped back to dispatched — the
// status-guarded claim UPDATE is what protects the race between the claim SELECT
// and a concurrent result POST.
func TestClaimProbeCommands_TerminalNotResurrected(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cmd := seedCommand(t, d, 13, nil)
	// Simulate a dispatched-then-redelivery-eligible command that then completes.
	d.Gorm().Model(&models.ProbeCommand{}).Where("id = ?", cmd.ID).
		Updates(map[string]interface{}{"status": ProbeCommandStatusDispatched, "updated_at": time.Now().Add(-time.Hour)})
	if _, err := d.CompleteProbeCommand(13, cmd.CommandID, ProbeCommandStatusSucceeded, "done"); err != nil {
		t.Fatalf("CompleteProbeCommand: %v", err)
	}

	claimed, err := d.ClaimProbeCommands(13)
	if err != nil {
		t.Fatalf("ClaimProbeCommands: %v", err)
	}
	if len(claimed) != 0 {
		t.Fatalf("claimed %d, want 0 (a succeeded command must not be re-delivered)", len(claimed))
	}
	var got models.ProbeCommand
	d.Gorm().Where("command_id = ?", cmd.CommandID).First(&got)
	if got.Status != ProbeCommandStatusSucceeded {
		t.Errorf("status = %q, want succeeded (never resurrected to dispatched)", got.Status)
	}
}
