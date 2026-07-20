package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// ErrIPSecConcurrentDeploy is returned by TransitionIPSecDeploy when the tunnel's
// status isn't in the expected set — i.e. a concurrent deploy/rollback already
// moved it, or it's in a state that forbids the transition. Handlers map it to
// HTTP 409 so a second concurrent deploy can't double-write the device.
var ErrIPSecConcurrentDeploy = errors.New("ipsec: tunnel busy or not in a deployable state")

// IPSec tunnel persistence for the provisioning wizard. The structured
// vendor-neutral intent (ipsec.TunnelIntent) is stored as IntentJSON WITHOUT the
// PSK; the PSK lives in its own column, encrypted at rest via the field crypto,
// and is never serialized into IntentJSON or returned unmasked by handlers.

// redactedMask mirrors httputil.RedactedMask; duplicated here to keep the
// database layer from importing the http layer. A PSK equal to this on update
// means "unchanged".
const redactedMask = "********"

// IPSecIntentToModel serializes a vendor-neutral intent into a persistable row.
// The PSK is split out of IntentJSON into the (to-be-encrypted) PSK column.
func IPSecIntentToModel(t *ipsec.TunnelIntent) (*models.IPSecTunnel, error) {
	clone := *t
	clone.PSK = "" // never persist the PSK inside IntentJSON
	blob, err := json.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("marshal ipsec intent: %w", err)
	}
	return &models.IPSecTunnel{
		ID:         t.ID,
		Name:       t.Name,
		Enabled:    t.Enabled,
		ADeviceID:  t.Ends[0].DeviceID,
		BDeviceID:  t.Ends[1].DeviceID,
		AVendor:    t.Ends[0].Vendor,
		BVendor:    t.Ends[1].Vendor,
		IntentJSON: string(blob),
		PSK:        t.PSK, // plaintext here; encrypted by the store on write
	}, nil
}

// IPSecModelToIntent reconstructs the runtime intent from a stored row, folding
// the (already-decrypted) PSK back in.
func IPSecModelToIntent(m *models.IPSecTunnel) (*ipsec.TunnelIntent, error) {
	var t ipsec.TunnelIntent
	if m.IntentJSON != "" {
		if err := json.Unmarshal([]byte(m.IntentJSON), &t); err != nil {
			return nil, fmt.Errorf("unmarshal ipsec intent %d: %w", m.ID, err)
		}
	}
	t.ID = m.ID
	t.Name = m.Name
	t.Enabled = m.Enabled
	t.PSK = m.PSK
	return &t, nil
}

// CreateIPSecTunnel persists a new tunnel row, encrypting the PSK at rest.
func (d *Database) CreateIPSecTunnel(m *models.IPSecTunnel) error {
	m.PSK = d.EncryptField(m.PSK)
	if m.Status == "" {
		m.Status = "draft"
	}
	return d.db.Create(m).Error
}

// GetIPSecTunnel loads a tunnel and decrypts its PSK in place.
func (d *Database) GetIPSecTunnel(id uint) (*models.IPSecTunnel, error) {
	var m models.IPSecTunnel
	if err := d.db.First(&m, id).Error; err != nil {
		return nil, err
	}
	m.PSK = d.DecryptField(m.PSK)
	return &m, nil
}

// ListIPSecTunnels returns all tunnels (newest first). PSK is left encrypted —
// list responses never expose it.
func (d *Database) ListIPSecTunnels() ([]models.IPSecTunnel, error) {
	var ms []models.IPSecTunnel
	err := d.db.Order("id DESC").Find(&ms).Error
	for i := range ms {
		ms[i].PSK = "" // never leak even the ciphertext in a list
	}
	return ms, err
}

// UpdateIPSecTunnel updates a tunnel. A PSK equal to the redaction mask (or
// empty) is treated as "leave unchanged" so a round-tripped masked value can't
// clobber the stored secret; any other value is re-encrypted.
func (d *Database) UpdateIPSecTunnel(m *models.IPSecTunnel) error {
	fields := map[string]interface{}{
		"name":        m.Name,
		"enabled":     m.Enabled,
		"status":      m.Status,
		"last_error":  m.LastError,
		"a_device_id": m.ADeviceID,
		"b_device_id": m.BDeviceID,
		"a_vendor":    m.AVendor,
		"b_vendor":    m.BVendor,
		"intent_json": m.IntentJSON,
	}
	if m.PSK != "" && m.PSK != redactedMask {
		fields["psk"] = d.EncryptField(m.PSK)
	}
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", m.ID).Updates(fields).Error
}

// UpdateIPSecTunnelStatus is the deploy-saga fast path: set status + last_error
// without touching config or deploy state. Use MarkIPSecTunnelDeployed when a
// transition to a deployed state must also stamp last_deployed_at.
func (d *Database) UpdateIPSecTunnelStatus(id uint, status, lastErr string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr}).Error
}

// MarkIPSecTunnelDeployed sets status + last_error AND stamps last_deployed_at =
// now — the deploy-succeeded path (fixes the old UpdateIPSecTunnelStatus, whose
// doc claimed to set last_deployed_at but never did).
func (d *Database) MarkIPSecTunnelDeployed(id uint, status, lastErr string) error {
	now := time.Now()
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr, "last_deployed_at": now}).Error
}

// ClearIPSecDeployState sets status + last_error AND clears deploy_json — the
// successful-rollback path, so the tunnel becomes eligible for edit/delete again
// (the "delete-allowed-from-empty-deploy" rule).
func (d *Database) ClearIPSecDeployState(id uint, status, lastErr string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr, "deploy_json": ""}).Error
}

// SetIPSecRollbackState updates status + deploy_json only (records the rollback
// command IDs on an existing deploy record). Used when the rollback poll needs to
// persist intermediate state without touching last_deployed_at.
func (d *Database) SetIPSecRollbackState(id uint, status, deployJSON string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "deploy_json": deployJSON}).Error
}

// TransitionIPSecDeploy atomically (1) UPDATEs the tunnel's status + last_error +
// deploy_json (+ last_deployed_at when setDeployedAt), guarded on its current
// status being in fromStatuses (optimistic lock — 0 rows affected ⇒
// ErrIPSecConcurrentDeploy), and (2) enqueues each command in the SAME
// transaction. Either all of it commits or none does, so a status poll can never
// observe a deploy_json whose command rows don't exist yet, two concurrent
// deploys can't both pass the guard and double-write, and every terminal poll
// outcome (deploying/degraded/error/rolling_back) is exactly ONE guarded write —
// the caller must NEVER chain a second status/deploy_json setter after this (that
// reopens the terminal-write race). The caller pre-generates each cmd.CommandID
// and records it in deployJSON before calling.
func (d *Database) TransitionIPSecDeploy(id uint, fromStatuses []string, toStatus, lastErr, deployJSON string, setDeployedAt bool, cmds []*models.ProbeCommand) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		fields := map[string]interface{}{
			"status":      toStatus,
			"last_error":  lastErr,
			"deploy_json": deployJSON,
		}
		if setDeployedAt {
			fields["last_deployed_at"] = time.Now()
		}
		res := tx.Model(&models.IPSecTunnel{}).
			Where("id = ? AND status IN ?", id, fromStatuses).
			Updates(fields)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrIPSecConcurrentDeploy
		}
		for _, cmd := range cmds {
			if err := d.enqueueProbeCommandTx(tx, cmd); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteIPSecTunnel removes a tunnel row.
func (d *Database) DeleteIPSecTunnel(id uint) error {
	return d.db.Delete(&models.IPSecTunnel{}, id).Error
}
