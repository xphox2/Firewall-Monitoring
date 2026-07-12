package database

import (
	"encoding/json"
	"fmt"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"
)

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
// (+ last_deployed_at when moving to a deployed state) without touching config.
func (d *Database) UpdateIPSecTunnelStatus(id uint, status, lastErr string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr}).Error
}

// DeleteIPSecTunnel removes a tunnel row.
func (d *Database) DeleteIPSecTunnel(id uint) error {
	return d.db.Delete(&models.IPSecTunnel{}, id).Error
}
