package database

import (
	"time"

	"firewall-mon/internal/models"
)

// TOTP persistence (P0-3). The shared secret is stored {enc}-encrypted (the
// caller passes it through EncryptField); recovery codes reuse the sha256:
// at-rest scheme via HashAPIToken's sibling here — same construction, its own
// call sites so the credential domains stay legible.

// SetAdminTOTP stores the (already encrypted) secret and the enabled flag.
// Enrollment writes (encSecret, false) at setup and flips to true on verify.
func (d *Database) SetAdminTOTP(id uint, encSecret string, enabled bool) error {
	updates := map[string]interface{}{
		"totp_secret":  encSecret,
		"totp_enabled": enabled,
	}
	if enabled {
		now := time.Now()
		updates["totp_confirmed_at"] = &now
	}
	return d.db.Model(&models.Admin{}).Where("id = ?", id).UpdateColumns(updates).Error
}

// ClearAdminTOTP disables 2FA and deletes the account's recovery codes (used
// by self-service disable and the admin-only reset).
func (d *Database) ClearAdminTOTP(id uint) error {
	if err := d.db.Model(&models.Admin{}).Where("id = ?", id).UpdateColumns(map[string]interface{}{
		"totp_secret":       "",
		"totp_enabled":      false,
		"totp_confirmed_at": nil,
	}).Error; err != nil {
		return err
	}
	return d.db.Where("admin_id = ?", id).Delete(&models.AdminRecoveryCode{}).Error
}

// ReplaceRecoveryCodes swaps the full set (hashes only — plaintext is shown
// once by the handler and never stored).
func (d *Database) ReplaceRecoveryCodes(adminID uint, hashes []string) error {
	if err := d.db.Where("admin_id = ?", adminID).Delete(&models.AdminRecoveryCode{}).Error; err != nil {
		return err
	}
	rows := make([]models.AdminRecoveryCode, len(hashes))
	for i, h := range hashes {
		rows[i] = models.AdminRecoveryCode{AdminID: adminID, CodeHash: h}
	}
	if len(rows) == 0 {
		return nil
	}
	return d.db.Create(&rows).Error
}

// ConsumeRecoveryCode atomically burns a code: the UPDATE only matches an
// unused row, so of two concurrent presentations exactly one sees
// RowsAffected==1. Returns whether the code was valid-and-unused.
func (d *Database) ConsumeRecoveryCode(adminID uint, codeHash string) (bool, error) {
	res := d.db.Model(&models.AdminRecoveryCode{}).
		Where("admin_id = ? AND code_hash = ? AND used_at IS NULL", adminID, codeHash).
		Update("used_at", time.Now())
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}
