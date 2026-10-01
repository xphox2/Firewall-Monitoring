package database

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Passkey (WebAuthn) persistence (migration v70). Every method except the
// login lookup (GetPasskeyByCredentialID) is scoped by admin_id, so a caller
// can never read or change another account's credentials by id alone.

// ErrPasskeyLimit is returned by CreatePasskey when the account already holds
// MaxPasskeysPerUser credentials.
var ErrPasskeyLimit = errors.New("passkey limit reached")

// ErrPasskeyDuplicate is returned by CreatePasskey when the credential id is
// already registered (to any account).
var ErrPasskeyDuplicate = errors.New("passkey already registered")

// MaxPasskeysPerUser caps the credentials one account may register.
const MaxPasskeysPerUser = 10

// GetPasskeyByCredentialID returns the credential with this raw credential id,
// or nil when none exists. The only lookup not scoped by admin_id: it is how
// a usernameless login finds the owning account.
func (d *Database) GetPasskeyByCredentialID(credentialID []byte) (*models.WebAuthnCredential, error) {
	if len(credentialID) == 0 {
		return nil, nil
	}
	var cred models.WebAuthnCredential
	err := d.db.Where("credential_id = ?", credentialID).First(&cred).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// ListPasskeys returns the account's credentials, oldest first.
func (d *Database) ListPasskeys(adminID uint) ([]models.WebAuthnCredential, error) {
	var creds []models.WebAuthnCredential
	err := d.db.Where("admin_id = ?", adminID).Order("created_at, id").Find(&creds).Error
	return creds, err
}

// CountPasskeys returns how many credentials the account holds.
func (d *Database) CountPasskeys(adminID uint) (int64, error) {
	var n int64
	err := d.db.Model(&models.WebAuthnCredential{}).Where("admin_id = ?", adminID).Count(&n).Error
	return n, err
}

// CreatePasskey stores a new credential for cred.AdminID. Inside one
// transaction it re-checks the per-account limit and the credential id's
// uniqueness (the unique index is the backstop for a concurrent insert, which
// is mapped to ErrPasskeyDuplicate as well).
func (d *Database) CreatePasskey(cred *models.WebAuthnCredential) error {
	if cred == nil || cred.AdminID == 0 || len(cred.CredentialID) == 0 {
		return errors.New("create passkey: admin id and credential id are required")
	}
	err := d.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.WebAuthnCredential{}).Where("admin_id = ?", cred.AdminID).Count(&n).Error; err != nil {
			return err
		}
		if n >= MaxPasskeysPerUser {
			return ErrPasskeyLimit
		}
		var dup int64
		if err := tx.Model(&models.WebAuthnCredential{}).Where("credential_id = ?", cred.CredentialID).Count(&dup).Error; err != nil {
			return err
		}
		if dup > 0 {
			return ErrPasskeyDuplicate
		}
		return tx.Create(cred).Error
	})
	if err != nil && !errors.Is(err, ErrPasskeyLimit) && !errors.Is(err, ErrPasskeyDuplicate) && isUniqueViolation(err) {
		return ErrPasskeyDuplicate
	}
	return err
}

// isUniqueViolation recognises a unique-constraint failure on either driver
// (Postgres SQLSTATE 23505, SQLite "UNIQUE constraint failed").
func isUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key value")
}

// RecordPasskeyUse persists the outcome of a verified assertion: the new
// signature counter, the backup-state flag and the time of use. Scoped by
// admin_id; reports whether a row was updated.
func (d *Database) RecordPasskeyUse(id, adminID uint, signCount uint32, backupState bool, usedAt time.Time) (bool, error) {
	res := d.db.Model(&models.WebAuthnCredential{}).
		Where("id = ? AND admin_id = ?", id, adminID).
		UpdateColumns(map[string]interface{}{
			"sign_count":   int64(signCount),
			"backup_state": backupState,
			"last_used_at": usedAt,
		})
	return res.RowsAffected == 1, res.Error
}

// RenamePasskey changes a credential's display name. Scoped by admin_id;
// reports whether a row matched.
func (d *Database) RenamePasskey(id, adminID uint, name string) (bool, error) {
	res := d.db.Model(&models.WebAuthnCredential{}).
		Where("id = ? AND admin_id = ?", id, adminID).
		UpdateColumn("name", name)
	return res.RowsAffected == 1, res.Error
}

// DeletePasskey removes one credential. Scoped by admin_id; reports whether a
// row was deleted.
func (d *Database) DeletePasskey(id, adminID uint) (bool, error) {
	res := d.db.Where("id = ? AND admin_id = ?", id, adminID).Delete(&models.WebAuthnCredential{})
	return res.RowsAffected == 1, res.Error
}

// DeleteAdminPasskeys removes every credential of the account and returns how
// many were deleted. Used by every reset path (D-RESET).
func (d *Database) DeleteAdminPasskeys(adminID uint) (int64, error) {
	res := d.db.Where("admin_id = ?", adminID).Delete(&models.WebAuthnCredential{})
	return res.RowsAffected, res.Error
}

// EnsureWebAuthnUserHandle sets the account's user handle to candidate if it
// has none yet, then returns the stored handle (the existing one wins, so two
// concurrent first registrations agree on one value).
func (d *Database) EnsureWebAuthnUserHandle(adminID uint, candidate []byte) ([]byte, error) {
	if len(candidate) == 0 {
		return nil, errors.New("ensure user handle: empty candidate")
	}
	if err := d.db.Model(&models.Admin{}).
		Where("id = ? AND webauthn_user_handle IS NULL", adminID).
		UpdateColumn("webauthn_user_handle", candidate).Error; err != nil {
		return nil, err
	}
	var admin models.Admin
	if err := d.db.Select("id", "webauthn_user_handle").First(&admin, adminID).Error; err != nil {
		return nil, err
	}
	if len(admin.WebAuthnUserHandle) == 0 {
		return nil, fmt.Errorf("ensure user handle: admin %d has no handle after update", adminID)
	}
	return admin.WebAuthnUserHandle, nil
}

// ListPasskeyNotices returns the account's credentials created after its
// last notice acknowledgement (all of them if it never acknowledged) — the
// "a passkey named X was added on <date>" notice.
func (d *Database) ListPasskeyNotices(adminID uint) ([]models.WebAuthnCredential, error) {
	var admin models.Admin
	if err := d.db.Select("id", "passkey_notice_seen_at").First(&admin, adminID).Error; err != nil {
		return nil, err
	}
	q := d.db.Where("admin_id = ?", adminID)
	if admin.PasskeyNoticeSeenAt != nil {
		q = q.Where("created_at > ?", *admin.PasskeyNoticeSeenAt)
	}
	var creds []models.WebAuthnCredential
	err := q.Order("created_at, id").Find(&creds).Error
	return creds, err
}

// AckPasskeyNotices marks every current notice as seen.
func (d *Database) AckPasskeyNotices(adminID uint, at time.Time) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", adminID).
		UpdateColumn("passkey_notice_seen_at", at).Error
}

// ResetAuthResult describes what ResetAuth changed.
type ResetAuthResult struct {
	AdminID          uint
	Disabled         bool
	TOTPCleared      bool
	PasskeysDeleted  int64
	PasskeysSkipped  bool // table absent (migration v70 not applied yet)
	RecoveryCodesDel int64
}

// ResetAuth is the break-glass account reset behind `fwmon-api reset-auth`:
// in ONE transaction it sets the new password hash, flags
// must_change_password, clears TOTP and recovery codes (unless keep2FA),
// deletes every passkey (unless keepPasskeys), bumps token_version and writes
// an audit_logs row. The account's disabled flag is left as it is. Returns an
// error (and changes nothing) when the username does not exist.
func (d *Database) ResetAuth(username, passwordHash string, keep2FA, keepPasskeys bool) (*ResetAuthResult, error) {
	if username == "" || passwordHash == "" {
		return nil, errors.New("reset-auth: username and password hash are required")
	}
	res := &ResetAuthResult{}
	// The credentials table only exists once v70 ran; a break-glass reset must
	// still work against an older schema (e.g. an API that failed to boot).
	hasPasskeyTable := d.db.Migrator().HasTable(&models.WebAuthnCredential{})
	err := d.db.Transaction(func(tx *gorm.DB) error {
		var admin models.Admin
		if err := tx.Where("username = ?", username).First(&admin).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("reset-auth: no user named %q", username)
			}
			return err
		}
		res.AdminID = admin.ID
		res.Disabled = admin.Disabled
		if err := tx.Model(&models.Admin{}).Where("id = ?", admin.ID).UpdateColumns(map[string]interface{}{
			"password":             passwordHash,
			"must_change_password": true,
			"token_version":        gorm.Expr("token_version + 1"),
		}).Error; err != nil {
			return err
		}
		if !keep2FA {
			if err := tx.Model(&models.Admin{}).Where("id = ?", admin.ID).UpdateColumns(map[string]interface{}{
				"totp_secret":       "",
				"totp_enabled":      false,
				"totp_confirmed_at": nil,
			}).Error; err != nil {
				return err
			}
			del := tx.Where("admin_id = ?", admin.ID).Delete(&models.AdminRecoveryCode{})
			if del.Error != nil {
				return del.Error
			}
			res.TOTPCleared = true
			res.RecoveryCodesDel = del.RowsAffected
		}
		if !keepPasskeys {
			if hasPasskeyTable {
				del := tx.Where("admin_id = ?", admin.ID).Delete(&models.WebAuthnCredential{})
				if del.Error != nil {
					return del.Error
				}
				res.PasskeysDeleted = del.RowsAffected
			} else {
				res.PasskeysSkipped = true
			}
		}
		target := fmt.Sprintf("user=%s id=%d keep_2fa=%t keep_passkeys=%t passkeys_deleted=%d",
			admin.Username, admin.ID, keep2FA, keepPasskeys, res.PasskeysDeleted)
		return tx.Create(&models.AuditLog{
			CreatedAt: time.Now(),
			Actor:     "cli:reset-auth",
			Method:    "CLI",
			Action:    "reset_auth",
			Target:    target,
			Status:    200,
			IPAddress: "local",
			UserAgent: "fwmon-api reset-auth",
		}).Error
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
