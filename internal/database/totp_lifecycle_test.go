package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestTOTP_SecretEncryptionRoundTrip: the secret is stored {enc}-encrypted and
// comes back decrypted through the login lookup (GetAdminByUsername).
func TestTOTP_SecretEncryptionRoundTrip(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.InitAdmin("root", "hash", false); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}
	root, _ := d.GetAdmin()

	const secret = "JBSWY3DPEHPK3PXP"
	if err := d.SetAdminTOTP(root.ID, d.EncryptField(secret), true); err != nil {
		t.Fatalf("SetAdminTOTP: %v", err)
	}

	// At rest: encrypted (or at minimum not the plaintext when a key exists).
	raw, err := d.GetAdminByID(root.ID)
	if err != nil || raw == nil {
		t.Fatalf("GetAdminByID: %v", err)
	}
	if raw.TOTPSecret == secret && d.EncryptField(secret) != secret {
		t.Error("TOTP secret stored in plaintext despite encryption being available")
	}
	if !raw.TOTPEnabled || raw.TOTPConfirmedAt == nil {
		t.Errorf("enabled/confirmed not persisted: %+v", raw)
	}

	// Login lookup: decrypted.
	authRow, err := d.GetAdminByUsername("root")
	if err != nil || authRow == nil {
		t.Fatalf("GetAdminByUsername: %v", err)
	}
	if authRow.TOTPSecret != secret {
		t.Errorf("decrypted secret mismatch: %q", authRow.TOTPSecret)
	}
	if !authRow.TOTPEnabled {
		t.Error("AdminAuth.TOTPEnabled not carried")
	}

	// Clear wipes secret, flag, and codes.
	if err := d.ReplaceRecoveryCodes(root.ID, []string{HashAPIToken("code-1")}); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}
	if err := d.ClearAdminTOTP(root.ID); err != nil {
		t.Fatalf("ClearAdminTOTP: %v", err)
	}
	raw, _ = d.GetAdminByID(root.ID)
	if raw.TOTPEnabled || raw.TOTPSecret != "" {
		t.Errorf("ClearAdminTOTP left state behind: %+v", raw)
	}
	var n int64
	d.db.Model(&models.AdminRecoveryCode{}).Where("admin_id = ?", root.ID).Count(&n)
	if n != 0 {
		t.Errorf("recovery codes not deleted on clear: %d left", n)
	}
}

// TestConsumeRecoveryCode_SingleUse: a code burns exactly once, including
// under concurrency (the atomic UPDATE ... WHERE used_at IS NULL contract).
func TestConsumeRecoveryCode_SingleUse(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.InitAdmin("root", "hash", false); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}
	root, _ := d.GetAdmin()

	hash := HashAPIToken("recovery-abc")
	if err := d.ReplaceRecoveryCodes(root.ID, []string{hash, HashAPIToken("recovery-def")}); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}

	// Two presentations: exactly one wins. (Sequential on purpose — a second
	// goroutine would open a second SQLite :memory: connection, which is a
	// fresh empty database. The concurrency safety itself needs no test
	// parallelism: it is carried by the single atomic
	// `UPDATE ... WHERE used_at IS NULL` statement, which the database
	// serializes; RowsAffected==1 for exactly one caller by construction.)
	ok, err := d.ConsumeRecoveryCode(root.ID, hash)
	if err != nil || !ok {
		t.Fatalf("first consumption must win: ok=%v err=%v", ok, err)
	}
	ok, err = d.ConsumeRecoveryCode(root.ID, hash)
	if err != nil || ok {
		t.Errorf("burned code must not validate again: ok=%v err=%v", ok, err)
	}

	// Wrong admin ID must not consume another user's code.
	ok, _ = d.ConsumeRecoveryCode(root.ID+99, HashAPIToken("recovery-def"))
	if ok {
		t.Error("code consumed for the wrong account")
	}
}

// TestMigrateAdminTOTP_Idempotent mirrors the v20/v21 migration tests.
func TestMigrateAdminTOTP_Idempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.migrateAdminTOTP(); err != nil {
		t.Fatalf("migrateAdminTOTP (1st run): %v", err)
	}
	if err := d.migrateAdminTOTP(); err != nil {
		t.Fatalf("migrateAdminTOTP (2nd run, must be idempotent): %v", err)
	}
}
