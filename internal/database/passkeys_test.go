package database

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"
)

func pkAdmin(t *testing.T, d *Database, name string) *models.Admin {
	t.Helper()
	a := &models.Admin{Username: name, Password: "old-hash", Role: auth.RoleOperator}
	if err := d.CreateAdmin(a); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	return a
}

func pkCred(t *testing.T, d *Database, adminID uint, id string) *models.WebAuthnCredential {
	t.Helper()
	c := &models.WebAuthnCredential{AdminID: adminID, CredentialID: []byte(id), PublicKey: []byte{1, 2, 3}, Name: strings.ToValidUTF8(strings.ReplaceAll(id, "\x00", ""), ""), CreatedAt: time.Now()}
	if err := d.CreatePasskey(c); err != nil {
		t.Fatalf("CreatePasskey(%s): %v", id, err)
	}
	return c
}

func countCreds(t *testing.T, d *Database, adminID uint) int64 {
	t.Helper()
	n, err := d.CountPasskeys(adminID)
	if err != nil {
		t.Fatalf("CountPasskeys: %v", err)
	}
	return n
}

// TestDeleteAdmin_RemovesPasskeys: deleting a user deletes its passkeys in the
// same transaction (SQLite enforces no FK), leaving other users' alone.
func TestDeleteAdmin_RemovesPasskeys(t *testing.T) {
	d := NewDatabaseForTesting(t)
	testDeleteAdminRemovesPasskeys(t, d)
}

func testDeleteAdminRemovesPasskeys(t *testing.T, d *Database) {
	gone, kept := pkAdmin(t, d, "gone"), pkAdmin(t, d, "kept")
	pkCred(t, d, gone.ID, "g1")
	pkCred(t, d, gone.ID, "g2")
	pkCred(t, d, kept.ID, "k1")
	if err := d.DeleteAdmin(gone.ID); err != nil {
		t.Fatalf("DeleteAdmin: %v", err)
	}
	var orphans int64
	d.db.Model(&models.WebAuthnCredential{}).Where("admin_id = ?", gone.ID).Count(&orphans)
	if orphans != 0 {
		t.Fatalf("deleted user still has %d passkeys", orphans)
	}
	if n := countCreds(t, d, kept.ID); n != 1 {
		t.Fatalf("other user's passkeys changed: %d", n)
	}
}

// TestPasskeyStore_ScopedAndLimits: rename/delete/use are scoped by
// admin_id; duplicates and the 11th credential are refused.
func TestPasskeyStore_ScopedAndLimits(t *testing.T) {
	d := NewDatabaseForTesting(t)
	a, b := pkAdmin(t, d, "a"), pkAdmin(t, d, "b")
	ca := pkCred(t, d, a.ID, "a1")

	if ok, err := d.RenamePasskey(ca.ID, b.ID, "x"); err != nil || ok {
		t.Fatalf("rename across accounts: ok=%v err=%v", ok, err)
	}
	if ok, err := d.DeletePasskey(ca.ID, b.ID); err != nil || ok {
		t.Fatalf("delete across accounts: ok=%v err=%v", ok, err)
	}
	if ok, err := d.RecordPasskeyUse(ca.ID, b.ID, 9, true, time.Now()); err != nil || ok {
		t.Fatalf("use across accounts: ok=%v err=%v", ok, err)
	}
	if err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: b.ID, CredentialID: []byte("a1"), PublicKey: []byte{1}}); !errors.Is(err, ErrPasskeyDuplicate) {
		t.Fatalf("duplicate credential id: %v", err)
	}
	for i := 1; i < MaxPasskeysPerUser; i++ {
		pkCred(t, d, a.ID, "a-extra-"+string(rune('a'+i)))
	}
	if err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: a.ID, CredentialID: []byte("eleven"), PublicKey: []byte{1}}); !errors.Is(err, ErrPasskeyLimit) {
		t.Fatalf("11th credential: %v", err)
	}
	h1, err := d.EnsureWebAuthnUserHandle(a.ID, bytes.Repeat([]byte{7}, 64))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := d.EnsureWebAuthnUserHandle(a.ID, bytes.Repeat([]byte{9}, 64))
	if err != nil || !bytes.Equal(h1, h2) || h1[0] != 7 {
		t.Fatalf("handle must be set once and kept: %x / %x (%v)", h1[:2], h2[:2], err)
	}
}

// TestResetAuth: the break-glass reset sets the password, forces a change,
// clears 2FA + recovery codes, deletes passkeys, bumps token_version and
// audits — and the --keep flags keep exactly what they name.
func TestResetAuth(t *testing.T) {
	d := NewDatabaseForTesting(t)
	testResetAuth(t, d)
}

func testResetAuth(t *testing.T, d *Database) {
	type state struct {
		pw         string
		must       bool
		totp       bool
		codes      int64
		creds      int64
		tokVersion uint
	}
	read := func(id uint) state {
		a, err := d.GetAdminByID(id)
		if err != nil || a == nil {
			t.Fatalf("GetAdminByID: %v", err)
		}
		var codes int64
		d.db.Model(&models.AdminRecoveryCode{}).Where("admin_id = ?", id).Count(&codes)
		return state{a.Password, a.MustChangePassword, a.TOTPEnabled, codes, countCreds(t, d, id), a.TokenVersion}
	}
	setup := func(name string) *models.Admin {
		a := pkAdmin(t, d, name)
		if err := d.SetAdminTOTP(a.ID, "secret", true); err != nil {
			t.Fatal(err)
		}
		if err := d.ReplaceRecoveryCodes(a.ID, []string{name + "-c1", name + "-c2"}); err != nil {
			t.Fatal(err)
		}
		pkCred(t, d, a.ID, name+"-k1")
		pkCred(t, d, a.ID, name+"-k2")
		return a
	}

	full, keep2fa, keepPK, other := setup("full"), setup("keep2fa"), setup("keeppk"), setup("other")

	if _, err := d.ResetAuth("nobody", "h", false, false); err == nil || !strings.Contains(err.Error(), "no user") {
		t.Fatalf("unknown user: %v", err)
	}

	res, err := d.ResetAuth("full", "new-hash", false, false)
	if err != nil {
		t.Fatalf("ResetAuth: %v", err)
	}
	if got := read(full.ID); got.pw != "new-hash" || !got.must || got.totp || got.codes != 0 || got.creds != 0 || got.tokVersion != 1 {
		t.Fatalf("full reset state = %+v", got)
	}
	if res.PasskeysDeleted != 2 || !res.TOTPCleared || res.AdminID != full.ID {
		t.Fatalf("result = %+v", res)
	}

	if _, err := d.ResetAuth("keep2fa", "h2", true, false); err != nil {
		t.Fatal(err)
	}
	if got := read(keep2fa.ID); !got.totp || got.codes != 2 || got.creds != 0 || !got.must {
		t.Fatalf("--keep-2fa state = %+v", got)
	}
	if _, err := d.ResetAuth("keeppk", "h3", false, true); err != nil {
		t.Fatal(err)
	}
	if got := read(keepPK.ID); got.totp || got.codes != 0 || got.creds != 2 {
		t.Fatalf("--keep-passkeys state = %+v", got)
	}
	if got := read(other.ID); got.pw != "old-hash" || got.must || !got.totp || got.codes != 2 || got.creds != 2 || got.tokVersion != 0 {
		t.Fatalf("an unrelated account changed: %+v", got)
	}
	var audits []models.AuditLog
	d.db.Where("action = ?", "reset_auth").Find(&audits)
	if len(audits) != 3 || audits[0].Actor != "cli:reset-auth" || !strings.Contains(audits[0].Target, "user=full") {
		t.Fatalf("audit rows = %+v", audits)
	}
}

// TestMigratePasskeys_RerunOnPartialSchema (SQLite): v70 completes on a
// schema where only part of it exists, and re-running it is a no-op.
func TestMigratePasskeys_RerunOnPartialSchema(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for _, stmt := range []string{
		`DROP TABLE webauthn_credentials`,
		`DROP INDEX IF EXISTS idx_admins_webauthn_user_handle`,
		`ALTER TABLE login_attempts DROP COLUMN method`,
	} {
		if err := d.db.Exec(stmt).Error; err != nil {
			t.Fatalf("simulate partial schema (%s): %v", stmt, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := d.migratePasskeys(); err != nil {
			t.Fatalf("migratePasskeys run %d: %v", i+1, err)
		}
	}
	m := d.db.Migrator()
	if !m.HasTable(&models.WebAuthnCredential{}) || !m.HasColumn(&models.LoginAttempt{}, "method") ||
		!m.HasColumn(&models.Admin{}, "webauthn_user_handle") || !m.HasIndex(&models.Admin{}, "idx_admins_webauthn_user_handle") ||
		!m.HasIndex(&models.WebAuthnCredential{}, "idx_webauthn_credentials_credential_id") {
		t.Fatal("v70 did not complete the schema")
	}
	a := pkAdmin(t, d, "after")
	pkCred(t, d, a.ID, "c")
}

// TestResetAuth_WithoutPasskeyTable: break-glass must still work against a
// schema where v70 never ran.
func TestResetAuth_WithoutPasskeyTable(t *testing.T) {
	d := NewDatabaseForTesting(t)
	a := pkAdmin(t, d, "root")
	if err := d.db.Exec(`DROP TABLE webauthn_credentials`).Error; err != nil {
		t.Fatal(err)
	}
	res, err := d.ResetAuth("root", "new", false, false)
	if err != nil || !res.PasskeysSkipped {
		t.Fatalf("ResetAuth without table: %+v %v", res, err)
	}
	if got, _ := d.GetAdminByID(a.ID); got.Password != "new" || !got.MustChangePassword {
		t.Fatalf("not reset: %+v", got)
	}
}
