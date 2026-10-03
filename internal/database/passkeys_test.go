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
	if err := d.CreatePasskey(c, 0); err != nil {
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
	if ok, err := d.DeletePasskeyAndEndSessions(ca.ID, b.ID); err != nil || ok {
		t.Fatalf("delete across accounts: ok=%v err=%v", ok, err)
	}
	if ok, err := d.RecordPasskeyUse(ca.ID, b.ID, 9, true, time.Now()); err != nil || ok {
		t.Fatalf("use across accounts: ok=%v err=%v", ok, err)
	}

	if err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: b.ID, CredentialID: []byte("a1"), PublicKey: []byte{1}}, 0); !errors.Is(err, ErrPasskeyDuplicate) {
		t.Fatalf("duplicate credential id: %v", err)
	}
	for i := 1; i < MaxPasskeysPerUser; i++ {
		pkCred(t, d, a.ID, "a-extra-"+string(rune('a'+i)))
	}
	if err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: a.ID, CredentialID: []byte("eleven"), PublicKey: []byte{1}}, 0); !errors.Is(err, ErrPasskeyLimit) {
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

// TestPasskeyStore_RecordUseIsCompareAndSet: the counter write succeeds only
// while the stored counter is below the asserted one — a replay of the same
// value (two racing assertions from a cloned authenticator) is refused and
// leaves the row untouched — while an authenticator that never counts (always
// 0) is accepted every time.
func TestPasskeyStore_RecordUseIsCompareAndSet(t *testing.T) {
	testRecordUseCompareAndSet(t, NewDatabaseForTesting(t))
}

// testRecordUseCompareAndSet is shared with the Postgres suite.
func testRecordUseCompareAndSet(t *testing.T, d *Database) {
	t.Helper()
	a := pkAdmin(t, d, "cas-a")
	c := pkCred(t, d, a.ID, "counting")
	z := pkCred(t, d, a.ID, "zero")

	stored := func(id uint) (int64, *time.Time) {
		t.Helper()
		var row models.WebAuthnCredential
		if err := d.db.First(&row, id).Error; err != nil {
			t.Fatal(err)
		}
		return row.SignCount, row.LastUsedAt
	}

	use := func(id uint, count uint32) bool {
		t.Helper()
		ok, err := d.RecordPasskeyUse(id, a.ID, count, false, time.Now())
		if err != nil {
			t.Fatalf("RecordPasskeyUse(%d, %d): %v", id, count, err)
		}
		return ok
	}
	for _, step := range []struct {
		count uint32
		want  bool
	}{
		{5, true},       // 0 → 5
		{5, false},      // replay of the committed value
		{4, false},      // below it
		{0, false},      // a counting authenticator never goes back to 0
		{6, true},       // advances again
		{1 << 31, true}, // full uint32 range: no int4 parameter on Postgres
	} {
		if got := use(c.ID, step.count); got != step.want {
			t.Fatalf("counting authenticator: use(%d) = %v, want %v", step.count, got, step.want)
		}
	}
	if sc, used := stored(c.ID); sc != 1<<31 || used == nil {
		t.Fatalf("counting authenticator stored = %d used=%v, want %d", sc, used, 1<<31)
	}

	for i := 0; i < 3; i++ {
		if !use(z.ID, 0) {
			t.Fatalf("zero-counter authenticator refused on use %d", i+1)
		}
	}
	if sc, used := stored(z.ID); sc != 0 || used == nil {
		t.Fatalf("zero-counter authenticator stored = %d used=%v, want 0 and a last_used_at", sc, used)
	}
	// Once such an authenticator starts counting, the usual rule applies.
	if !use(z.ID, 3) || use(z.ID, 0) || use(z.ID, 3) {
		t.Fatal("zero-counter authenticator: counted use must be accepted once and then only advance")
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

// TestCreatePasskey_StaleSessionRefused: the insert re-reads the account in
// its transaction — a session whose token_version is behind (a reset ran) or
// a disabled account is refused and nothing is stored.
func TestCreatePasskey_StaleSessionRefused(t *testing.T) {
	d := NewDatabaseForTesting(t)
	a := pkAdmin(t, d, "a")
	if err := d.IncrementAdminTokenVersion(a.ID); err != nil {
		t.Fatal(err)
	}
	stale := &models.WebAuthnCredential{AdminID: a.ID, CredentialID: []byte("s"), PublicKey: []byte{1}}
	if err := d.CreatePasskey(stale, 0); !errors.Is(err, ErrPasskeyStale) {
		t.Fatalf("stale token version: %v", err)
	}
	if err := d.SetAdminDisabled(a.ID, true); err != nil {
		t.Fatal(err)
	}
	cur, _ := d.GetAdminByID(a.ID)
	if err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: a.ID, CredentialID: []byte("d"), PublicKey: []byte{1}}, cur.TokenVersion); !errors.Is(err, ErrPasskeyStale) {
		t.Fatalf("disabled account: %v", err)
	}
	if n := countCreds(t, d, a.ID); n != 0 {
		t.Fatalf("%d credentials stored", n)
	}
}

// TestResetAdminCredentials_Atomic: when any part of a reset fails, none of
// it happens — the passkeys stay and token_version does not move.
func TestResetAdminCredentials_Atomic(t *testing.T) {
	d := NewDatabaseForTesting(t)
	a := pkAdmin(t, d, "a")
	pkCred(t, d, a.ID, "k1")
	// Make the recovery-code step fail.
	if err := d.db.Exec(`DROP TABLE admin_recovery_codes`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := d.ResetAdminCredentials(a.ID, AdminReset{PasswordHash: "new", ClearTOTP: true}); err == nil {
		t.Fatal("reset should have failed")
	}
	got, _ := d.GetAdminByID(a.ID)
	if n := countCreds(t, d, a.ID); n != 1 || got.TokenVersion != 0 || got.Password != "old-hash" {
		t.Fatalf("partial reset applied: creds=%d tv=%d pw=%s", n, got.TokenVersion, got.Password)
	}
	// A successful reset deletes and bumps together.
	n, err := d.ResetAdminCredentials(a.ID, AdminReset{})
	got, _ = d.GetAdminByID(a.ID)
	if err != nil || n != 1 || got.TokenVersion != 1 || countCreds(t, d, a.ID) != 0 {
		t.Fatalf("reset: n=%d err=%v tv=%d", n, err, got.TokenVersion)
	}
}
