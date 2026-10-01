//go:build integration

package database

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"firewall-mon/internal/models"
)

// TestPasskeysPostgres runs the passkey schema and store checks against real
// Postgres (TEST_PG_DSN; skipped otherwise): v70 re-run on a partially
// applied schema, the ON DELETE CASCADE backstop, DeleteAdmin's explicit
// delete, and the break-glass reset.
func TestPasskeysPostgres(t *testing.T) {
	d := newPGForTest(t)

	t.Run("V70RerunOnPartialSchema", func(t *testing.T) {
		// Simulate a v70 that died after its first statements: the column is
		// there, its unique index and the table are not, and v70 is not
		// recorded.
		for _, stmt := range []string{
			`DROP TABLE IF EXISTS webauthn_credentials`,
			`DROP INDEX IF EXISTS idx_admins_webauthn_user_handle`,
			`DELETE FROM schema_migrations WHERE version = 70`,
		} {
			if err := d.Gorm().Exec(stmt).Error; err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		if err := d.RunMigrations(); err != nil {
			t.Fatalf("RunMigrations over a partial v70: %v", err)
		}
		if err := d.migratePasskeys(); err != nil {
			t.Fatalf("v70 re-run on a complete schema: %v", err)
		}
		var n int64
		d.Gorm().Raw(`SELECT count(*) FROM pg_indexes WHERE indexname IN
			('idx_admins_webauthn_user_handle','idx_webauthn_credentials_credential_id','idx_webauthn_credentials_admin_id')`).Scan(&n)
		if n != 3 {
			t.Fatalf("want 3 passkey indexes, got %d", n)
		}
		var cascade int64
		d.Gorm().Raw(`SELECT count(*) FROM pg_constraint WHERE conrelid = 'webauthn_credentials'::regclass
			AND contype = 'f' AND confdeltype = 'c'`).Scan(&cascade)
		if cascade != 1 {
			t.Fatalf("webauthn_credentials.admin_id ON DELETE CASCADE missing (%d)", cascade)
		}
		var col int64
		d.Gorm().Raw(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'login_attempts' AND column_name = 'method'`).Scan(&col)
		if col != 1 {
			t.Fatal("login_attempts.method missing")
		}
		method := "passkey"
		if err := d.SaveLoginAttempt(&models.LoginAttempt{Username: "x", Method: &method}); err != nil {
			t.Fatalf("login attempt with method: %v", err)
		}
	})

	t.Run("DeleteAdminRemovesPasskeys", func(t *testing.T) {
		testDeleteAdminRemovesPasskeys(t, d)
	})

	t.Run("CascadeBackstop", func(t *testing.T) {
		a := pkAdmin(t, d, "cascade")
		pkCred(t, d, a.ID, "cascade-1")
		if err := d.Gorm().Exec(`DELETE FROM admins WHERE id = ?`, a.ID).Error; err != nil {
			t.Fatal(err)
		}
		if n := countCreds(t, d, a.ID); n != 0 {
			t.Fatalf("FK cascade did not remove %d credentials", n)
		}
	})

	t.Run("HandleAndBytea", func(t *testing.T) {
		a := pkAdmin(t, d, "handle")
		want := make([]byte, 64)
		for i := range want {
			want[i] = byte(i)
		}
		got, err := d.EnsureWebAuthnUserHandle(a.ID, want)
		if err != nil || string(got) != string(want) {
			t.Fatalf("handle round-trip: %x %v", got, err)
		}
		b := pkAdmin(t, d, "handle2")
		if _, err := d.EnsureWebAuthnUserHandle(b.ID, want); err == nil {
			t.Fatal("unique index must refuse a second account with the same handle")
		}
		c := pkCred(t, d, a.ID, "bytea-\x00\xff")
		row, err := d.GetPasskeyByCredentialID([]byte("bytea-\x00\xff"))
		if err != nil || row == nil || row.ID != c.ID {
			t.Fatalf("lookup by raw id: %+v %v", row, err)
		}
	})

	t.Run("ResetLocksAndIsAtomic", func(t *testing.T) {
		a := pkAdmin(t, d, "pg-reset")
		pkCred(t, d, a.ID, "pg-reset-1")
		if _, err := d.ResetAdminCredentials(a.ID, AdminReset{ClearTOTP: true}); err != nil {
			t.Fatalf("ResetAdminCredentials (FOR UPDATE): %v", err)
		}
		got, _ := d.GetAdminByID(a.ID)
		if countCreds(t, d, a.ID) != 0 || got.TokenVersion != 1 {
			t.Fatalf("reset: tv=%d", got.TokenVersion)
		}
		err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: a.ID, CredentialID: []byte("pg-stale"), PublicKey: []byte{1}}, 0)
		if err != ErrPasskeyStale {
			t.Fatalf("stale CreatePasskey on Postgres: %v", err)
		}
		if err := d.CreatePasskey(&models.WebAuthnCredential{AdminID: a.ID, CredentialID: []byte("pg-fresh"), PublicKey: []byte{1}}, 1); err != nil {
			t.Fatalf("fresh CreatePasskey on Postgres: %v", err)
		}
		if ok, err := d.DeletePasskeyAndEndSessions(1<<30, a.ID); ok || err != nil {
			t.Fatalf("delete of a missing id: %v %v", ok, err)
		}
		if got, _ := d.GetAdminByID(a.ID); got.TokenVersion != 1 {
			t.Fatal("a no-op delete bumped token_version")
		}
	})

	// Lock-order regression guard: DeleteAdmin and ResetAdminCredentials on
	// the same account, concurrently, 200 times. Both lock the admins row
	// first, so neither may fail with a deadlock (40P01): the reset either
	// completes or finds the account gone.
	t.Run("ConcurrentDeleteAndResetNoDeadlock", func(t *testing.T) {
		for i := 0; i < 200; i++ {
			a := pkAdmin(t, d, fmt.Sprintf("race-%d", i))
			for k := 0; k < 3; k++ {
				pkCred(t, d, a.ID, fmt.Sprintf("race-%d-%d", i, k))
			}
			var wg sync.WaitGroup
			var delErr, resetErr error
			start := make(chan struct{})
			wg.Add(2)
			go func() { defer wg.Done(); <-start; delErr = d.DeleteAdmin(a.ID) }()
			go func() {
				defer wg.Done()
				<-start
				_, resetErr = d.ResetAdminCredentials(a.ID, AdminReset{ClearTOTP: true})
			}()
			close(start)
			wg.Wait()
			if delErr != nil {
				t.Fatalf("iteration %d: DeleteAdmin: %v", i, delErr)
			}
			if resetErr != nil && !strings.Contains(resetErr.Error(), "not found") {
				t.Fatalf("iteration %d: ResetAdminCredentials: %v", i, resetErr)
			}
			if n := countCreds(t, d, a.ID); n != 0 {
				t.Fatalf("iteration %d: %d credentials left", i, n)
			}
		}
	})

	t.Run("ResetAuth", func(t *testing.T) {
		testResetAuth(t, d)
	})
}
