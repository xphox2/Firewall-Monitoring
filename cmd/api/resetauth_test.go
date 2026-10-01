package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"golang.org/x/crypto/bcrypt"
)

// keepOpen lets the test inspect the in-memory database after the command
// "closes" it.
type keepOpen struct{ *database.Database }

func (keepOpen) Close() error { return nil }

// TestResetAuthCmd: `fwmon-api reset-auth --user <name>` prints a temporary
// password that then passes the real credential check, forces a password
// change, clears 2FA, deletes passkeys, ends sessions and prints the
// restart-to-clear-lockouts reminder. Usage errors change nothing.
func TestResetAuthCmd(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Auth.BcryptCost = bcrypt.MinCost
	cfg.Auth.MaxLoginAttempts = 5
	am := auth.NewAuthManager(cfg, db)
	hash, _ := am.HashPassword("forgotten-password")
	admin := &models.Admin{Username: "root", Password: hash, Role: auth.RoleAdmin}
	if err := db.CreateAdmin(admin); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAdminTOTP(admin.ID, "secret", true); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePasskey(&models.WebAuthnCredential{AdminID: admin.ID, CredentialID: []byte("k"), PublicKey: []byte{1}}, 0); err != nil {
		t.Fatal(err)
	}
	open := func() (resetAuthStore, error) { return keepOpen{db}, nil }

	for _, args := range [][]string{{}, {"--user", ""}, {"--bogus"}, {"--user", "root", "extra"}} {
		var out, errb bytes.Buffer
		if code := resetAuth(cfg, args, &out, &errb, open); code != 2 {
			t.Fatalf("args %v: exit %d, want 2 (usage)", args, code)
		}
	}
	var out, errb bytes.Buffer
	if code := resetAuth(cfg, []string{"--user", "nobody"}, &out, &errb, open); code != 1 || !strings.Contains(errb.String(), "nothing was changed") {
		t.Fatalf("unknown user: exit %d stderr %q", code, errb.String())
	}
	if got, _ := db.GetAdminByID(admin.ID); got.Password != hash {
		t.Fatal("a failed run changed the account")
	}

	out.Reset()
	errb.Reset()
	if code := resetAuth(cfg, []string{"--user", "root"}, &out, &errb, open); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errb.String())
	}
	m := regexp.MustCompile(`Temporary password \(shown ONCE\): (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no temporary password printed:\n%s", out.String())
	}
	if err := am.ValidateCredentials("root", m[1], "127.0.0.1"); err != nil {
		t.Fatalf("printed temporary password does not log in: %v", err)
	}
	got, _ := db.GetAdminByID(admin.ID)
	if !got.MustChangePassword || got.TOTPEnabled || got.TokenVersion != 1 {
		t.Fatalf("account state after reset-auth: must=%v totp=%v tv=%d", got.MustChangePassword, got.TOTPEnabled, got.TokenVersion)
	}
	if n, _ := db.CountPasskeys(admin.ID); n != 0 {
		t.Fatalf("%d passkeys left", n)
	}
	if !strings.Contains(out.String(), "restart the API container") {
		t.Fatalf("no lockout reminder:\n%s", out.String())
	}
}
