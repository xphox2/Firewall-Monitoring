package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestResetAdminCredentials_RevokesAPITokens pins M-1: a password change or 2FA
// reset revokes the account's API tokens (a separate bearer credential that
// bypasses TOTP), while a bare "remove passkeys" reset leaves them.
func TestResetAdminCredentials_RevokesAPITokens(t *testing.T) {
	d := NewDatabaseForTesting(t)
	a := pkAdmin(t, d, "revoke-on-reset")

	plaintext := APITokenPlaintextPrefix + "revoke-on-reset-token"
	tok := &models.ApiToken{
		Name:        "revoke-on-reset",
		TokenHash:   HashAPIToken(plaintext),
		Prefix:      plaintext[:12],
		Scope:       "read",
		CreatedByID: a.ID,
	}
	if err := d.CreateAPIToken(tok); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	// A bare remove-passkeys reset (no password/2FA change) must NOT revoke.
	if _, err := d.ResetAdminCredentials(a.ID, AdminReset{}); err != nil {
		t.Fatalf("ResetAdminCredentials (bare): %v", err)
	}
	got := &models.ApiToken{}
	if err := d.db.First(got, tok.ID).Error; err != nil {
		t.Fatalf("read token after bare reset: %v", err)
	}
	if got.RevokedAt != nil {
		t.Fatal("bare remove-passkeys reset must not revoke API tokens")
	}

	// A password change revokes the token.
	if _, err := d.ResetAdminCredentials(a.ID, AdminReset{PasswordHash: "new-hash"}); err != nil {
		t.Fatalf("ResetAdminCredentials (password): %v", err)
	}
	if err := d.db.First(got, tok.ID).Error; err != nil {
		t.Fatalf("read token after password change: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("password change must revoke the account's API tokens")
	}
}
