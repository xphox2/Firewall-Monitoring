package database

import (
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"
)

// TestAPITokens_RevokedWithAccount_LC15 pins the defense-in-depth half of
// LC-15: disabling or deleting an account soft-revokes every live API token
// it created, in the same transaction as the account change, so both
// credential types die together. (The authoritative half — the auth
// middleware re-checking the creator's state per bearer request — is pinned
// in internal/api/middleware/token_auth_test.go.)
func TestAPITokens_RevokedWithAccount_LC15(t *testing.T) {
	d := NewDatabaseForTesting(t)

	mkUserWithToken := func(name string) (*models.Admin, *models.ApiToken) {
		u := &models.Admin{Username: name, Password: "hash", Role: auth.RoleOperator}
		if err := d.CreateAdmin(u); err != nil {
			t.Fatalf("CreateAdmin(%s): %v", name, err)
		}
		tok := &models.ApiToken{
			Name:        name + "-token",
			TokenHash:   HashAPIToken("fwm_" + name + "-secret"),
			Scope:       "write",
			CreatedByID: u.ID,
		}
		if err := d.CreateAPIToken(tok); err != nil {
			t.Fatalf("CreateAPIToken(%s): %v", name, err)
		}
		return u, tok
	}

	reload := func(id uint) *models.ApiToken {
		var tok models.ApiToken
		if err := d.db.First(&tok, id).Error; err != nil {
			t.Fatalf("reload token %d: %v", id, err)
		}
		return &tok
	}

	// Disable revokes the account's tokens…
	u1, t1 := mkUserWithToken("lc15-disable")
	if err := d.SetAdminDisabled(u1.ID, true); err != nil {
		t.Fatalf("SetAdminDisabled: %v", err)
	}
	if reload(t1.ID).RevokedAt == nil {
		t.Error("disabling the account must revoke its API tokens")
	}

	// …and re-enabling does NOT resurrect them (revocation is final).
	if err := d.SetAdminDisabled(u1.ID, false); err != nil {
		t.Fatalf("SetAdminDisabled(false): %v", err)
	}
	if reload(t1.ID).RevokedAt == nil {
		t.Error("re-enabling the account must not resurrect revoked tokens")
	}

	// Delete revokes too; the token row is kept for the audit trail.
	u2, t2 := mkUserWithToken("lc15-delete")
	if err := d.DeleteAdmin(u2.ID); err != nil {
		t.Fatalf("DeleteAdmin: %v", err)
	}
	if reload(t2.ID).RevokedAt == nil {
		t.Error("deleting the account must revoke its API tokens")
	}

	// A bystander's token is untouched.
	_, t3 := mkUserWithToken("lc15-bystander")
	if err := d.SetAdminDisabled(u1.ID, true); err != nil {
		t.Fatalf("SetAdminDisabled (again): %v", err)
	}
	if reload(t3.ID).RevokedAt != nil {
		t.Error("another account's token must not be revoked")
	}
}
