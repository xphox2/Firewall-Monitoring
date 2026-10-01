package database

import (
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"
)

// TestDeleteAdmin_RemovesRecoveryCodes_D7: deleting a user deletes its 2FA
// recovery codes in the same transaction, and leaves other users' codes alone.
func TestDeleteAdmin_RemovesRecoveryCodes_D7(t *testing.T) {
	d := NewDatabaseForTesting(t)

	gone := models.Admin{Username: "gone", Password: "hash", Role: auth.RoleOperator}
	kept := models.Admin{Username: "kept", Password: "hash", Role: auth.RoleOperator}
	for _, u := range []*models.Admin{&gone, &kept} {
		if err := d.CreateAdmin(u); err != nil {
			t.Fatalf("CreateAdmin: %v", err)
		}
		if err := d.ReplaceRecoveryCodes(u.ID, []string{"h1-" + u.Username, "h2-" + u.Username}); err != nil {
			t.Fatalf("ReplaceRecoveryCodes: %v", err)
		}
	}

	if err := d.DeleteAdmin(gone.ID); err != nil {
		t.Fatalf("DeleteAdmin: %v", err)
	}

	count := func(id uint) int64 {
		var n int64
		if err := d.db.Model(&models.AdminRecoveryCode{}).Where("admin_id = ?", id).Count(&n).Error; err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if n := count(gone.ID); n != 0 {
		t.Errorf("deleted user still has %d recovery codes", n)
	}
	if n := count(kept.ID); n != 2 {
		t.Errorf("other user's recovery codes changed: %d, want 2", n)
	}
}
