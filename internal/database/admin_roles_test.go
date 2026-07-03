package database

import (
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"
)

// TestAdminRoles_Lifecycle pins the RBAC plumbing (P0-1, migration v20):
// bootstrap lands on role=admin, role/disabled changes revoke live sessions
// via a token-version bump, the login lookup carries role+disabled, and the
// last-admin guard counter counts only OTHER enabled admins.
func TestAdminRoles_Lifecycle(t *testing.T) {
	d := NewDatabaseForTesting(t)

	if err := d.InitAdmin("root", "hash", false); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}
	root, err := d.GetAdmin()
	if err != nil || root == nil {
		t.Fatalf("GetAdmin: %v", err)
	}
	if root.Role != auth.RoleAdmin {
		t.Fatalf("bootstrap admin role = %q, want %q", root.Role, auth.RoleAdmin)
	}

	op := models.Admin{Username: "op", Password: "hash", Role: auth.RoleOperator}
	if err := d.CreateAdmin(&op); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	all, err := d.ListAdmins()
	if err != nil || len(all) != 2 {
		t.Fatalf("ListAdmins: %v (n=%d, want 2)", err, len(all))
	}

	// Role change bumps token_version (session revocation).
	before, _ := d.GetAdminTokenVersion(op.ID)
	if err := d.UpdateAdminRole(op.ID, auth.RoleViewer); err != nil {
		t.Fatalf("UpdateAdminRole: %v", err)
	}
	after, _ := d.GetAdminTokenVersion(op.ID)
	if after != before+1 {
		t.Errorf("UpdateAdminRole must bump token_version: %d -> %d", before, after)
	}
	reloaded, err := d.GetAdminByID(op.ID)
	if err != nil || reloaded == nil || reloaded.Role != auth.RoleViewer {
		t.Fatalf("role change did not stick: %+v (err=%v)", reloaded, err)
	}

	// Disable bumps token_version and surfaces via the login lookup.
	before = after
	if err := d.SetAdminDisabled(op.ID, true); err != nil {
		t.Fatalf("SetAdminDisabled: %v", err)
	}
	after, _ = d.GetAdminTokenVersion(op.ID)
	if after != before+1 {
		t.Errorf("SetAdminDisabled must bump token_version: %d -> %d", before, after)
	}
	authRow, err := d.GetAdminByUsername("op")
	if err != nil || authRow == nil {
		t.Fatalf("GetAdminByUsername: %v", err)
	}
	if !authRow.Disabled || authRow.Role != auth.RoleViewer {
		t.Errorf("AdminAuth must carry disabled+role: %+v", authRow)
	}

	// Last-admin guard: root is the only enabled admin, so excluding root
	// leaves zero; excluding the (viewer) op still counts root.
	n, err := d.CountOtherEnabledAdmins(root.ID)
	if err != nil || n != 0 {
		t.Errorf("CountOtherEnabledAdmins(exclude root) = %d, %v; want 0", n, err)
	}
	n, err = d.CountOtherEnabledAdmins(op.ID)
	if err != nil || n != 1 {
		t.Errorf("CountOtherEnabledAdmins(exclude op) = %d, %v; want 1", n, err)
	}
}

// TestMigrateAdminRoles_IdempotentAndBackfills mirrors the v19 migration test:
// running v20 on a database whose admin row predates the role column must
// backfill role=admin, and running it twice must be harmless.
func TestMigrateAdminRoles_IdempotentAndBackfills(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.InitAdmin("root", "hash", false); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}
	// Simulate a pre-RBAC row (empty role, as an old snapshot would have).
	if err := d.db.Exec(`UPDATE admins SET role = '' WHERE username = 'root'`).Error; err != nil {
		t.Fatalf("blank role: %v", err)
	}

	if err := d.migrateAdminRoles(); err != nil {
		t.Fatalf("migrateAdminRoles (1st run): %v", err)
	}
	if err := d.migrateAdminRoles(); err != nil {
		t.Fatalf("migrateAdminRoles (2nd run, must be idempotent): %v", err)
	}

	root, err := d.GetAdmin()
	if err != nil || root == nil {
		t.Fatalf("GetAdmin: %v", err)
	}
	if root.Role != auth.RoleAdmin {
		t.Errorf("backfill: role = %q, want %q", root.Role, auth.RoleAdmin)
	}
}
