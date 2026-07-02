package database

import "testing"

// TestAdminMustChangePassword_Lifecycle pins the forced first-login password
// change flag: it is set when the admin is bootstrapped with a generated
// password, readable, and cleared once the operator rotates the password.
func TestAdminMustChangePassword_Lifecycle(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// Bootstrap with mustChange=true (the generated-password path).
	if err := d.InitAdmin("admin", "hashed-generated", true); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}

	admin, err := d.GetAdmin()
	if err != nil || admin == nil {
		t.Fatalf("GetAdmin: %v (admin=%v)", err, admin)
	}

	must, err := d.GetAdminMustChangePassword(admin.ID)
	if err != nil {
		t.Fatalf("GetAdminMustChangePassword: %v", err)
	}
	if !must {
		t.Fatal("expected must_change_password=true after generated-password bootstrap")
	}

	// The username/password lookup used by the login handler must carry the flag.
	auth, err := d.GetAdminByUsername("admin")
	if err != nil || auth == nil {
		t.Fatalf("GetAdminByUsername: %v", err)
	}
	if !auth.MustChangePassword {
		t.Fatal("AdminAuth.MustChangePassword should be true")
	}

	// Clearing (what ChangePassword does) must stick.
	if err := d.SetAdminMustChangePassword(admin.ID, false); err != nil {
		t.Fatalf("SetAdminMustChangePassword: %v", err)
	}
	must, err = d.GetAdminMustChangePassword(admin.ID)
	if err != nil {
		t.Fatalf("GetAdminMustChangePassword (after clear): %v", err)
	}
	if must {
		t.Fatal("expected must_change_password=false after clear")
	}
}

// TestInitAdmin_OperatorPasswordNotForced verifies that an operator-supplied
// password (mustChange=false) does not force a change.
func TestInitAdmin_OperatorPasswordNotForced(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.InitAdmin("admin", "hashed-operator-set", false); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}
	admin, err := d.GetAdmin()
	if err != nil || admin == nil {
		t.Fatalf("GetAdmin: %v", err)
	}
	must, err := d.GetAdminMustChangePassword(admin.ID)
	if err != nil {
		t.Fatalf("GetAdminMustChangePassword: %v", err)
	}
	if must {
		t.Fatal("operator-set password must NOT force a change")
	}
}
