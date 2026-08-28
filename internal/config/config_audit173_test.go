package config

import "testing"

// TestEmptyAdminPassword_AUDIT173 pins that a set-but-EMPTY ADMIN_PASSWORD
// (exactly what config.env.example ships and deploy.sh seeds into the live
// config on first install) behaves like UNSET: the auto-generate+persist
// path engages and the resolved password is never empty.
//
// The pre-fix LookupEnv semantics treated `ADMIN_PASSWORD=` as "the operator
// deliberately wants an empty password". But the login handler rejects empty
// passwords outright (binding:"required"), so that choice bootstrapped an
// admin with bcrypt("") that nobody can ever log in as — and InitAdmin skips
// existing admins on every later boot, so setting a real ADMIN_PASSWORD
// afterwards never heals it. Permanent lockout, recoverable only by DB
// surgery (docs/OPERATIONS.md "Admin password reset").
func TestEmptyAdminPassword_AUDIT173(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "") // set-but-empty, the shipped default

	c := Load()

	if !c.IsGeneratedPassword() {
		t.Error("IsGeneratedPassword() = false with ADMIN_PASSWORD set-but-empty; empty must count as unset, or the shipped config.env.example bootstraps an unusable bcrypt(\"\") admin (AUDIT-173).")
	}
	if c.Auth.AdminPassword == "" {
		t.Error("Auth.AdminPassword resolved empty with ADMIN_PASSWORD set-but-empty; the generated-default path must engage so the bootstrapped admin is loggable-in (AUDIT-173).")
	}
}

// TestValidateRejectsEmptyAdminPassword_AUDIT173 pins the belt-and-braces
// invariant: if a future refactor lets an empty AdminPassword through the
// resolution, Validate() must fail loudly rather than let main bootstrap an
// admin the login handler can never accept.
func TestValidateRejectsEmptyAdminPassword_AUDIT173(t *testing.T) {
	c := Load()
	c.Auth.AdminPassword = "" // simulate the broken resolution

	if err := c.Validate(); err == nil {
		t.Error("Validate() accepted an empty Auth.AdminPassword; it must fail loudly instead of allowing a bcrypt(\"\") admin bootstrap (AUDIT-173).")
	}
}
