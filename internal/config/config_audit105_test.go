package config

import (
	"strings"
	"testing"
)

// TestValidate_DefaultAdminUsernameFatal_AUDIT105_M9 — when the operator hasn't
// set ADMIN_USERNAME and the default "admin" is in effect, Validate() must FAIL
// (not just warn): it is the textbook brute-force target. The escape hatch
// ADMIN_USERNAME_ALLOW_DEFAULT=true keeps the default available for a lab.
func TestValidate_DefaultAdminUsernameFatal_AUDIT105_M9(t *testing.T) {
	c := validConfig()
	c.Auth.AdminUsername = "admin"
	c.Auth.AdminUsernameExplicit = false
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ADMIN_USERNAME") {
		t.Fatalf("default admin username must be fatal, got: %v", err)
	}
	c.Auth.AdminUsernameAllowDefault = true
	if err := c.Validate(); err != nil {
		t.Fatalf("ADMIN_USERNAME_ALLOW_DEFAULT=true must allow the default, got: %v", err)
	}
}

// TestValidate_ExplicitAdminUsernameDoesNotWarn_AUDIT105 — when the
// operator explicitly sets ADMIN_USERNAME=admin (or any value), the
// warning does NOT fire. We test the case-insensitive default-match
// path: ADMIN_USERNAME=Admin and ADMIN_USERNAME=ADMIN both still
// trigger the warning when !Explicit, and both are silent when
// Explicit=true.
func TestValidate_ExplicitAdminUsernameDoesNotWarn_AUDIT105(t *testing.T) {
	c := validConfig()
	c.Auth.AdminUsername = "admin"
	c.Auth.AdminUsernameExplicit = true
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() returned err: %v", err)
	}
}

// TestValidate_NonDefaultAdminUsernameSilent_AUDIT105 — when the
// operator set ADMIN_USERNAME to anything other than "admin"
// (case-insensitive), the warning does NOT fire. The test uses a
// name that an attacker would never try first.
func TestValidate_NonDefaultAdminUsernameSilent_AUDIT105(t *testing.T) {
	c := validConfig()
	c.Auth.AdminUsername = "ops-jane"
	c.Auth.AdminUsernameExplicit = false // would still warn if value were "admin"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() returned err: %v", err)
	}
}

// TestValidate_DefaultAdminUsernameCaseInsensitive_AUDIT105 — the failure
// fires for case variants of "admin" too (Admin, ADMIN, etc.) when the value
// was inherited from the default.
func TestValidate_DefaultAdminUsernameCaseInsensitive_AUDIT105(t *testing.T) {
	for _, variant := range []string{"Admin", "ADMIN", "aDmIn"} {
		t.Run(variant, func(t *testing.T) {
			c := validConfig()
			c.Auth.AdminUsername = variant
			c.Auth.AdminUsernameExplicit = false
			if err := c.Validate(); err == nil {
				t.Fatalf("variant %q: Validate() returned nil, want a fatal default-username error", variant)
			}
		})
	}
}
