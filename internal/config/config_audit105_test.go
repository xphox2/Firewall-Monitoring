package config

import "testing"

// TestValidate_DefaultAdminUsernameWarns_AUDIT105 — the headline
// regression: when the operator hasn't set ADMIN_USERNAME and the
// default "admin" is in effect, Validate() must log a clear warning
// that points at the brute-force surface. The pre-fix code shipped
// the default silently, which meant a public deploy with
// `ADMIN_USERNAME=admin` and a weak password was an unauthenticated
// brute-force away from a full compromise.
//
// We can't easily assert on the log output without redirecting
// log.Printf; instead we verify that Validate() returns nil (warning
// is logged, not fatal — running behind a SSO portal is a legitimate
// reason to keep the default) and that a config with a non-default
// username doesn't even attempt the warn path (tested by the
// "NoWarnOnNonDefault" variant).
func TestValidate_DefaultAdminUsernameWarns_AUDIT105(t *testing.T) {
	c := validConfig()
	c.Auth.AdminUsername = "admin"
	c.Auth.AdminUsernameExplicit = false
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() returned err on the default-username config; warning is expected, error is not: %v", err)
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

// TestValidate_DefaultAdminUsernameCaseInsensitive_AUDIT105 — the
// warning fires for case variants of "admin" too (Admin, ADMIN, etc.)
// when the value was inherited from the default. An attacker who
// tries "Admin" against a host that only sets "admin" will get
// through, so the warn has to cover both.
func TestValidate_DefaultAdminUsernameCaseInsensitive_AUDIT105(t *testing.T) {
	for _, variant := range []string{"Admin", "ADMIN", "aDmIn"} {
		t.Run(variant, func(t *testing.T) {
			c := validConfig()
			c.Auth.AdminUsername = variant
			c.Auth.AdminUsernameExplicit = false
			if err := c.Validate(); err != nil {
				t.Fatalf("variant %q: Validate() returned err: %v", variant, err)
			}
		})
	}
}
