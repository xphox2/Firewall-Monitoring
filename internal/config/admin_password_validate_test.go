package config

import (
	"strings"
	"testing"
)

// TestValidateBootstrapAdminPassword_L9 pins L-9: an operator-set
// ADMIN_PASSWORD outside the change-password bounds (8-72) cannot seed the
// first admin; in-bounds and auto-generated values pass. Validate() itself no
// longer refuses it: on an existing install the value is unused.
func TestValidateBootstrapAdminPassword_L9(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		wantErr bool
	}{
		{"too short", "short7!", true},
		{"min", strings.Repeat("a", MinPasswordLength), false},
		{"max", strings.Repeat("a", MaxPasswordLength), false},
		{"too long", strings.Repeat("a", MaxPasswordLength+1), true},
		{"generated", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ADMIN_USERNAME", "test-admin") // avoid the M-9 default-username fatal
			t.Setenv("JWT_SECRET_KEY", "")
			t.Setenv("ADMIN_PASSWORD", tc.env)
			cfg := Load()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate must not refuse it (unused on an existing install): %v", err)
			}
			err := cfg.ValidateBootstrapAdminPassword()
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "ADMIN_PASSWORD")) {
				t.Fatalf("want an ADMIN_PASSWORD error, got: %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got: %v", err)
			}
		})
	}
}
