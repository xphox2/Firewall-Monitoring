package config

import (
	"strings"
	"testing"
)

// TestValidate_ShortJWTSecretFatal pins M-3: a short operator-set JWT secret is
// a fatal startup error (not a warning), because HS256 with low entropy is
// offline brute-forceable and also seeds the AES key when ENCRYPTION_KEY is
// unset.
func TestValidate_ShortJWTSecretFatal(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "too-short")
	t.Setenv("JWT_SECRET_KEY_ALLOW_WEAK", "")
	cfg := Load()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY") {
		t.Fatalf("short JWT secret must be fatal, got: %v", err)
	}
}

// TestValidate_ShortJWTSecretAllowWeak pins the escape hatch: the explicit
// JWT_SECRET_KEY_ALLOW_WEAK=1 downgrades the fatal error to a warning.
func TestValidate_ShortJWTSecretAllowWeak(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "test-admin") // avoid the M-9 default-username fatal
	t.Setenv("JWT_SECRET_KEY", "too-short")
	t.Setenv("JWT_SECRET_KEY_ALLOW_WEAK", "1")
	cfg := Load()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("JWT_SECRET_KEY_ALLOW_WEAK=1 must allow a short secret, got: %v", err)
	}
}
