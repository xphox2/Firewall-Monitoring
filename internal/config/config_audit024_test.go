package config

import (
	"os"
	"strings"
	"testing"
)

// validConfig returns a minimal Config that passes Validate() — used as
// the base for the AUDIT-024 cases. We mutate the returned struct from
// each test rather than maintaining a fixture, so the relationship
// between the default state and the change-under-test is visible
// inline.
//
// Defaults match config.env.example: postgres DB, plain HTTP, V2c SNMP,
// BcryptCost 12.
func validConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:                 "8080",
			EnableTLS:            false,
			TLSCertFile:          "",
			TLSKeyFile:           "",
			CookieSecure:         false,
			CookieSecureExplicit: false,
		},
		SNMP: SNMPConfig{
			SNMPPort:  161,
			Community: "public",
			Version:   "2c",
		},
		Database: DatabaseConfig{
			Type: "sqlite", // bypasses the DB_HOST requirement
			Host: "",
		},
		Auth: AuthConfig{
			BcryptCost: 12,
		},
	}
}

// TestValidate_CookieSecureMismatch_AUDIT024 — when the operator explicitly
// sets COOKIE_SECURE=true while SERVER_ENABLE_TLS=false, Validate() must
// log a clear warning. The mismatch is the silent-login-break class
// (browser drops the Secure cookie over plain HTTP → login button does
// nothing → operator files a bug). We can't assert on the log output
// directly without redirecting log.Printf, so we just confirm the call
// doesn't error (the warning is logged, the function returns nil) — a
// future change that flips the warning to log.Fatal would surface as
// a test failure here, which is the right hook for a deliberate
// breaking change.
func TestValidate_CookieSecureMismatch_AUDIT024(t *testing.T) {
	c := validConfig()
	c.Server.CookieSecure = true
	c.Server.CookieSecureExplicit = true
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() returned err on the broken config; warning is expected, error is not: %v", err)
	}
}

// TestValidate_CookieSecureInheritedFromTLS_AUDIT024 — when the operator
// leaves COOKIE_SECURE unset, the default is to inherit SERVER_ENABLE_TLS.
// In the implicit-inherit case the warning must NOT fire (it would be
// noise — the operator didn't ask for the mismatch).
func TestValidate_CookieSecureInheritedFromTLS_AUDIT024(t *testing.T) {
	c := validConfig()
	c.Server.EnableTLS = true
	c.Server.TLSCertFile = "/tmp/cert.pem"
	c.Server.TLSKeyFile = "/tmp/key.pem"
	c.Server.CookieSecure = true          // inherited from EnableTLS
	c.Server.CookieSecureExplicit = false // operator did NOT set it
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() returned err on the consistent (TLS+Secure) config: %v", err)
	}
}

// TestValidate_CookieSecureExplicitlyFalseOverPlainHTTP_AUDIT024 — when the
// operator explicitly sets COOKIE_SECURE=false over plain HTTP, the warning
// must NOT fire (this is the correct configuration for plain-HTTP deploys).
func TestValidate_CookieSecureExplicitlyFalseOverPlainHTTP_AUDIT024(t *testing.T) {
	c := validConfig()
	c.Server.CookieSecure = false
	c.Server.CookieSecureExplicit = true
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() returned err on the explicit-false config: %v", err)
	}
}

// TestConfigExample_HasNoCookieSecureMismatch_AUDIT024 is a static check
// on config.env.example. The example file is the template operators copy;
// shipping it with COOKIE_SECURE=true + SERVER_ENABLE_TLS=false was the
// root cause of the audit. The check is intentionally loose: it
// rejects the specific line `COOKIE_SECURE=true` when the file also
// contains `SERVER_ENABLE_TLS=false`, but allows the operator-comment
// form (i.e. the line being commented out, or a non-true value).
//
// The fail message points the future agent at the audit and the fix.
func TestConfigExample_HasNoCookieSecureMismatch_AUDIT024(t *testing.T) {
	const path = "../../config.env.example"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("config.env.example not found at %s (tests must run from internal/config/); err: %v", path, err)
	}
	body := string(data)

	// Strip comments to make sure we don't false-positive on a
	// commented-out #COOKIE_SECURE=true line.
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line)
	}
	effective := strings.Join(lines, "\n")

	if !strings.Contains(effective, "SERVER_ENABLE_TLS=false") {
		// Example no longer ships with TLS off — the mismatch path
		// can't manifest from this example.
		return
	}
	if strings.Contains(effective, "COOKIE_SECURE=true") {
		t.Fatalf("config.env.example has COOKIE_SECURE=true while SERVER_ENABLE_TLS=false (AUDIT-024 mismatch). Either set COOKIE_SECURE=false, comment the line out, or unset it so the default inherits from SERVER_ENABLE_TLS.")
	}
}
