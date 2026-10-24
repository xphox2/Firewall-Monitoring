package config

import (
	"os"
	"strings"
	"testing"
)

// TestDBSSLModeDefault_TopologyAware pins M-10: the DB_SSL_MODE default must
// stay `disable` exactly where cleartext is harmless (loopback and the
// single-container unix socket) and become `require` everywhere else, while an
// explicit value always wins.
func TestDBSSLModeDefault_TopologyAware(t *testing.T) {
	// The unset-env cases must see NO DB_SSL_MODE in the environment at all.
	if err := os.Unsetenv("DB_SSL_MODE"); err != nil {
		t.Fatalf("unset DB_SSL_MODE: %v", err)
	}

	cases := []struct {
		host string
		want string
	}{
		// Same-box topologies: SSL is pointless; `disable` keeps them working.
		{"localhost", "disable"},
		{"LOCALHOST", "disable"}, // host is case-folded before matching
		{"127.0.0.1", "disable"},
		{"::1", "disable"},
		{"[::1]", "disable"},
		{"/var/run/postgresql", "disable"}, // single-container entrypoint ($PGRUN)
		// Anything else is a remote Postgres: default to `require`.
		{"10.0.0.5", "require"},
		{"db.internal.example.net", "require"},
		{"postgres", "require"}, // compose-style service name
	}
	for _, tc := range cases {
		if got := dbSSLModeDefault(tc.host); got != tc.want {
			t.Fatalf("dbSSLModeDefault(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// TestDBSSLModeDefault_ExplicitWins: an operator-set DB_SSL_MODE overrides the
// topology default in BOTH directions — including `disable` on a remote host
// (a conscious accepted risk) and `require` on loopback (TLS on loopback is
// unusual but valid when the Postgres side has SSL enabled).
func TestDBSSLModeDefault_ExplicitWins(t *testing.T) {
	t.Setenv("DB_SSL_MODE", "verify-full")
	if got := dbSSLModeDefault("10.0.0.5"); got != "verify-full" {
		t.Fatalf("explicit verify-full on remote host = %q, want verify-full", got)
	}
	t.Setenv("DB_SSL_MODE", "disable")
	if got := dbSSLModeDefault("10.0.0.5"); got != "disable" {
		t.Fatalf("explicit disable on remote host = %q, want disable", got)
	}

	// An explicitly EMPTY value (the entrypoint copies env files verbatim)
	// must fall through to the topology default, not produce sslmode="".
	t.Setenv("DB_SSL_MODE", "")
	if got := dbSSLModeDefault("10.0.0.5"); got != "require" {
		t.Fatalf("empty DB_SSL_MODE on remote host = %q, want topology default require", got)
	}
}

// TestValidate_DBSSLModeInvalid: a typo'd sslmode must fail startup with a
// message naming the value and the accepted set, not die later on the first
// connect with a cryptic libpq error.
func TestValidate_DBSSLModeInvalid(t *testing.T) {
	c := validConfig()
	c.Database.Type = "postgres"
	c.Database.Host = "db.internal"
	c.Database.SSLMode = "reqiure" // the typo under test

	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "DB_SSL_MODE") {
		t.Fatalf("expected a DB_SSL_MODE validation error, got %v", err)
	}

	// Every accepted value must still pass.
	for _, m := range []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"} {
		c.Database.SSLMode = m
		if err := c.Validate(); err != nil {
			t.Fatalf("sslmode %q should validate, got %v", m, err)
		}
	}
}
