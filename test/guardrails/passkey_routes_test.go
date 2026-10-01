package guardrails

import (
	"os"
	"strings"
	"testing"
)

// roleMaps splits cmd/api/main.go's RequireRole call into its
// selfServiceRoutes and adminOnlyRoutes literals.
func roleMaps(t *testing.T, body string) (self, adminOnly string) {
	t.Helper()
	s := strings.Index(body, "selfServiceRoutes — any authenticated role")
	a := strings.Index(body, "adminOnlyRoutes — role=admin")
	if s < 0 || a < 0 || a < s {
		t.Fatal("RequireRole map markers not found in main.go")
	}
	end := strings.Index(body[a:], "\n\t\t},")
	if end < 0 {
		t.Fatal("end of adminOnlyRoutes not found")
	}
	return body[s:a], body[a : a+end]
}

// TestPasskeyRoutesWiring pins the passkey wiring in cmd/api/main.go:
//   - every self-service passkey route is in selfServiceRoutes (each role
//     manages its OWN passkeys; the handlers scope by session user id) and
//     none of them is admin-only;
//   - "remove all passkeys for user X" is admin-only and NOT self-service;
//   - the public login routes ride their own LoginRateLimiter instance;
//   - the service comes from passkey.Setup (non-fatal, disabled by default).
//
// The handler tests use a copy of these map entries; this test keeps that
// copy honest.
func TestPasskeyRoutesWiring(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	self, adminOnly := roleMaps(t, body)

	for _, r := range []string{
		`"/admin/api/passkeys"`, `"/admin/api/passkeys/:id"`,
		`"/admin/api/passkeys/register/begin"`, `"/admin/api/passkeys/register/finish"`,
		`"/admin/api/passkeys/notices/ack"`,
	} {
		if !strings.Contains(self, r) {
			t.Errorf("selfServiceRoutes missing %s", r)
		}
		if strings.Contains(adminOnly, r) {
			t.Errorf("%s must not be admin-only (every role manages its own passkeys)", r)
		}
	}
	if !strings.Contains(adminOnly, `"/admin/api/users/:id/passkeys"`) {
		t.Error("adminOnlyRoutes missing /admin/api/users/:id/passkeys")
	}
	if strings.Contains(self, `"/admin/api/users/:id/passkeys"`) {
		t.Error("/admin/api/users/:id/passkeys must not be self-service")
	}

	for _, line := range []string{
		`passkeyLimiter := middleware.LoginRateLimiter()`,
		`api.POST("/auth/passkey/login/begin", passkeyLimiter, handler.PasskeyLoginBegin)`,
		`api.POST("/auth/passkey/login/finish", passkeyLimiter, handler.PasskeyLoginFinish)`,
		`api.GET("/auth/passkey/config", handler.GetPasskeyConfig)`,
		`handler.SetPasskeys(passkey.Setup(cfg))`,
		`admin.DELETE("/api/users/:id/passkeys", handler.RemoveUserPasskeys)`,
		`admin.DELETE("/api/passkeys/:id", handler.DeletePasskey)`,
		`case "reset-auth":`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("main.go missing %s", line)
		}
	}
}

// TestResetAuthWrapperInImage pins the break-glass wrapper: installed on PATH
// by the Dockerfile, and rebuilding exactly the DB environment entrypoint.sh
// exports before running the API binary's reset-auth as fwmon.
func TestResetAuthWrapperInImage(t *testing.T) {
	df, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(df), "COPY scripts/fwmon-reset-auth /usr/local/bin/fwmon-reset-auth") ||
		!strings.Contains(string(df), "chmod 0755 /usr/local/bin/fwmon-reset-auth") {
		t.Error("Dockerfile does not install fwmon-reset-auth on PATH")
	}
	w, err := os.ReadFile("../../scripts/fwmon-reset-auth")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := os.ReadFile("../../entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`PG_CRED_FILE="/config/pg-credentials"`,
		`export DB_TYPE=postgres`,
		`export DB_PORT=5432`,
		`export DB_USER="$PG_USER"`,
		`export DB_PASSWORD="$PG_PASSWORD"`,
	} {
		if !strings.Contains(string(w), want) {
			t.Errorf("wrapper missing %s", want)
		}
		if !strings.Contains(string(ep), want) {
			t.Errorf("entrypoint.sh no longer has %s — keep the wrapper in step", want)
		}
	}
	for _, want := range []string{
		`PGRUN="/run/postgresql"`, `export DB_HOST="$PGRUN"`, `export DB_NAME=firewall_mon`,
		`export CONFIG_FILE=/config/config.env`, `exec su-exec fwmon ./fwmon-api reset-auth "$@"`,
	} {
		if !strings.Contains(string(w), want) {
			t.Errorf("wrapper missing %s", want)
		}
	}
	for _, want := range []string{`PGRUN="/run/postgresql"`, `PG_DB="firewall_mon"`, `export CONFIG_FILE=/config/config.env`} {
		if !strings.Contains(string(ep), want) {
			t.Errorf("entrypoint.sh no longer has %s — keep the wrapper in step", want)
		}
	}
}
