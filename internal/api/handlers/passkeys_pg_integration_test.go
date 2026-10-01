//go:build integration

package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/passkey"
)

// TestPasskeys_Postgres_EndToEnd runs registration, passkey login, the clone
// warning, delete-with-reissue and an admin reset through the real handler
// chain against real Postgres (bytea credential ids/handles, the unique
// indexes, the FK). Skips unless TEST_PG_DSN is set.
func TestPasskeys_Postgres_EndToEnd(t *testing.T) {
	db := database.NewIntegrationDB(t)
	svc, err := passkey.New(passkey.Settings{RPID: pkTestRPID, Origins: []string{pkTestOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	e := newPasskeyEnvDB(t, db, svc)
	root := e.createUser("root", auth.RoleAdmin, true)
	rs := e.login("root", totpCode(t, -1))
	ra := newSoftAuth(t)
	rs.register(ra, totpCode(t, 0), "root-key")

	alice, a, as := e.registered("alice", auth.RoleOperator)
	if rec := e.passkeyLogin(a, a.userHandle); rec.Code != http.StatusOK {
		t.Fatalf("passkey login: %d %s", rec.Code, rec.Body.String())
	}
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, ra.userHandle)) // alice's key, root's handle
	a.counter = 0
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle)) // clone warning
	if !e.hasAudit("passkey_clone_warning") {
		t.Fatal("clone warning not audited")
	}

	id := e.passkeyRows(alice.ID)[0].ID
	rec := as.do(http.MethodDelete, fmt.Sprintf("/admin/api/passkeys/%d", id), `{"password":"`+pkTestPass+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if r := e.sessionFrom(rec).do(http.MethodGet, "/admin/api/passkeys", ""); r.Code != http.StatusOK {
		t.Fatalf("re-issued session: %d", r.Code)
	}

	bob, _, _ := e.registered("bob", auth.RoleViewer)
	if r := rs.do(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/reset-2fa", bob.ID), ""); r.Code != http.StatusOK {
		t.Fatalf("reset-2fa: %d %s", r.Code, r.Body.String())
	}
	if n := len(e.passkeyRows(bob.ID)); n != 0 {
		t.Fatalf("reset-2fa left %d passkeys", n)
	}
	if n := len(e.passkeyRows(root.ID)); n != 1 {
		t.Fatalf("root's passkey count = %d", n)
	}
}
