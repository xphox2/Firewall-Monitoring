package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/passkey"
)

// TestPasskey_SecondRegisterBeginSupersedesAudited_D39: a second
// registration begin while one is pending replaces it — the superseded
// challenge can no longer finish, the new one finishes under ITS name — and
// the supersede is audited rather than silent. A first begin writes no such
// row.
func TestPasskey_SecondRegisterBeginSupersedesAudited_D39(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice := e.createUser("alice", auth.RoleOperator, false)
	s := e.login("alice", "")
	a := newSoftAuth(t)
	finish := func(o pkOptions) *httptest.ResponseRecorder {
		return s.do(http.MethodPost, "/admin/api/passkeys/register/finish",
			a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID)))
	}

	// Superseded challenge: refused, nothing stored.
	first := decodeOptions(t, s.registerBegin(pkTestPass, "", "first"))
	if e.hasAudit("passkey_register_superseded") {
		t.Fatal("a first begin was audited as a supersede")
	}
	decodeOptions(t, s.registerBegin(pkTestPass, "", "second"))
	if !e.hasAudit("passkey_register_superseded") {
		t.Fatalf("superseding begin not audited; audit rows = %v", e.auditActions())
	}
	if rec := finish(first); rec.Code != http.StatusBadRequest {
		t.Fatalf("finish with the superseded challenge = %d %s, want 400", rec.Code, rec.Body.String())
	}
	if n := e.allPasskeyCount(); n != 0 {
		t.Fatal("credential stored from a superseded ceremony")
	}

	// Current challenge: accepted, stored under the superseding begin's name.
	decodeOptions(t, s.registerBegin(pkTestPass, "", "third"))
	fourth := decodeOptions(t, s.registerBegin(pkTestPass, "", "fourth"))
	if rec := finish(fourth); rec.Code != http.StatusOK {
		t.Fatalf("finish with the current challenge = %d %s", rec.Code, rec.Body.String())
	}
	if rows := e.passkeyRows(alice.ID); len(rows) != 1 || rows[0].Name != "fourth" {
		t.Fatalf("stored passkeys = %+v, want one named fourth", rows)
	}
}

// TestPasskey_CeremoniesRequireHTTPS_D41: over plain HTTP (no TLS, no trusted
// proxy, no explicit COOKIE_SECURE) every ceremony endpoint refuses, a
// refused register begin leaves no ceremony and spends no re-auth budget,
// and the localhost / COOKIE_SECURE=true exceptions still work.
func TestPasskey_CeremoniesRequireHTTPS_D41(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice := e.createUser("alice", auth.RoleOperator, false)
	s := e.login("alice", "") // the session itself was issued over TLS
	e.plainHTTP = true

	if rec := e.do(http.MethodPost, "/api/auth/passkey/login/begin", "", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("login begin over HTTP = %d, want 403", rec.Code)
	}
	assertGenericPasskeyFailure(t, e.loginFinish(nil, "{}"))
	for i := 0; i < 8; i++ { // more than the re-auth burst
		if rec := s.registerBegin(pkTestPass, "", "k"); rec.Code != http.StatusForbidden || errorBody(t, rec) != passkeyNeedsHTTPSMsg {
			t.Fatalf("register begin over HTTP = %d %s, want 403", rec.Code, rec.Body.String())
		}
	}
	if _, ok := e.h.passkeys.RegisterCeremonies.Take(passkey.KindRegister, passkey.RegistrationKey(alice.ID)); ok {
		t.Fatal("a refused plain-HTTP begin left a registration ceremony")
	}
	if rec := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", "{}"); rec.Code != http.StatusForbidden {
		t.Fatalf("register finish over HTTP = %d, want 403", rec.Code)
	}

	// The re-auth budget is intact: a TLS begin still succeeds.
	e.plainHTTP = false
	if rec := s.registerBegin(pkTestPass, "", "k"); rec.Code != http.StatusOK {
		t.Fatalf("register begin over TLS after refusals = %d %s", rec.Code, rec.Body.String())
	}

	// localhost over plain HTTP is a secure context (http://localhost origins).
	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/begin", strings.NewReader(""))
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin on http://localhost = %d, want 200", rec.Code)
	}

	// An explicit COOKIE_SECURE=true is the operator saying the deployment is
	// HTTPS (e.g. a proxy not listed in TRUSTED_PROXIES).
	e.cfg.Server.CookieSecure, e.cfg.Server.CookieSecureExplicit = true, true
	req = httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/begin", strings.NewReader(""))
	rec = httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin with COOKIE_SECURE=true = %d, want 200", rec.Code)
	}
}
