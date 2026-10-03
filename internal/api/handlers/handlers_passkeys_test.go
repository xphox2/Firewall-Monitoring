package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/passkey"

	"github.com/go-webauthn/webauthn/protocol"
)

// --- happy path --------------------------------------------------------------

// TestPasskey_RegisterAndLogin is the end-to-end happy path: a TOTP-enrolled
// admin registers a passkey (password + TOTP re-auth), then signs in with it
// alone and gets a full session (no TOTP stage), audited and recorded.
func TestPasskey_RegisterAndLogin(t *testing.T) {
	e := newPasskeyEnv(t, true)
	root := e.createUser("root", auth.RoleAdmin, true)
	s := e.login("root", totpCode(t, -1))

	a := newSoftAuth(t)
	s.register(a, totpCode(t, 0), "Laptop")

	stored := e.admin(root.ID)
	if len(stored.WebAuthnUserHandle) != userHandleBytes {
		t.Fatalf("user handle is %d bytes, want %d", len(stored.WebAuthnUserHandle), userHandleBytes)
	}
	rows := e.passkeyRows(root.ID)
	if len(rows) != 1 || rows[0].Name != "Laptop" || !rows[0].BackupEligible || !rows[0].BackupState {
		t.Fatalf("stored passkeys = %+v", rows)
	}

	rec := e.passkeyLogin(a, a.userHandle)
	if rec.Code != http.StatusOK {
		t.Fatalf("passkey login: %d %s", rec.Code, rec.Body.String())
	}
	ps := e.sessionFrom(rec)
	if me := ps.do(http.MethodGet, "/admin/api/me", ""); me.Code != http.StatusOK {
		t.Fatalf("passkey session rejected: %d", me.Code)
	}
	if ck := cookieByName(rec, passkeyLoginCookie); ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("webauthn_login cookie not cleared on success: %+v", ck)
	}
	row := e.passkeyRows(root.ID)[0]
	if row.SignCount != 1 || row.LastUsedAt == nil {
		t.Fatalf("use not persisted: sign_count=%d last_used=%v", row.SignCount, row.LastUsedAt)
	}
	if !e.hasAudit("passkey_register") || !e.hasAudit("passkey_login_success") {
		t.Fatalf("audit rows = %v", e.auditActions())
	}
	var attempts []models.LoginAttempt
	e.db.Gorm().Order("id").Find(&attempts)
	last := attempts[len(attempts)-1]
	if !last.Success || last.Method == nil || *last.Method != "passkey" || last.Username != "root" {
		t.Fatalf("last login attempt = %+v", last)
	}
	// root signed in with password+TOTP: the password step writes no row and
	// the TOTP step records the login as "totp" (v0.11.283).
	if len(attempts) != 2 || attempts[0].Method == nil || *attempts[0].Method != "totp" || !attempts[0].Success {
		t.Fatalf("password+TOTP login attempt rows = %+v", attempts)
	}

	// A second registration reuses the same handle and lists the first key
	// in excludeCredentials.
	beg := s.registerBegin(pkTestPass, totpCode(t, 1), "Phone")
	if beg.Code != http.StatusOK {
		t.Fatalf("second begin: %d %s", beg.Code, beg.Body.String())
	}
	o := decodeOptions(t, beg)
	if len(o.Data.PublicKey.ExcludeCredentials) != 1 || o.Data.PublicKey.ExcludeCredentials[0].ID != b64u(a.credID) {
		t.Fatalf("excludeCredentials = %+v", o.Data.PublicKey.ExcludeCredentials)
	}
	if got := e.admin(root.ID).WebAuthnUserHandle; string(got) != string(stored.WebAuthnUserHandle) {
		t.Fatal("user handle changed on the second registration")
	}
}

// --- production login path unchanged -----------------------------------------

// loginShape is the observable shape of a login response: status, the JSON
// keys of data, and the cookies set.
func loginShape(t *testing.T, rec interface {
	Result() *http.Response
}, body []byte, code int) string {
	t.Helper()
	var resp struct {
		Success bool                   `json:"success"`
		Data    map[string]interface{} `json:"data"`
		Error   string                 `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	keys := make([]string, 0, len(resp.Data))
	for k, v := range resp.Data {
		if k == "csrf_token" {
			keys = append(keys, k)
			continue
		}
		keys = append(keys, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(keys)
	var cookies []string
	for _, c := range rec.Result().Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s(path=%s,maxage=%d,httponly=%t)", c.Name, c.Path, c.MaxAge, c.HttpOnly))
	}
	sort.Strings(cookies)
	return fmt.Sprintf("%d success=%t err=%q data=%v cookies=%v", code, resp.Success, resp.Error, keys, cookies)
}

// TestPasskey_PasswordLoginUnchanged_FeatureOffAndOn pins the production
// account's path: password+TOTP (and password-only, and a wrong password)
// produce exactly the response shape and cookies of v0.11.276, with passkeys
// disabled and enabled.
func TestPasskey_PasswordLoginUnchanged_FeatureOffAndOn(t *testing.T) {
	shapes := map[bool][]string{}
	for _, enabled := range []bool{false, true} {
		e := newPasskeyEnv(t, enabled)
		e.createUser("root", auth.RoleAdmin, true)
		e.createUser("plain", auth.RoleOperator, false)

		step1 := e.do(http.MethodPost, "/api/auth/login", `{"username":"root","password":"`+pkTestPass+`"}`, nil, nil)
		pending := cookieByName(step1, "pending_2fa")
		if pending == nil {
			t.Fatalf("enabled=%v: no pending_2fa", enabled)
		}
		step2 := e.do(http.MethodPost, "/api/auth/totp", `{"code":"`+totpCode(t, 0)+`"}`, []*http.Cookie{pending}, nil)
		plain := e.do(http.MethodPost, "/api/auth/login", `{"username":"plain","password":"`+pkTestPass+`"}`, nil, nil)
		bad := e.do(http.MethodPost, "/api/auth/login", `{"username":"root","password":"wrong-password"}`, nil, nil)
		for _, rec := range []*struct {
			name string
			code int
			body []byte
			r    interface{ Result() *http.Response }
		}{
			{"password step", step1.Code, step1.Body.Bytes(), step1},
			{"totp step", step2.Code, step2.Body.Bytes(), step2},
			{"password only", plain.Code, plain.Body.Bytes(), plain},
			{"wrong password", bad.Code, bad.Body.Bytes(), bad},
		} {
			shapes[enabled] = append(shapes[enabled], rec.name+": "+loginShape(t, rec.r, rec.body, rec.code))
		}
		if step2.Code != http.StatusOK || plain.Code != http.StatusOK || bad.Code != http.StatusUnauthorized {
			t.Fatalf("enabled=%v: statuses %d/%d/%d", enabled, step2.Code, plain.Code, bad.Code)
		}
		// The TOTP-stage session works.
		if me := e.sessionFrom(step2).do(http.MethodGet, "/admin/api/me", ""); me.Code != http.StatusOK {
			t.Fatalf("enabled=%v: totp session rejected %d", enabled, me.Code)
		}
	}
	// Golden: captured from origin/master (v0.11.276, before any passkey
	// code) with the same harness — the shapes must match it exactly with
	// the feature off AND on.
	golden := []string{
		`password step: 200 success=true err="" data=[totp_required=true] cookies=[pending_2fa(path=/,maxage=300,httponly=true)]`,
		`totp step: 200 success=true err="" data=[csrf_token message=Login successful must_change_password=false] cookies=[auth_token(path=/,maxage=3600,httponly=true) csrf_token(path=/,maxage=3600,httponly=false) pending_2fa(path=/,maxage=-1,httponly=true)]`,
		`password only: 200 success=true err="" data=[csrf_token message=Login successful must_change_password=false] cookies=[auth_token(path=/,maxage=3600,httponly=true) csrf_token(path=/,maxage=3600,httponly=false)]`,
		`wrong password: 401 success=false err="Invalid credentials" data=[] cookies=[]`,
	}
	for _, enabled := range []bool{false, true} {
		for i := range golden {
			if shapes[enabled][i] != golden[i] {
				t.Errorf("enabled=%v: login response differs from v0.11.276:\n got: %s\nwant: %s", enabled, shapes[enabled][i], golden[i])
			}
		}
	}
}

// --- kill switch and configuration -------------------------------------------

func allPasskeyEndpoints(userID uint) [][2]string {
	return [][2]string{
		{http.MethodPost, "/api/auth/passkey/login/begin"},
		{http.MethodPost, "/api/auth/passkey/login/finish"},
		{http.MethodGet, "/admin/api/passkeys"},
		{http.MethodPost, "/admin/api/passkeys/register/begin"},
		{http.MethodPost, "/admin/api/passkeys/register/finish"},
		{http.MethodPost, "/admin/api/passkeys/notices/ack"},
		{http.MethodPut, "/admin/api/passkeys/1"},
		{http.MethodDelete, "/admin/api/passkeys/1"},
		{http.MethodDelete, fmt.Sprintf("/admin/api/users/%d/passkeys", userID)},
	}
}

// TestPasskey_KillSwitch404: disabled ⇒ every passkey endpoint 404s (for an
// authenticated admin too), the public config says unavailable, and stored
// credentials are untouched.
func TestPasskey_KillSwitch404(t *testing.T) {
	e := newPasskeyEnv(t, false)
	root := e.createUser("root", auth.RoleAdmin, false)
	// A credential stored while the feature was on.
	if err := e.db.CreatePasskey(&models.WebAuthnCredential{AdminID: root.ID, CredentialID: []byte("kept-credential"), PublicKey: []byte{1}, Name: "old"}, 0); err != nil {
		t.Fatal(err)
	}
	s := e.login("root", "")
	for _, ep := range allPasskeyEndpoints(root.ID) {
		var rec interface{ Result() *http.Response }
		code := 0
		if strings.HasPrefix(ep[1], "/admin") {
			r := s.do(ep[0], ep[1], `{"password":"`+pkTestPass+`","name":"x"}`)
			rec, code = r, r.Code
		} else {
			r := e.do(ep[0], ep[1], "{}", nil, nil)
			rec, code = r, r.Code
		}
		_ = rec
		if code != http.StatusNotFound {
			t.Errorf("%s %s with passkeys disabled = %d, want 404", ep[0], ep[1], code)
		}
	}
	cfgRec := e.do(http.MethodGet, "/api/auth/passkey/config", "", nil, nil)
	if cfgRec.Code != http.StatusOK || !strings.Contains(cfgRec.Body.String(), `"enabled":false`) {
		t.Fatalf("public config = %d %s", cfgRec.Code, cfgRec.Body.String())
	}
	if n := e.allPasskeyCount(); n != 1 {
		t.Fatalf("stored credentials changed under the kill switch: %d", n)
	}
}

// TestPasskey_InvalidConfigDisablesButServerStarts: an IP RP ID, a bad
// origin, or enabled-without-a-host all make Setup return nil (passkeys off)
// without panicking or exiting, and password login keeps working with the
// resulting handler.
func TestPasskey_InvalidConfigDisablesButServerStarts(t *testing.T) {
	cases := []struct{ name, rpID, origins, base string }{
		{"ipv4 rp id", "192.0.2.10", "https://192.0.2.10", ""},
		{"ipv6 rp id", "::1", "", ""},
		{"ip from PUBLIC_BASE_URL", "", "", "https://192.0.2.10:8443"},
		{"http origin", "fwmon.example.test", "http://fwmon.example.test", ""},
		{"origin outside rp id", "fwmon.example.test", "https://evil.example.org", ""},
		{"origin with path", "fwmon.example.test", "https://fwmon.example.test/admin", ""},
		{"suffix trick", "example.test", "https://notexample.test", ""},
		{"nothing configured", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newPasskeyEnv(t, false)
			e.cfg.Auth.WebAuthnEnabled = true
			e.cfg.Auth.WebAuthnRPID = tc.rpID
			e.cfg.Auth.WebAuthnOrigins = tc.origins
			e.cfg.Alerts.PublicBaseURL = tc.base
			svc := passkey.Setup(e.cfg)
			if svc != nil {
				t.Fatalf("Setup accepted an invalid configuration: %+v", svc.Settings)
			}
			e.h.SetPasskeys(svc)
			e.createUser("root", auth.RoleAdmin, false)
			if rec := e.passwordLogin("root", ""); rec.Code != http.StatusOK {
				t.Fatalf("password login with invalid passkey config: %d", rec.Code)
			}
			if rec := e.do(http.MethodPost, "/api/auth/passkey/login/begin", "", nil, nil); rec.Code != http.StatusNotFound {
				t.Fatalf("passkey begin = %d, want 404", rec.Code)
			}
		})
	}
	// And a valid configuration is accepted (defaults from PUBLIC_BASE_URL).
	e := newPasskeyEnv(t, false)
	e.cfg.Auth.WebAuthnEnabled = true
	e.cfg.Alerts.PublicBaseURL = "https://FWMon.Example.test:8443"
	svc := passkey.Setup(e.cfg)
	if svc == nil || svc.Settings.RPID != "fwmon.example.test" || len(svc.Settings.Origins) != 1 || svc.Settings.Origins[0] != "https://fwmon.example.test:8443" {
		t.Fatalf("valid config rejected or mis-derived: %+v", svc)
	}
	e.cfg.Auth.WebAuthnEnabled = false
	if passkey.Setup(e.cfg) != nil {
		t.Fatal("WEBAUTHN_ENABLED=false must disable passkeys")
	}
}

// --- API tokens ----------------------------------------------------------------

// TestPasskey_APITokenForbidden: an admin-scope API token gets 403 on every
// passkey management route — tokens never register, list, rename or delete.
func TestPasskey_APITokenForbidden(t *testing.T) {
	e := newPasskeyEnv(t, true)
	root := e.createUser("root", auth.RoleAdmin, false)
	plaintext := database.APITokenPlaintextPrefix + "passkeytesttoken0123456789abcdefghijklmnopq"
	if err := e.db.CreateAPIToken(&models.ApiToken{Name: "ci", TokenHash: database.HashAPIToken(plaintext),
		Scope: "admin", CreatedBy: "root", CreatedByID: root.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.CreatePasskey(&models.WebAuthnCredential{AdminID: root.ID, CredentialID: []byte("cred"), PublicKey: []byte{1}, Name: "k"}, 0); err != nil {
		t.Fatal(err)
	}
	for _, ep := range allPasskeyEndpoints(root.ID) {
		if !strings.HasPrefix(ep[1], "/admin") {
			continue
		}
		rec := e.do(ep[0], ep[1], `{"password":"`+pkTestPass+`","name":"x"}`, nil,
			map[string]string{"Authorization": "Bearer " + plaintext})
		if rec.Code != http.StatusForbidden {
			t.Errorf("API token %s %s = %d, want 403 (%s)", ep[0], ep[1], rec.Code, rec.Body.String())
		}
	}
	if n := e.allPasskeyCount(); n != 1 {
		t.Fatalf("API token changed credentials: %d", n)
	}
}

// --- discoverable-login owner mapping ---------------------------------------

// registered sets up user name with one registered passkey; returns the
// account, its authenticator and a logged-in session.
func (e *pkEnv) registered(name, role string) (*models.Admin, *softAuth, *pkSession) {
	e.t.Helper()
	u := e.createUser(name, role, false)
	s := e.login(name, "")
	a := newSoftAuth(e.t)
	s.register(a, "", name+"-key")
	return u, a, s
}

// TestPasskey_HandleMismatchFails: the authenticator presents a user handle
// that is not the credential owner's stored handle — refused, even though the
// signature is valid; nothing about the credential is updated.
func TestPasskey_HandleMismatchFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)
	forged := append([]byte(nil), a.userHandle...)
	forged[0] ^= 0xff
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, forged))
	if r := e.passkeyRows(alice.ID)[0]; r.LastUsedAt != nil || r.SignCount != 0 {
		t.Fatalf("refused login updated the credential: %+v", r)
	}
	if !e.hasAudit("passkey_login_failure") {
		t.Fatal("failure not audited")
	}
}

// TestPasskey_CrossUserCredentialFails: alice's credential presented with
// bob's user handle must not produce a session for anyone.
func TestPasskey_CrossUserCredentialFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleViewer)
	_, b, _ := e.registered("bob", auth.RoleAdmin)
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, b.userHandle))
	if r := e.passkeyRows(alice.ID)[0]; r.LastUsedAt != nil {
		t.Fatalf("refused login updated alice's credential: %+v", r)
	}
}

// TestPasskey_DisabledOwnerFails: the owner is disabled — refused in the
// discoverable handler itself, before the credential is touched.
func TestPasskey_DisabledOwnerFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)
	if err := e.db.Gorm().Model(&models.Admin{}).Where("id = ?", alice.ID).Update("disabled", true).Error; err != nil {
		t.Fatal(err)
	}
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))
	if r := e.passkeyRows(alice.ID)[0]; r.LastUsedAt != nil || r.SignCount != 0 {
		t.Fatalf("disabled owner's credential was updated: %+v", r)
	}
}

// TestPasskey_DeletedOwnerFails: a credential row whose owner row is gone
// (FK not enforced on SQLite) is refused; and DeleteUser removes credentials
// so a re-created username never inherits them.
func TestPasskey_DeletedOwnerFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)
	if err := e.db.Gorm().Exec("DELETE FROM admins WHERE id = ?", alice.ID).Error; err != nil {
		t.Fatal(err)
	}
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))

	// Through the real admin route: credentials go with the account.
	e2 := newPasskeyEnv(t, true)
	e2.createUser("root", auth.RoleAdmin, false)
	bob, b, _ := e2.registered("bob", auth.RoleOperator)
	rs := e2.login("root", "")
	if rec := rs.do(http.MethodDelete, fmt.Sprintf("/admin/api/users/%d", bob.ID), ""); rec.Code != http.StatusOK {
		t.Fatalf("delete user: %d %s", rec.Code, rec.Body.String())
	}
	if n := e2.allPasskeyCount(); n != 0 {
		t.Fatalf("DeleteUser left %d credentials", n)
	}
	e2.createUser("bob", auth.RoleAdmin, false) // username reused
	assertGenericPasskeyFailure(t, e2.passkeyLogin(b, b.userHandle))
}

// TestPasskey_EmptyRoleFails (D5 on the passkey path): an owner whose role is
// empty or unknown gets no session.
func TestPasskey_EmptyRoleFails(t *testing.T) {
	for _, role := range []string{"", "superuser"} {
		e := newPasskeyEnv(t, true)
		alice, a, _ := e.registered("alice", auth.RoleOperator)
		if err := e.db.Gorm().Model(&models.Admin{}).Where("id = ?", alice.ID).Update("role", role).Error; err != nil {
			t.Fatal(err)
		}
		assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))
	}
}

// --- user verification ---------------------------------------------------------

// uvPreferredService builds a service whose LIBRARY config does not require
// UV — so only our explicit per-ceremony flag checks stand between a
// presence-only authenticator and an account.
func uvPreferredService(t *testing.T) *passkey.Service {
	t.Helper()
	svc, err := passkey.New(passkey.Settings{RPID: pkTestRPID, Origins: []string{pkTestOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	svc.WebAuthn.Config.AuthenticatorSelection.UserVerification = protocol.VerificationPreferred
	return svc
}

// TestPasskey_UV0LoginRejected: an assertion without the UV flag is refused —
// by the library under the pinned config, and by our own flag check even if
// the library config were weakened.
func TestPasskey_UV0LoginRejected(t *testing.T) {
	for _, weakened := range []bool{false, true} {
		var e *pkEnv
		if weakened {
			e = newPasskeyEnvWith(t, uvPreferredService(t))
		} else {
			e = newPasskeyEnv(t, true)
		}
		alice, a, _ := e.registered("alice", auth.RoleOperator)
		a.loginFlags &^= protocol.FlagUserVerified
		assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))
		if r := e.passkeyRows(alice.ID)[0]; r.LastUsedAt != nil {
			t.Fatalf("weakened=%v: UV=0 assertion updated the credential", weakened)
		}
	}
}

// TestPasskey_UV0RegistrationRejected: same for registration.
func TestPasskey_UV0RegistrationRejected(t *testing.T) {
	for _, weakened := range []bool{false, true} {
		var e *pkEnv
		if weakened {
			e = newPasskeyEnvWith(t, uvPreferredService(t))
		} else {
			e = newPasskeyEnv(t, true)
		}
		u := e.createUser("alice", auth.RoleOperator, false)
		s := e.login("alice", "")
		a := newSoftAuth(t)
		a.regFlags &^= protocol.FlagUserVerified
		beg := s.registerBegin(pkTestPass, "", "k")
		o := decodeOptions(t, beg)
		handle := mustB64(t, o.Data.PublicKey.User.ID)
		fin := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", a.registrationBody(o.Data.PublicKey.Challenge, handle))
		if fin.Code != http.StatusBadRequest {
			t.Fatalf("weakened=%v: UV=0 registration = %d %s", weakened, fin.Code, fin.Body.String())
		}
		if n := len(e.passkeyRows(u.ID)); n != 0 {
			t.Fatalf("weakened=%v: UV=0 credential stored", weakened)
		}
	}
}

// TestPasskey_LibraryConfigPinned: the library options the security model
// relies on are set (UV + resident key required, no attestation, enforced
// 5-minute timeouts — the session then carries an expiry).
func TestPasskey_LibraryConfigPinned(t *testing.T) {
	svc, err := passkey.New(passkey.Settings{RPID: pkTestRPID, Origins: []string{pkTestOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	c := svc.WebAuthn.Config
	if c.AuthenticatorSelection.UserVerification != protocol.VerificationRequired ||
		c.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired ||
		c.AttestationPreference != protocol.PreferNoAttestation ||
		!c.Timeouts.Login.Enforce || !c.Timeouts.Registration.Enforce ||
		c.Timeouts.Login.Timeout != 5*time.Minute || c.Timeouts.Registration.Timeout != 5*time.Minute {
		t.Fatalf("library config not pinned: %+v", c)
	}
	_, session, err := svc.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	if session.Expires.IsZero() || session.UserVerification != protocol.VerificationRequired {
		t.Fatalf("login session not expiring / UV not required: %+v", session)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeB64u(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return b
}

// --- ceremonies ----------------------------------------------------------------

// TestPasskey_CeremonyReuseFails: a finished ceremony cannot be finished again
// — neither by replaying the assertion nor by a freshly signed assertion over
// the same challenge (counter advanced, so only single use stops it).
func TestPasskey_CeremonyReuseFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	_, a, _ := e.registered("alice", auth.RoleOperator)
	challenge, ck := e.loginBegin()
	body := a.assertionBody(challenge, a.userHandle)
	if rec := e.loginFinish(ck, body); rec.Code != http.StatusOK {
		t.Fatalf("first finish: %d %s", rec.Code, rec.Body.String())
	}
	assertGenericPasskeyFailure(t, e.loginFinish(ck, body))
	assertGenericPasskeyFailure(t, e.loginFinish(ck, a.assertionBody(challenge, a.userHandle)))
}

// TestPasskey_CeremonyExpiredFails: a ceremony older than the TTL is refused
// by the store (independently of the library's own session expiry).
func TestPasskey_CeremonyExpiredFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	_, a, _ := e.registered("alice", auth.RoleOperator)
	challenge, ck := e.loginBegin()
	future := time.Now().Add(passkey.CeremonyTimeout + time.Second)
	e.h.passkeys.LoginCeremonies.SetClockForTesting(func() time.Time { return future })
	assertGenericPasskeyFailure(t, e.loginFinish(ck, a.assertionBody(challenge, a.userHandle)))
}

// TestPasskey_CeremonyMissingCookieFails: no cookie, or an unknown one, is
// the generic failure — and the cookie is cleared either way.
func TestPasskey_CeremonyMissingCookieFails(t *testing.T) {
	e := newPasskeyEnv(t, true)
	_, a, _ := e.registered("alice", auth.RoleOperator)
	challenge, _ := e.loginBegin()
	assertGenericPasskeyFailure(t, e.loginFinish(nil, a.assertionBody(challenge, a.userHandle)))
	assertGenericPasskeyFailure(t, e.loginFinish(&http.Cookie{Name: passkeyLoginCookie, Value: "bogus"}, a.assertionBody(challenge, a.userHandle)))
}

// TestPasskey_CeremonyWrongKindFails: a registration ceremony cannot be
// consumed as a login one (and vice versa), and the attempt consumes it.
func TestPasskey_CeremonyWrongKindFails(t *testing.T) {
	st := passkey.NewCeremonyStore(time.Minute, 10)
	st.Put("k", passkey.Ceremony{Kind: passkey.KindRegister, AdminID: 1})
	if _, ok := st.Take(passkey.KindLogin, "k"); ok {
		t.Fatal("registration ceremony consumed as a login")
	}
	if _, ok := st.Take(passkey.KindRegister, "k"); ok {
		t.Fatal("wrong-kind attempt must still consume the ceremony")
	}
	st.Put("l", passkey.Ceremony{Kind: passkey.KindLogin})
	if _, ok := st.Take(passkey.KindRegister, "l"); ok {
		t.Fatal("login ceremony consumed as a registration")
	}

	// Over HTTP: a registration ceremony's key as the login cookie.
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)
	_, sess, err := e.h.passkeys.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	key := passkey.RegistrationKey(alice.ID)
	e.h.passkeys.LoginCeremonies.Put(key, passkey.Ceremony{Kind: passkey.KindRegister, AdminID: alice.ID, Session: *sess})
	assertGenericPasskeyFailure(t, e.loginFinish(&http.Cookie{Name: passkeyLoginCookie, Value: key}, a.assertionBody(sess.Challenge, a.userHandle)))
}

// TestPasskey_CeremonyConcurrentDoubleFinish: many concurrent finishes of one
// ceremony — exactly one wins (store level and over HTTP).
func TestPasskey_CeremonyConcurrentDoubleFinish(t *testing.T) {
	st := passkey.NewCeremonyStore(time.Minute, 10)
	st.Put("k", passkey.Ceremony{Kind: passkey.KindLogin})
	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := st.Take(passkey.KindLogin, "k"); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("store: %d concurrent takes won, want exactly 1", wins)
	}

	e := newPasskeyEnv(t, true)
	_, a, _ := e.registered("alice", auth.RoleOperator)
	challenge, ck := e.loginBegin()
	body := a.assertionBody(challenge, a.userHandle)
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = e.loginFinish(ck, body).Code
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("HTTP: %d concurrent finishes succeeded (%v), want exactly 1", ok, codes)
	}
}

// TestPasskey_CeremonyCapEvictsOldest: the store never exceeds its cap.
func TestPasskey_CeremonyCapEvictsOldest(t *testing.T) {
	st := passkey.NewCeremonyStore(time.Minute, 3)
	base := time.Now()
	n := 0
	st.SetClockForTesting(func() time.Time { n++; return base.Add(time.Duration(n) * time.Millisecond) })
	for _, k := range []string{"a", "b", "c", "d"} {
		st.Put(k, passkey.Ceremony{Kind: passkey.KindLogin})
	}
	if l := st.Len(); l != 3 {
		t.Fatalf("store holds %d entries, cap 3", l)
	}
	if _, ok := st.Take(passkey.KindLogin, "a"); ok {
		t.Fatal("oldest entry was not evicted")
	}
	if _, ok := st.Take(passkey.KindLogin, "d"); !ok {
		t.Fatal("newest entry missing")
	}
}

// --- registration ----------------------------------------------------------------

// TestPasskey_RegisterReauthRequired: register-begin needs the current
// password and, for a 2FA account, a fresh unused TOTP code.
func TestPasskey_RegisterReauthRequired(t *testing.T) {
	e := newPasskeyEnv(t, true)
	root := e.createUser("root", auth.RoleAdmin, true)
	loginCode := totpCode(t, -1)
	s := e.login("root", loginCode)
	cases := []struct{ name, password, code string }{
		{"no password", "", totpCode(t, 0)},
		{"wrong password", "nope-nope-nope", totpCode(t, 0)},
		{"no totp", pkTestPass, ""},
		{"wrong totp", pkTestPass, "000000"},
		{"replayed login totp", pkTestPass, loginCode},
	}
	for _, tc := range cases {
		if tc.code == "000000" && (tc.code == totpCode(t, -1) || tc.code == totpCode(t, 0) || tc.code == totpCode(t, 1)) {
			continue
		}
		rec := s.registerBegin(tc.password, tc.code, "k")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
	if _, ok := e.h.passkeys.RegisterCeremonies.Take(passkey.KindRegister, passkey.RegistrationKey(root.ID)); ok {
		t.Fatal("a refused re-auth left a registration ceremony behind")
	}
	// A wrong password here never feeds the login lockout.
	if e.am.IsLocked("root", "192.0.2.1") {
		t.Fatal("re-auth failures locked the login")
	}
}

// TestPasskey_ReauthLimiter: the dedicated per-user limiter stops repeated
// re-auth attempts.
func TestPasskey_ReauthLimiter(t *testing.T) {
	e := newPasskeyEnv(t, true)
	e.createUser("alice", auth.RoleViewer, false)
	s := e.login("alice", "")
	got429 := false
	for i := 0; i < 8; i++ {
		if rec := s.registerBegin("wrong-password!", "", "k"); rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("per-user re-auth limiter never engaged")
	}
}

// TestPasskey_RegisterOtherAccountsCeremony: a registration ceremony belongs
// to the account that began it — another account cannot finish (or burn) it.
func TestPasskey_RegisterOtherAccountsCeremony(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice := e.createUser("alice", auth.RoleOperator, false)
	e.createUser("bob", auth.RoleAdmin, false)
	sa, sb := e.login("alice", ""), e.login("bob", "")
	beg := sa.registerBegin(pkTestPass, "", "alice-key")
	o := decodeOptions(t, beg)
	a := newSoftAuth(t)
	body := a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID))

	if rec := sb.do(http.MethodPost, "/admin/api/passkeys/register/finish", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("bob finishing alice's ceremony = %d %s", rec.Code, rec.Body.String())
	}
	if n := e.allPasskeyCount(); n != 0 {
		t.Fatal("credential stored from another account's ceremony")
	}
	// Alice's own ceremony is still intact.
	if rec := sa.do(http.MethodPost, "/admin/api/passkeys/register/finish", body); rec.Code != http.StatusOK {
		t.Fatalf("alice's finish after bob's attempt = %d %s", rec.Code, rec.Body.String())
	}
	if rows := e.passkeyRows(alice.ID); len(rows) != 1 {
		t.Fatalf("alice has %d passkeys", len(rows))
	}
}

// TestPasskey_RegisterDuplicateCredential: the same credential id cannot be
// registered twice — not by the same account, not by another.
func TestPasskey_RegisterDuplicateCredential(t *testing.T) {
	e := newPasskeyEnv(t, true)
	_, a, sa := e.registered("alice", auth.RoleOperator)
	e.createUser("bob", auth.RoleOperator, false)
	sb := e.login("bob", "")
	for name, s := range map[string]*pkSession{"same account": sa, "other account": sb} {
		beg := s.registerBegin(pkTestPass, "", "dup")
		o := decodeOptions(t, beg)
		rec := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s: duplicate credential = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if n := e.allPasskeyCount(); n != 1 {
		t.Fatalf("%d credentials stored, want 1", n)
	}
}

// TestPasskey_RegisterLimit: at most 10 passkeys per account, enforced at
// begin and again at finish.
func TestPasskey_RegisterLimit(t *testing.T) {
	e := newPasskeyEnv(t, true)
	u := e.createUser("alice", auth.RoleOperator, false)
	s := e.login("alice", "")
	for i := 0; i < database.MaxPasskeysPerUser-1; i++ {
		if err := e.db.CreatePasskey(&models.WebAuthnCredential{AdminID: u.ID, CredentialID: []byte(fmt.Sprintf("seed-%d", i)), PublicKey: []byte{1}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	// The 10th goes through begin; fill the slot before finish (race).
	beg := s.registerBegin(pkTestPass, "", "tenth")
	if beg.Code != http.StatusOK {
		t.Fatalf("begin with 9: %d", beg.Code)
	}
	if err := e.db.CreatePasskey(&models.WebAuthnCredential{AdminID: u.ID, CredentialID: []byte("seed-race"), PublicKey: []byte{1}}, 0); err != nil {
		t.Fatal(err)
	}
	o := decodeOptions(t, beg)
	a := newSoftAuth(t)
	fin := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID)))
	if fin.Code != http.StatusConflict {
		t.Fatalf("11th at finish = %d %s", fin.Code, fin.Body.String())
	}
	if rec := s.registerBegin(pkTestPass, "", "eleventh"); rec.Code != http.StatusConflict {
		t.Fatalf("begin with 10 = %d", rec.Code)
	}
	if n := len(e.passkeyRows(u.ID)); n != database.MaxPasskeysPerUser {
		t.Fatalf("%d passkeys stored", n)
	}
}

// --- management ------------------------------------------------------------------

// TestPasskey_OtherUsersKeyUntouchable: an operator and a viewer cannot list,
// rename or delete another account's passkey (owner-scoped queries), and only
// an admin may bulk-remove.
func TestPasskey_OtherUsersKeyUntouchable(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, _, _ := e.registered("alice", auth.RoleAdmin)
	keyID := e.passkeyRows(alice.ID)[0].ID
	for _, role := range []string{auth.RoleOperator, auth.RoleViewer} {
		e.createUser(role+"-user", role, false)
		s := e.login(role+"-user", "")
		if rec := s.do(http.MethodPut, fmt.Sprintf("/admin/api/passkeys/%d", keyID), `{"name":"pwned"}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s rename alice's key = %d", role, rec.Code)
		}
		if rec := s.do(http.MethodDelete, fmt.Sprintf("/admin/api/passkeys/%d", keyID), `{"password":"`+pkTestPass+`"}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s delete alice's key = %d", role, rec.Code)
		}
		if rec := s.do(http.MethodDelete, fmt.Sprintf("/admin/api/users/%d/passkeys", alice.ID), ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s bulk-remove = %d, want 403", role, rec.Code)
		}
		list := s.do(http.MethodGet, "/admin/api/passkeys", "")
		if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "alice-key") {
			t.Errorf("%s list leaked alice's key: %s", role, list.Body.String())
		}
	}
	rows := e.passkeyRows(alice.ID)
	if len(rows) != 1 || rows[0].Name != "alice-key" {
		t.Fatalf("alice's key changed: %+v", rows)
	}
}

// TestPasskey_RenameOwnKey: rename needs no re-auth and is audited.
func TestPasskey_RenameOwnKey(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, _, s := e.registered("alice", auth.RoleViewer)
	id := e.passkeyRows(alice.ID)[0].ID
	if rec := s.do(http.MethodPut, fmt.Sprintf("/admin/api/passkeys/%d", id), `{"name":"YubiKey"}`); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body.String())
	}
	if e.passkeyRows(alice.ID)[0].Name != "YubiKey" || !e.hasAudit("passkey_rename") {
		t.Fatal("rename not applied/audited")
	}
}

// TestPasskey_DeleteReissuesSession: deleting a passkey re-authenticates,
// bumps token_version (the old session dies) and returns a working session.
func TestPasskey_DeleteReissuesSession(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, _, s := e.registered("alice", auth.RoleOperator)
	other := e.login("alice", "") // a second session that must die
	id := e.passkeyRows(alice.ID)[0].ID
	before := e.admin(alice.ID).TokenVersion

	if rec := s.do(http.MethodDelete, fmt.Sprintf("/admin/api/passkeys/%d", id), `{"password":"wrong-password"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("delete without re-auth = %d", rec.Code)
	}
	rec := s.do(http.MethodDelete, fmt.Sprintf("/admin/api/passkeys/%d", id), `{"password":"`+pkTestPass+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if len(e.passkeyRows(alice.ID)) != 0 || !e.hasAudit("passkey_delete") {
		t.Fatal("passkey not deleted/audited")
	}
	if after := e.admin(alice.ID).TokenVersion; after != before+1 {
		t.Fatalf("token_version %d → %d, want +1", before, after)
	}
	if r := s.do(http.MethodGet, "/admin/api/me", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("old session still valid: %d", r.Code)
	}
	if r := other.do(http.MethodGet, "/admin/api/me", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("other session still valid: %d", r.Code)
	}
	fresh := e.sessionFrom(rec)
	if r := fresh.do(http.MethodGet, "/admin/api/passkeys", ""); r.Code != http.StatusOK {
		t.Fatalf("re-issued session rejected: %d", r.Code)
	}
}

// TestPasskey_AdminRemoveAll: the admin route removes every passkey of the
// target, ends its sessions and is audited.
func TestPasskey_AdminRemoveAll(t *testing.T) {
	e := newPasskeyEnv(t, true)
	e.createUser("root", auth.RoleAdmin, false)
	bob, _, bs := e.registered("bob", auth.RoleOperator)
	rs := e.login("root", "")
	rec := rs.do(http.MethodDelete, fmt.Sprintf("/admin/api/users/%d/passkeys", bob.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("remove all: %d %s", rec.Code, rec.Body.String())
	}
	if len(e.passkeyRows(bob.ID)) != 0 || !e.hasAudit("passkey_admin_remove_all") {
		t.Fatal("not removed/audited")
	}
	if r := bs.do(http.MethodGet, "/admin/api/me", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("bob's session survived: %d", r.Code)
	}
}

// TestPasskey_NewKeyNotice: after a registration the next password login and
// the list carry the notice. The session that registered the key cannot
// acknowledge it (a hijacked session must not hide its own rogue key); a
// later login can.
func TestPasskey_NewKeyNotice(t *testing.T) {
	e := newPasskeyEnv(t, true)
	_, _, s := e.registered("alice", auth.RoleOperator) // key registered in session s
	if ack := s.do(http.MethodPost, "/admin/api/passkeys/notices/ack", ""); ack.Code != http.StatusOK {
		t.Fatalf("ack: %d", ack.Code)
	}
	if list := s.do(http.MethodGet, "/admin/api/passkeys", ""); !strings.Contains(list.Body.String(), `"notices":[{"name":"alice-key"`) {
		t.Fatalf("the registering session hid its own key's notice: %s", list.Body.String())
	}

	// JWT iat has 1-second resolution: start the next session in a later
	// second than the registration.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(1100 * time.Millisecond)))
	rec := e.passwordLogin("alice", "")
	if !strings.Contains(rec.Body.String(), `"passkey_notices":[{"name":"alice-key"`) {
		t.Fatalf("password login carries no notice: %s", rec.Body.String())
	}
	s2 := e.sessionFrom(rec)
	if ack := s2.do(http.MethodPost, "/admin/api/passkeys/notices/ack", ""); ack.Code != http.StatusOK {
		t.Fatalf("ack in s2: %d", ack.Code)
	}
	if rec := e.passwordLogin("alice", ""); strings.Contains(rec.Body.String(), "passkey_notices") {
		t.Fatalf("notice survived the ack from a later session: %s", rec.Body.String())
	}
}

// --- clone warning -----------------------------------------------------------------

// TestPasskey_CloneWarningRejected: a counter that does not advance means a
// possibly cloned authenticator — refused, audited, counter not updated.
func TestPasskey_CloneWarningRejected(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)
	a.counter = 4 // next assertion reports 5
	if rec := e.passkeyLogin(a, a.userHandle); rec.Code != http.StatusOK {
		t.Fatalf("first login: %d %s", rec.Code, rec.Body.String())
	}
	a.counter = 4 // a clone replays the same counter value
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))
	if !e.hasAudit("passkey_clone_warning") {
		t.Fatalf("clone warning not audited: %v", e.auditActions())
	}
	if r := e.passkeyRows(alice.ID)[0]; r.SignCount != 5 {
		t.Fatalf("stored counter = %d, want 5 (not updated on the clone warning)", r.SignCount)
	}
}

// --- resets remove passkeys (D-RESET) ------------------------------------------------

func TestPasskey_AdminPasswordResetDeletesPasskeys(t *testing.T) {
	e := newPasskeyEnv(t, true)
	e.createUser("root", auth.RoleAdmin, false)
	bob, _, _ := e.registered("bob", auth.RoleOperator)
	rs := e.login("root", "")
	if rec := rs.do(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/reset-password", bob.ID), ""); rec.Code != http.StatusOK {
		t.Fatalf("reset-password: %d %s", rec.Code, rec.Body.String())
	}
	if n := len(e.passkeyRows(bob.ID)); n != 0 {
		t.Fatalf("admin password reset left %d passkeys", n)
	}
}

func TestPasskey_Admin2FAResetDeletesPasskeys(t *testing.T) {
	e := newPasskeyEnv(t, true)
	e.createUser("root", auth.RoleAdmin, false)
	bob, _, _ := e.registered("bob", auth.RoleOperator)
	rs := e.login("root", "")
	if rec := rs.do(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/reset-2fa", bob.ID), ""); rec.Code != http.StatusOK {
		t.Fatalf("reset-2fa: %d %s", rec.Code, rec.Body.String())
	}
	if n := len(e.passkeyRows(bob.ID)); n != 0 {
		t.Fatalf("admin 2FA reset left %d passkeys", n)
	}
}

// TestPasskey_ChangePasswordRemovePasskeys: remove_passkeys absent ⇒ delete,
// true ⇒ delete, explicit false ⇒ keep. Works with passkeys disabled too.
func TestPasskey_ChangePasswordRemovePasskeys(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		keep  bool
	}{
		{"absent", "", false},
		{"true", `,"remove_passkeys":true`, false},
		{"false", `,"remove_passkeys":false`, true},
	}
	for _, tc := range cases {
		for _, enabled := range []bool{true, false} {
			e := newPasskeyEnv(t, true)
			alice, _, _ := e.registered("alice", auth.RoleViewer)
			if !enabled {
				e.h.SetPasskeys(nil)
			}
			s := e.login("alice", "")
			rec := s.do(http.MethodPost, "/admin/api/settings/password",
				`{"current_password":"`+pkTestPass+`","new_password":"a-brand-new-password"`+tc.extra+`}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s/enabled=%v: change password %d %s", tc.name, enabled, rec.Code, rec.Body.String())
			}
			n := len(e.passkeyRows(alice.ID))
			if tc.keep && n != 1 || !tc.keep && n != 0 {
				t.Fatalf("%s/enabled=%v: %d passkeys after change, keep=%v", tc.name, enabled, n, tc.keep)
			}
		}
	}
}

func decodeB64u(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// --- review follow-ups -------------------------------------------------------------

// TestPasskey_RegisterFinishAfterResetRejected simulates the reset vs.
// in-flight registration interleaving: register-finish has already passed
// the auth middleware (session token_version N) and taken its ceremony when
// an admin reset bumps the account to N+1 and deletes its passkeys. The
// insert must be refused and nothing stored.
func TestPasskey_RegisterFinishAfterResetRejected(t *testing.T) {
	e := newPasskeyEnv(t, true)
	e.createUser("root", auth.RoleAdmin, false)
	alice := e.createUser("alice", auth.RoleOperator, false)
	sa := e.login("alice", "")
	beg := sa.registerBegin(pkTestPass, "", "late-key")
	o := decodeOptions(t, beg)
	a := newSoftAuth(t)
	body := a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID))
	key := passkey.RegistrationKey(alice.ID)
	ceremony, ok := e.h.passkeys.RegisterCeremonies.Take(passkey.KindRegister, key)
	if !ok {
		t.Fatal("no ceremony after begin")
	}
	staleTV := e.admin(alice.ID).TokenVersion

	// The reset lands now.
	rs := e.login("root", "")
	if rec := rs.do(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/reset-password", alice.ID), ""); rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if e.admin(alice.ID).TokenVersion == staleTV {
		t.Fatal("reset did not bump token_version")
	}

	// The finish that was already past the middleware continues.
	e.h.passkeys.RegisterCeremonies.Put(key, ceremony)
	c, rec := jsonReq(http.MethodPost, "/admin/api/passkeys/register/finish", body)
	c.Set("auth_method", "session")
	c.Set("user_id", alice.ID)
	c.Set("username", "alice")
	c.Set("token_version", staleTV)
	e.h.PasskeyRegisterFinish(c)
	if rec.Code == http.StatusOK {
		t.Fatalf("registration committed after the reset: %s", rec.Body.String())
	}
	if n := len(e.passkeyRows(alice.ID)); n != 0 {
		t.Fatalf("%d passkeys stored after the reset", n)
	}
}

// TestPasskey_ResetDiscardsRegistrationCeremony: every reset drops the
// account's outstanding registration ceremony.
func TestPasskey_ResetDiscardsRegistrationCeremony(t *testing.T) {
	for _, path := range []string{"reset-password", "reset-2fa", "passkeys"} {
		e := newPasskeyEnv(t, true)
		e.createUser("root", auth.RoleAdmin, false)
		alice := e.createUser("alice", auth.RoleOperator, false)
		if rec := e.login("alice", "").registerBegin(pkTestPass, "", "k"); rec.Code != http.StatusOK {
			t.Fatalf("begin: %d", rec.Code)
		}
		rs := e.login("root", "")
		method := http.MethodPost
		if path == "passkeys" {
			method = http.MethodDelete
		}
		if rec := rs.do(method, fmt.Sprintf("/admin/api/users/%d/%s", alice.ID, path), ""); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		if _, ok := e.h.passkeys.RegisterCeremonies.Take(passkey.KindRegister, passkey.RegistrationKey(alice.ID)); ok {
			t.Fatalf("%s left the registration ceremony in place", path)
		}
	}
}

// TestPasskey_AdminRemoveAllOwnAccountReissues: an admin removing their own
// passkeys gets their session re-issued in the response.
func TestPasskey_AdminRemoveAllOwnAccountReissues(t *testing.T) {
	e := newPasskeyEnv(t, true)
	root, _, rs := e.registered("root", auth.RoleAdmin)
	rec := rs.do(http.MethodDelete, fmt.Sprintf("/admin/api/users/%d/passkeys", root.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("remove own: %d %s", rec.Code, rec.Body.String())
	}
	if len(e.passkeyRows(root.ID)) != 0 {
		t.Fatal("passkeys not removed")
	}
	if r := rs.do(http.MethodGet, "/admin/api/me", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived: %d", r.Code)
	}
	if r := e.sessionFrom(rec).do(http.MethodGet, "/admin/api/passkeys", ""); r.Code != http.StatusOK {
		t.Fatalf("re-issued session rejected: %d", r.Code)
	}
}

// TestPasskey_LoginFloodCannotEvictRegistration: filling the login ceremony
// store (unauthenticated) never evicts an in-flight registration.
func TestPasskey_LoginFloodCannotEvictRegistration(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice := e.createUser("alice", auth.RoleOperator, false)
	s := e.login("alice", "")
	beg := s.registerBegin(pkTestPass, "", "k")
	o := decodeOptions(t, beg)
	for i := 0; i < passkey.DefaultCeremonyCap+50; i++ {
		if rec := e.do(http.MethodPost, "/api/auth/passkey/login/begin", "", nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("login begin %d: %d", i, rec.Code)
		}
	}
	if n := e.h.passkeys.LoginCeremonies.Len(); n != passkey.DefaultCeremonyCap {
		t.Fatalf("login store holds %d", n)
	}
	a := newSoftAuth(t)
	fin := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID)))
	if fin.Code != http.StatusOK {
		t.Fatalf("registration after a login flood: %d %s", fin.Code, fin.Body.String())
	}
	if len(e.passkeyRows(alice.ID)) != 1 {
		t.Fatal("passkey not stored")
	}
}

// TestPasskey_WrongOriginRPIDTypeRejected: real library verification refuses
// an assertion/attestation from another origin, for another RP ID, or (login)
// with the creation clientData type.
func TestPasskey_WrongOriginRPIDTypeRejected(t *testing.T) {
	const evilOrigin, evilRPID = "https://evil.example.test", "evil.example.test"
	login := map[string]func(a *softAuth){
		"origin": func(a *softAuth) { a.origin = evilOrigin },
		"rp id":  func(a *softAuth) { a.rpID = evilRPID },
		"type":   func(a *softAuth) { a.assertType = "webauthn.create" },
	}
	for name, mutate := range login {
		e := newPasskeyEnv(t, true)
		alice, a, _ := e.registered("alice", auth.RoleOperator)
		mutate(a)
		assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))
		if r := e.passkeyRows(alice.ID)[0]; r.LastUsedAt != nil {
			t.Fatalf("login %s: credential updated", name)
		}
	}
	reg := map[string]func(a *softAuth){
		"origin": func(a *softAuth) { a.origin = evilOrigin },
		"rp id":  func(a *softAuth) { a.rpID = evilRPID },
	}
	for name, mutate := range reg {
		e := newPasskeyEnv(t, true)
		u := e.createUser("alice", auth.RoleOperator, false)
		s := e.login("alice", "")
		o := decodeOptions(t, s.registerBegin(pkTestPass, "", "k"))
		a := newSoftAuth(t)
		mutate(a)
		fin := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", a.registrationBody(o.Data.PublicKey.Challenge, mustB64(t, o.Data.PublicKey.User.ID)))
		if fin.Code != http.StatusBadRequest || len(e.passkeyRows(u.ID)) != 0 {
			t.Fatalf("registration %s: %d %s", name, fin.Code, fin.Body.String())
		}
	}
}

// --- sign-count compare-and-set (v0.11.283) ------------------------------------------

// staleRowsStore serves the login lookup a frozen snapshot of the owner's
// credential rows while every write goes to the real database. It reproduces
// the window in which a clone's assertion read the row before the original's
// counter write committed, deterministically.
type staleRowsStore struct {
	database.Store
	rows []models.WebAuthnCredential
}

func (s *staleRowsStore) WithContextStore(context.Context) database.Store { return s }
func (s *staleRowsStore) ListPasskeys(uint) ([]models.WebAuthnCredential, error) {
	return append([]models.WebAuthnCredential(nil), s.rows...), nil
}

// TestPasskey_StaleCounterRead_RefusedAtCommit: an assertion that passed the
// clone check against a stale row (counter 5 > stale 0) is refused when the
// counter write finds the row already at 5 — audited as a clone warning, no
// session, counter untouched. Before v0.11.283 the write was unconditional
// and this login succeeded.
func TestPasskey_StaleCounterRead_RefusedAtCommit(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)
	stale := e.passkeyRows(alice.ID) // sign_count 0, never used

	a.counter = 4 // the genuine assertion reports 5
	if rec := e.passkeyLogin(a, a.userHandle); rec.Code != http.StatusOK {
		t.Fatalf("first login: %d %s", rec.Code, rec.Body.String())
	}
	if r := e.passkeyRows(alice.ID)[0]; r.SignCount != 5 {
		t.Fatalf("stored counter = %d, want 5", r.SignCount)
	}

	e.h.db = &staleRowsStore{Store: e.db, rows: stale}
	a.counter = 4 // the clone also reports 5, having read the row at 0
	var before []models.LoginAttempt
	e.db.Gorm().Find(&before)
	assertGenericPasskeyFailure(t, e.passkeyLogin(a, a.userHandle))

	if !e.hasAudit("passkey_clone_warning") {
		t.Fatalf("clone warning not audited: %v", e.auditActions())
	}
	if r := e.passkeyRows(alice.ID)[0]; r.SignCount != 5 {
		t.Fatalf("stored counter = %d, want 5 (unchanged by the refused assertion)", r.SignCount)
	}
	var after []models.LoginAttempt
	e.db.Gorm().Order("id").Find(&after)
	if len(after) != len(before)+1 {
		t.Fatalf("login_attempts rows: %d → %d, want one new failure row", len(before), len(after))
	}
	if last := after[len(after)-1]; last.Success || last.Username != "alice" || last.Method == nil || *last.Method != "passkey" {
		t.Fatalf("refused assertion recorded as %+v", last)
	}
}

// TestPasskey_ConcurrentSameCounter_OneSession: two finishes carrying the
// same counter race each other — whichever interleaving the scheduler picks,
// exactly one session is issued and the other is refused as a clone.
func TestPasskey_ConcurrentSameCounter_OneSession(t *testing.T) {
	e := newPasskeyEnv(t, true)
	alice, a, _ := e.registered("alice", auth.RoleOperator)

	const n = 2
	var bodies [n]string
	var cookies [n]*http.Cookie
	for i := range bodies {
		challenge, ck := e.loginBegin()
		a.counter = 4 // both assertions report 5
		bodies[i], cookies[i] = a.assertionBody(challenge, a.userHandle), ck
	}
	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recs[i] = e.loginFinish(cookies[i], bodies[i])
		}(i)
	}
	wg.Wait()

	sessions := 0
	for i, rec := range recs {
		switch rec.Code {
		case http.StatusOK:
			sessions++
			e.sessionFrom(rec)
		case http.StatusUnauthorized:
			assertGenericPasskeyFailure(t, rec)
		default:
			t.Fatalf("finish %d: unexpected status %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if sessions != 1 {
		t.Fatalf("%d sessions issued for two assertions with the same counter, want exactly 1", sessions)
	}
	if !e.hasAudit("passkey_clone_warning") {
		t.Fatalf("clone warning not audited: %v", e.auditActions())
	}
	if r := e.passkeyRows(alice.ID)[0]; r.SignCount != 5 {
		t.Fatalf("stored counter = %d, want 5", r.SignCount)
	}
}

// TestPasskey_ZeroCounterAuthenticatorLogsInRepeatedly: an authenticator
// that never counts (every assertion reports 0 — most synced passkeys) keeps
// working: the compare-and-set accepts 0 over a stored 0 every time. This
// also passed before the compare-and-set; it guards its "both zero" clause
// against a stricter variant (plain sign_count < ?).
func TestPasskey_ZeroCounterAuthenticatorLogsInRepeatedly(t *testing.T) {
	e := newPasskeyEnv(t, true)
	e.createUser("alice", auth.RoleOperator, false)
	s := e.login("alice", "")
	a := newSoftAuth(t)
	a.zeroCounter = true
	s.register(a, "", "synced")

	for i := 0; i < 3; i++ {
		rec := e.passkeyLogin(a, a.userHandle)
		if rec.Code != http.StatusOK {
			t.Fatalf("login %d with a zero counter: %d %s", i+1, rec.Code, rec.Body.String())
		}
		e.sessionFrom(rec)
	}
	alice, _ := e.db.GetAdminByUsername("alice")
	if r := e.passkeyRows(alice.ID)[0]; r.SignCount != 0 || r.LastUsedAt == nil {
		t.Fatalf("zero-counter row = sign_count %d last_used %v", r.SignCount, r.LastUsedAt)
	}
	if e.hasAudit("passkey_clone_warning") {
		t.Fatalf("zero-counter authenticator flagged as a clone: %v", e.auditActions())
	}
}
