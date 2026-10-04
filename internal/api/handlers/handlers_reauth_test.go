package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

// Auth hardening D2 / D4 / D8 (v0.11.289): the 2FA retry budget survives a
// password round-trip, every in-session re-authentication is rate-limited
// per account without touching the login lockout, and self-service account
// actions resolve the account from the session's user_id (browser sessions
// only — API-token principals are refused).

// sessionCtx builds an AdminAuth-shaped context: identity + auth_method.
func sessionCtx(method, path, body, username string, userID uint, authMethod string) (*gin.Context, *httptest.ResponseRecorder) {
	c, rec := jsonReq(method, path, body)
	c.Set("username", username)
	c.Set("user_id", userID)
	c.Set("role", auth.RoleAdmin)
	c.Set("auth_method", authMethod)
	return c, rec
}

// TestTOTPLogin_BudgetSurvivesPasswordRoundTrip_D2 is the end-to-end attack:
// with the budget at 3, password ok → wrong code ×2 → password ok again →
// wrong code → the account is locked for both stages. Pre-fix the second
// password check reset the counter and the attacker kept two fresh guesses
// per round-trip.
func TestTOTPLogin_BudgetSurvivesPasswordRoundTrip_D2(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, hardeningTOTPSecret) // MaxLoginAttempts = 3

	pendingOf := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("password stage: status = %d (body=%s)", rec.Code, rec.Body.String())
		}
		ck := cookieByName(rec, "pending_2fa")
		if ck == nil {
			t.Fatal("no pending_2fa cookie")
		}
		return ck.Value
	}

	pending := pendingOf(loginReq(h))
	for i := 0; i < 2; i++ {
		if rec := totpReq(h, pending, "000000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: status = %d, want 401 (body=%s)", i+1, rec.Code, rec.Body.String())
		}
	}
	// Second password round-trip must not hand out a fresh budget.
	pending = pendingOf(loginReq(h))
	if rec := totpReq(h, pending, "000000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("third wrong code: status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := loginReq(h); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("D2 regression: password stage after 3 TOTP failures = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := totpReq(h, pending, "000000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("TOTP stage after 3 failures = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestTOTPLogin_CompletedLoginClearsBudget_D2: the legitimate flow is
// unchanged — a valid code after some failures issues the session and empties
// the bucket, so the next login starts fresh.
func TestTOTPLogin_CompletedLoginClearsBudget_D2(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, hardeningTOTPSecret)
	rec := loginReq(h)
	pending := cookieByName(rec, "pending_2fa").Value
	if rec := totpReq(h, pending, "000000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	if rec := totpReq(h, pending, code); rec.Code != http.StatusOK || cookieByName(rec, "auth_token") == nil {
		t.Fatalf("valid code: status = %d, session cookie = %v (body=%s)", rec.Code, cookieByName(rec, "auth_token") != nil, rec.Body.String())
	}
	if h.authManager.IsLocked("root", "192.0.2.1") {
		t.Fatal("bucket not cleared by the completed login")
	}
}

// reauthEndpoint is one password-re-verifying self-service action.
type reauthEndpoint struct {
	name string
	path string
	body func(password string) string
	call func(h *Handler, c *gin.Context)
	// wantWrong is the status for a wrong password; the 6th attempt is 429.
	wantWrong int
}

func reauthEndpoints(deviceID uint) []reauthEndpoint {
	dev := strconv.FormatUint(uint64(deviceID), 10)
	return []reauthEndpoint{
		{"ChangePassword", "/admin/api/settings/password",
			func(p string) string { return `{"current_password":"` + p + `","new_password":"a-new-password-1"}` },
			func(h *Handler, c *gin.Context) { h.ChangePassword(c) }, http.StatusForbidden},
		{"Setup2FA", "/admin/api/2fa/setup",
			func(p string) string { return `{"password":"` + p + `"}` },
			func(h *Handler, c *gin.Context) { h.Setup2FA(c) }, http.StatusForbidden},
		{"Disable2FA", "/admin/api/2fa/disable",
			func(p string) string { return `{"password":"` + p + `","code":"000000"}` },
			func(h *Handler, c *gin.Context) { h.Disable2FA(c) }, http.StatusForbidden},
		{"RevealDeviceSecret", "/admin/api/devices/" + dev + "/reveal-secret",
			func(p string) string { return `{"password":"` + p + `","field":"ssh_password"}` },
			func(h *Handler, c *gin.Context) {
				c.Params = gin.Params{{Key: "id", Value: dev}}
				h.RevealDeviceSecret(c)
			}, http.StatusForbidden},
		{"PurgeDevice", "/admin/api/devices/" + dev + "/purge",
			func(p string) string { return `{"confirm_name":"fw","password":"` + p + `"}` },
			func(h *Handler, c *gin.Context) {
				c.Params = gin.Params{{Key: "id", Value: dev}}
				h.PurgeDevice(c)
			}, http.StatusForbidden},
	}
}

// TestReauth_PerAccountLimiter_LoginLockoutUntouched_D4: on every endpoint
// family that re-verifies the password inside a session, 5 wrong passwords
// are 403 and the 6th is 429 — and none of them count toward the login
// lockout (the real operator can still log in; a hijacked session cannot lock
// them out). Pre-fix there was no limit at all (only the route-level 1 req/s
// limiter on two of them) and the 6th attempt was another 403.
func TestReauth_PerAccountLimiter_LoginLockoutUntouched_D4(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for i, ep := range reauthEndpoints(0) {
		t.Run(ep.name, func(t *testing.T) {
			h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw") // MaxLoginAttempts = 3
			dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "ssh-pw"}
			if err := db.Gorm().Create(dev).Error; err != nil {
				t.Fatalf("create device: %v", err)
			}
			if err := db.RetireDevice(dev.ID); err != nil {
				t.Fatalf("retire: %v", err)
			}
			ep := reauthEndpoints(dev.ID)[i]

			for i := 1; i <= 5; i++ {
				c, rec := sessionCtx(http.MethodPost, ep.path, ep.body("wrong-password"), "admin1", u.ID, "session")
				ep.call(h, c)
				if rec.Code != ep.wantWrong {
					t.Fatalf("attempt %d: status = %d, want %d (body=%s)", i, rec.Code, ep.wantWrong, rec.Body.String())
				}
			}
			// 6th attempt — even with the RIGHT password — is refused by the
			// per-account budget (every attempt counts).
			c, rec := sessionCtx(http.MethodPost, ep.path, ep.body("s3cret-pw"), "admin1", u.ID, "session")
			ep.call(h, c)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("D4 regression: 6th attempt = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
			}
			if errorBody(t, rec) != reauthLimitedMsg {
				t.Fatalf("429 body = %s", rec.Body.String())
			}
			// The login lockout is untouched: not locked, and the real password
			// still logs in from the same source.
			if h.authManager.IsLocked("admin1", "192.0.2.1") {
				t.Fatal("in-session re-auth failures must not feed the login lockout")
			}
			if err := h.authManager.ValidateCredentials("admin1", "s3cret-pw", "192.0.2.1"); err != nil {
				t.Fatalf("login after re-auth failures: %v", err)
			}
			// Another account's budget is separate.
			other := &models.Admin{Username: "other", Password: u.Password, Role: auth.RoleAdmin}
			if err := db.Gorm().Create(other).Error; err != nil {
				t.Fatalf("seed other: %v", err)
			}
			c, rec = sessionCtx(http.MethodPost, ep.path, ep.body("wrong-password"), "other", other.ID, "session")
			ep.call(h, c)
			if rec.Code != ep.wantWrong {
				t.Fatalf("other account: status = %d, want %d (body=%s)", rec.Code, ep.wantWrong, rec.Body.String())
			}
		})
	}
}

// TestReauth_TokenPrincipalRefused_D8: an API token carries user_id = its
// CREATOR's id, so a by-id lookup would make the token act on that account —
// every self-service account action refuses auth_method "token" with 403
// before touching anything. Pre-fix these failed by accident (the username
// "token:<name>" matched no row — a 500 or a misleading 403); with by-id
// lookup and no explicit refusal they would succeed against the creator.
func TestReauth_TokenPrincipalRefused_D8(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "ssh-pw"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := db.RetireDevice(dev.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	type call struct {
		name string
		path string
		body string
		call func(c *gin.Context)
	}
	calls := []call{
		{"Verify2FA", "/admin/api/2fa/verify", `{"code":"000000"}`, h.Verify2FA},
		{"UpdateProfile", "/admin/api/me", `{"email":"x@example.test","full_name":"X"}`, h.UpdateProfile},
		{"SetMyDashboardPrefs", "/admin/api/me/dashboard", `{"prefs":"{}"}`, h.SetMyDashboardPrefs},
		{"GetMyDashboardPrefs", "/admin/api/me/dashboard", ``, h.GetMyDashboardPrefs},
		{"DeclineMFAPrompt", "/admin/api/me/mfa-decline", `{"acknowledge_risk":true}`, h.DeclineMFAPrompt},
	}
	for _, ep := range reauthEndpoints(dev.ID) {
		ep := ep
		calls = append(calls, call{ep.name, ep.path, ep.body("s3cret-pw"), func(c *gin.Context) { ep.call(h, c) }})
	}
	for _, tc := range calls {
		c, rec := sessionCtx(http.MethodPost, tc.path, tc.body, "token:deploy", u.ID, "token")
		tc.call(c)
		if rec.Code != http.StatusForbidden || errorBody(t, rec) != sessionOnlyMsg {
			t.Errorf("%s with an API token: status = %d body=%s, want 403 %q", tc.name, rec.Code, rec.Body.String(), sessionOnlyMsg)
		}
	}
	// Nothing was written to the creator's row.
	row, _ := db.GetAdminByID(u.ID)
	if row.Email != "" || row.TOTPSecret != "" || row.MFAPromptDismissedAt != nil || row.DashboardPrefs != "" || row.Password != u.Password {
		t.Fatalf("token principal modified the creator's account: %+v", row)
	}
	// GetMe for a token keeps the identity fields and carries no profile.
	c, rec := sessionCtx(http.MethodGet, "/admin/api/me", "", "token:deploy", u.ID, "token")
	if err := db.UpdateAdminProfile(u.ID, "creator@example.test", "Creator"); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	h.GetMe(c)
	var me struct {
		Data struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GetMe: status %d err %v body %s", rec.Code, err, rec.Body.String())
	}
	if me.Data.Username != "token:deploy" || me.Data.Email != "" {
		t.Fatalf("GetMe for a token must not expose the creator's profile: %+v", me.Data)
	}
}

// TestReauth_SessionActsOnUserIDNotUsername_D8: a session whose username
// claim names ANOTHER account acts on its own user_id. With the victim's
// password in the body, the by-username code verified it against the
// victim's hash and wrote to the victim's row; now the password is checked
// against the session's own account (403) and the victim is untouched.
func TestReauth_SessionActsOnUserIDNotUsername_D8(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, db, attacker := profileTestHandler(t, "attacker", auth.RoleAdmin, "attacker-pw")
	victimHash, err := h.authManager.HashPassword("victim-pw")
	if err != nil {
		t.Fatal(err)
	}
	victim := &models.Admin{Username: "victim", Password: victimHash, Role: auth.RoleAdmin}
	if err := db.Gorm().Create(victim).Error; err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	// Setup2FA with the VICTIM's password on a session {username: victim,
	// user_id: attacker} — must be refused, and the victim gets no secret.
	c, rec := sessionCtx(http.MethodPost, "/admin/api/2fa/setup", `{"password":"victim-pw"}`, "victim", attacker.ID, "session")
	h.Setup2FA(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("D8 regression: Setup2FA by username claim = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// ChangePassword likewise.
	c, rec = sessionCtx(http.MethodPost, "/admin/api/settings/password", `{"current_password":"victim-pw","new_password":"owned-by-attacker"}`, "victim", attacker.ID, "session")
	h.ChangePassword(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("D8 regression: ChangePassword by username claim = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// UpdateProfile writes the session's OWN row, never the named one.
	c, rec = sessionCtx(http.MethodPut, "/admin/api/me", `{"email":"me@example.test","full_name":"Me"}`, "victim", attacker.ID, "session")
	h.UpdateProfile(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("UpdateProfile: %d (body=%s)", rec.Code, rec.Body.String())
	}
	v, _ := db.GetAdminByID(victim.ID)
	a, _ := db.GetAdminByID(attacker.ID)
	if v.TOTPSecret != "" || v.Password != victimHash || v.Email != "" {
		t.Fatalf("victim row was touched: %+v", v)
	}
	if a.Email != "me@example.test" || a.Password != attacker.Password {
		t.Fatalf("own row not updated as expected: %+v", a)
	}

	// The same session with its OWN password works on its own account.
	c, rec = sessionCtx(http.MethodPost, "/admin/api/2fa/setup", `{"password":"attacker-pw"}`, "victim", attacker.ID, "session")
	h.Setup2FA(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("Setup2FA with own password: %d (body=%s)", rec.Code, rec.Body.String())
	}
	a, _ = db.GetAdminByID(attacker.ID)
	v, _ = db.GetAdminByID(victim.ID)
	if a.TOTPSecret == "" || v.TOTPSecret != "" {
		t.Fatalf("enrollment landed on the wrong row: own=%q victim=%q", a.TOTPSecret, v.TOTPSecret)
	}
}

// TestReauth_NoIdentity_401 pins the fail-closed path: a request that never
// passed AdminAuth (no auth_method) is 401, not a token refusal.
func TestReauth_NoIdentity_401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _, _ := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	c, rec := jsonReq(http.MethodPost, "/admin/api/2fa/setup", `{"password":"s3cret-pw"}`)
	h.Setup2FA(c)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestTOTP_EnrollVerifyDisable_RealDB pins the whole self-service 2FA cycle
// over the real store, now that the handlers read the row by id: the staged
// secret is written encrypted, Verify2FA validates through the decryption
// chain and writes the stored ciphertext back UNCHANGED (not re-encrypted),
// the login path then sees the same plaintext secret, and Disable2FA
// (password + current code) clears it.
func TestTOTP_EnrollVerifyDisable_RealDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	db.SetEncryptionKeyForTesting("test-field-encryption-key") // real {enc} ciphertext, not the keyless identity

	c, rec := sessionCtx(http.MethodPost, "/admin/api/2fa/setup", `{"password":"s3cret-pw"}`, "admin1", u.ID, "session")
	h.Setup2FA(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: %d (body=%s)", rec.Code, rec.Body.String())
	}
	var setup struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil || setup.Data.Secret == "" {
		t.Fatalf("setup body: %v %s", err, rec.Body.String())
	}
	staged, _ := db.GetAdminByID(u.ID)
	if staged.TOTPSecret == setup.Data.Secret {
		t.Fatal("staged secret is stored in plaintext")
	}

	code, _ := totp.GenerateCode(setup.Data.Secret, time.Now())
	c, rec = sessionCtx(http.MethodPost, "/admin/api/2fa/verify", `{"code":"`+code+`"}`, "admin1", u.ID, "session")
	h.Verify2FA(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d (body=%s)", rec.Code, rec.Body.String())
	}
	enabled, _ := db.GetAdminByID(u.ID)
	if !enabled.TOTPEnabled || enabled.TOTPSecret != staged.TOTPSecret {
		t.Fatalf("verify must enable 2FA and keep the stored ciphertext as is: enabled=%v same=%v", enabled.TOTPEnabled, enabled.TOTPSecret == staged.TOTPSecret)
	}
	// The login path (by username, decrypted by the store) sees the secret.
	authRow, err := db.GetAdminByUsername("admin1")
	if err != nil || authRow == nil || !authRow.TOTPEnabled || authRow.TOTPSecret != setup.Data.Secret {
		t.Fatalf("login view of the enrolled secret is wrong: %v %+v", err, authRow)
	}

	// Disable with the password and a FRESH code (the verify code is spent).
	c, rec = sessionCtx(http.MethodPost, "/admin/api/2fa/disable", `{"password":"s3cret-pw","code":"`+code+`"}`, "admin1", u.ID, "session")
	h.Disable2FA(c)
	if rec.Code != http.StatusForbidden || errorBody(t, rec) != totpCodeAlreadyUsedMsg {
		t.Fatalf("disable with the spent verify code: %d %s", rec.Code, rec.Body.String())
	}
	fresh, _ := totp.GenerateCode(setup.Data.Secret, time.Now().Add(-30*time.Second))
	if fresh == code {
		fresh, _ = totp.GenerateCode(setup.Data.Secret, time.Now().Add(30*time.Second))
	}
	c, rec = sessionCtx(http.MethodPost, "/admin/api/2fa/disable", `{"password":"s3cret-pw","code":"`+fresh+`"}`, "admin1", u.ID, "session")
	h.Disable2FA(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: %d (body=%s)", rec.Code, rec.Body.String())
	}
	if after, _ := db.GetAdminByID(u.ID); after.TOTPEnabled || after.TOTPSecret != "" {
		t.Fatalf("2FA not cleared: %+v", after)
	}
}
