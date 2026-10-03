package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

// PR 1 auth hardening: D1 (no user-1 fallback), D5 (empty role never admin),
// the shared TOTP replay guard, and the completeLogin extraction.

const hardeningTOTPSecret = "JBSWY3DPEHPK3PXP"

func loginReq(h *Handler) *httptest.ResponseRecorder {
	c, rec := jsonReq(http.MethodPost, "/api/auth/login", `{"username":"root","password":"correct-horse"}`)
	h.Login(c)
	return rec
}

func totpReq(h *Handler, pending, code string) *httptest.ResponseRecorder {
	c, rec := jsonReq(http.MethodPost, "/api/auth/totp", `{"code":"`+code+`"}`)
	c.Request.AddCookie(&http.Cookie{Name: "pending_2fa", Value: pending})
	h.TOTPLogin(c)
	return rec
}

func assertNoSession(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range []string{"auth_token", "csrf_token"} {
		if ck := cookieByName(rec, name); ck != nil && ck.MaxAge >= 0 {
			t.Errorf("%s cookie must not be set, got %+v", name, ck)
		}
	}
}

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if resp.Success {
		t.Errorf("success must be false, body=%s", rec.Body.String())
	}
	return resp.Error
}

// TestLogin_D1_SecondLookupFailure_NoSession: the password verifies, then the
// handler's own account lookup fails. Pre-fix this minted an admin session
// for user id 1 (and skipped TOTP); now it is a 500 with no cookies.
func TestLogin_D1_SecondLookupFailure_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, totpOn := range []bool{false, true} {
		h, store := totpTestHandler(t, hardeningTOTPSecret)
		store.admin.ID = 42
		store.admin.TOTPEnabled = totpOn
		store.failUsernameCall = 2 // 1 = ValidateCredentials, 2 = handler lookup

		rec := loginReq(h)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("totp=%v: status = %d, want 500 (body=%s)", totpOn, rec.Code, rec.Body.String())
		}
		assertNoSession(t, rec)
		if cookieByName(rec, "pending_2fa") != nil {
			t.Errorf("totp=%v: no pending_2fa cookie may be set on a failed lookup", totpOn)
		}
	}
}

// TestLogin_D5_EmptyRole_PasswordPath: an account row with an empty role must
// not be granted a session at all (pre-fix it became admin).
func TestLogin_D5_EmptyRole_PasswordPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, role := range []string{"", "superuser"} {
		h, store := totpTestHandler(t, hardeningTOTPSecret)
		store.admin.TOTPEnabled = false
		store.admin.Role = role

		rec := loginReq(h)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("role %q: status = %d, want 401 (body=%s)", role, rec.Code, rec.Body.String())
		}
		if msg := errorBody(t, rec); msg != "Invalid credentials" {
			t.Errorf("role %q: error = %q, want the generic login failure", role, msg)
		}
		assertNoSession(t, rec)
	}
}

// TestLogin_D5_EmptyRole_TOTPPath: same invariant on the second-factor step.
func TestLogin_D5_EmptyRole_TOTPPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	store.admin.Role = ""
	pending, err := h.authManager.GeneratePendingToken("root", 1, 4)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())

	rec := totpReq(h, pending, code)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	assertNoSession(t, rec)
}

// TestTOTP_CodeUsedAtLoginRejectedAtDisable: the replay guard is shared by
// every TOTP consumer — a code spent on the 2FA login cannot then be spent to
// disable 2FA within its validity window.
func TestTOTP_CodeUsedAtLoginRejectedAtDisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, hardeningTOTPSecret)
	store := h.db.(*totpFakeStore)
	pending, err := h.authManager.GeneratePendingToken("root", 1, 4)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())

	if rec := totpReq(h, pending, code); rec.Code != http.StatusOK {
		t.Fatalf("login with code: status = %d (body=%s)", rec.Code, rec.Body.String())
	}

	c, rec := jsonReq(http.MethodPost, "/admin/api/auth/2fa/disable",
		`{"password":"correct-horse","code":"`+code+`"}`)
	c.Set("username", "root")
	h.Disable2FA(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replayed code at disable: status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if store.totpCleared {
		t.Fatal("2FA must not be cleared with a replayed code")
	}
}

// TestCompleteLogin_DisabledAtCompletion: the account is disabled between the
// credential check and session minting. completeLogin re-reads by ID and
// refuses with the entry point's usual generic failure.
func TestCompleteLogin_DisabledAtCompletion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	disable := func(a *models.Admin) { a.Disabled = true }

	// Password path.
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	store.admin.TOTPEnabled = false
	store.byIDMutate = disable
	rec := loginReq(h)
	if rec.Code != http.StatusUnauthorized || errorBody(t, rec) != "Invalid credentials" {
		t.Fatalf("password path: status = %d body=%s, want 401 Invalid credentials", rec.Code, rec.Body.String())
	}
	assertNoSession(t, rec)

	// TOTP path.
	h, store = totpTestHandler(t, hardeningTOTPSecret)
	store.byIDMutate = disable
	pending, _ := h.authManager.GeneratePendingToken("root", 1, 4)
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	rec = totpReq(h, pending, code)
	if rec.Code != http.StatusUnauthorized || errorBody(t, rec) != "Pending login invalid — start over" {
		t.Fatalf("totp path: status = %d body=%s, want 401 generic", rec.Code, rec.Body.String())
	}
	assertNoSession(t, rec)
}

// TestCompleteLogin_PasswordPathNeverSkipsTOTP: if 2FA is enabled between the
// password check's lookup and completion, the password path must not mint a
// full session.
func TestCompleteLogin_PasswordPathNeverSkipsTOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	store.admin.TOTPEnabled = false
	store.byIDMutate = func(a *models.Admin) { a.TOTPEnabled = true }
	rec := loginReq(h)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	assertNoSession(t, rec)
}

// TestCompleteLogin_RecoveryCodeBurnedOnFailure pins the chosen behaviour: if
// completeLogin fails AFTER a recovery code was consumed, the code stays
// consumed (fail closed — no un-burning of credentials) and the pending login
// survives so the user can retry with another code.
func TestCompleteLogin_RecoveryCodeBurnedOnFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	store.recoveryHash = database.HashAPIToken("recover-me")
	store.byIDErr = errors.New("injected by-id failure")
	pending, _ := h.authManager.GeneratePendingToken("root", 1, 4)

	rec := totpReq(h, pending, "recover-me")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	assertNoSession(t, rec)
	if cookieByName(rec, "pending_2fa") != nil {
		t.Error("pending_2fa must not be cleared when completion fails")
	}
	if !store.recoveryUsed {
		t.Fatal("recovery code must stay consumed after a completion failure")
	}

	store.byIDErr = nil
	if rec := totpReq(h, pending, "recover-me"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("burned recovery code reused: status = %d, want 401", rec.Code)
	}
}

// --- behaviour-preservation (characterization) tests ------------------------
// These pass identically on the pre-refactor code: they pin that the
// completeLogin extraction changed no status, cookie, body or login_attempts row.

type loginSuccessBody struct {
	Success bool                   `json:"success"`
	Data    map[string]interface{} `json:"data"`
}

func assertSessionIssued(t *testing.T, rec *httptest.ResponseRecorder, wantUser string, wantUID uint, wantVersion uint, h *Handler) {
	t.Helper()
	assertSessionIssuedAs(t, rec, wantUser, wantUID, wantVersion, auth.RoleAdmin, false, h)
}

func assertSessionIssuedAs(t *testing.T, rec *httptest.ResponseRecorder, wantUser string, wantUID uint, wantVersion uint, wantRole string, wantMustChange bool, h *Handler) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	authCk, csrfCk := cookieByName(rec, "auth_token"), cookieByName(rec, "csrf_token")
	if authCk == nil || csrfCk == nil {
		t.Fatalf("auth_token/csrf_token cookies missing: %v", rec.Result().Cookies())
	}
	if !authCk.HttpOnly || authCk.Path != "/" || authCk.MaxAge != 3600 || authCk.SameSite != http.SameSiteStrictMode || authCk.Secure {
		t.Errorf("auth_token attributes changed: %+v", authCk)
	}
	if csrfCk.HttpOnly || csrfCk.Path != "/" || csrfCk.MaxAge != 3600 || csrfCk.SameSite != http.SameSiteStrictMode || csrfCk.Secure {
		t.Errorf("csrf_token attributes changed: %+v", csrfCk)
	}
	var body loginSuccessBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Success || len(body.Data) != 3 ||
		body.Data["message"] != "Login successful" ||
		body.Data["must_change_password"] != wantMustChange ||
		body.Data["csrf_token"] != csrfCk.Value {
		t.Errorf("success body changed: %s", rec.Body.String())
	}
	claims, err := h.authManager.ValidateToken(authCk.Value)
	if err != nil {
		t.Fatalf("issued token invalid: %v", err)
	}
	if claims.Username != wantUser || claims.UserID != wantUID || claims.TokenVersion != wantVersion ||
		claims.Role != wantRole || claims.Stage != "" {
		t.Errorf("claims changed: %+v", claims)
	}
}

func TestLogin_PasswordOnly_Unchanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	store.admin.TOTPEnabled = false

	rec := loginReq(h)
	assertSessionIssued(t, rec, "root", 1, 4, h)
	if cookieByName(rec, "pending_2fa") != nil {
		t.Error("password-only login must not touch pending_2fa")
	}
	if len(rec.Result().Cookies()) != 2 {
		t.Errorf("want exactly 2 cookies, got %v", rec.Result().Cookies())
	}
	if len(store.loginAttempts) != 1 || !store.loginAttempts[0].Success || store.loginAttempts[0].Username != "root" {
		t.Errorf("login_attempts rows changed: %+v", store.loginAttempts)
	}
}

func TestLogin_PasswordPlusTOTP_Unchanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)

	rec := loginReq(h)
	if rec.Code != http.StatusOK {
		t.Fatalf("password step: status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != `{"success":true,"data":{"totp_required":true}}` {
		t.Errorf("password step body changed: %s", got)
	}
	cks := rec.Result().Cookies()
	if len(cks) != 1 || cks[0].Name != "pending_2fa" || !cks[0].HttpOnly || cks[0].MaxAge != int(auth.PendingTokenExpiry.Seconds()) {
		t.Fatalf("password step cookies changed: %v", cks)
	}
	// v0.11.283: the password step of a 2FA account is an intermediate stage
	// and writes NO login_attempts row (it used to write success=true before
	// the second factor was checked); the TOTP step records the outcome.
	if len(store.loginAttempts) != 0 {
		t.Errorf("password step of a 2FA login must write no login_attempts row: %+v", store.loginAttempts)
	}

	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	rec = totpReq(h, cks[0].Value, code)
	assertSessionIssued(t, rec, "root", 1, 4, h)
	if ck := cookieByName(rec, "pending_2fa"); ck == nil || ck.MaxAge != -1 || ck.Value != "" {
		t.Errorf("pending_2fa must be cleared on success, got %+v", ck)
	}
	if len(rec.Result().Cookies()) != 3 {
		t.Errorf("want exactly 3 cookies (pending clear + session pair), got %v", rec.Result().Cookies())
	}
	if len(store.loginAttempts) != 1 || !store.loginAttempts[0].Success || store.loginAttempts[0].Username != "root" ||
		store.loginAttempts[0].Method == nil || *store.loginAttempts[0].Method != loginMethodTOTP {
		t.Errorf("TOTP step must write exactly one success row with method totp: %+v", store.loginAttempts)
	}
}

// TestLogin_RolesAndMustChange_Unchanged: viewer/operator logins carry their
// own role, and must_change_password=true is reported, exactly as before.
func TestLogin_RolesAndMustChange_Unchanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		role       string
		mustChange bool
	}{
		{auth.RoleViewer, false},
		{auth.RoleOperator, false},
		{auth.RoleAdmin, true},
	}
	for _, tc := range cases {
		h, store := totpTestHandler(t, hardeningTOTPSecret)
		store.admin.TOTPEnabled = false
		store.admin.Role = tc.role
		store.admin.MustChangePassword = tc.mustChange
		rec := loginReq(h)
		assertSessionIssuedAs(t, rec, "root", 1, 4, tc.role, tc.mustChange, h)
		if len(rec.Result().Cookies()) != 2 {
			t.Errorf("%s: want exactly 2 cookies, got %v", tc.role, rec.Result().Cookies())
		}
		if len(store.loginAttempts) != 1 || !store.loginAttempts[0].Success {
			t.Errorf("%s: login_attempts rows changed: %+v", tc.role, store.loginAttempts)
		}
	}
}

// --- review follow-ups -----------------------------------------------------

// TestTOTPLogin_PendingTokenForOtherUserID: the pending token names user id 99
// but the username now resolves to id 1 — not the account the password was
// verified for, so the second step refuses.
func TestTOTPLogin_PendingTokenForOtherUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, hardeningTOTPSecret)
	pending, err := h.authManager.GeneratePendingToken("root", 99, 4)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	rec := totpReq(h, pending, code)
	if rec.Code != http.StatusUnauthorized || errorBody(t, rec) != "Pending login invalid — start over" {
		t.Fatalf("status = %d body=%s, want 401 generic", rec.Code, rec.Body.String())
	}
	assertNoSession(t, rec)
}

// TestTOTPLogin_ReplayedCode_DistinctMessageNoFailure: a valid-but-spent code
// gets the "already used" message and does not count toward lockout.
func TestTOTPLogin_ReplayedCode_DistinctMessageNoFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, hardeningTOTPSecret) // MaxLoginAttempts = 3
	pending, _ := h.authManager.GeneratePendingToken("root", 1, 4)
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	if rec := totpReq(h, pending, code); rec.Code != http.StatusOK {
		t.Fatalf("first use: status = %d", rec.Code)
	}
	for i := 0; i < 4; i++ {
		rec := totpReq(h, pending, code)
		if rec.Code != http.StatusUnauthorized || errorBody(t, rec) != totpCodeAlreadyUsedMsg {
			t.Fatalf("replay %d: status = %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	if h.authManager.IsLocked("root", "192.0.2.1") {
		t.Fatal("replayed valid codes must not count toward lockout")
	}
}

// TestDisable2FA_ReplayedCode_DistinctMessage: same message at disable-2FA.
func TestDisable2FA_ReplayedCode_DistinctMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	if !h.authManager.MarkTOTPSlotUsed(1, code) {
		t.Fatal("seed use failed")
	}
	c, rec := jsonReq(http.MethodPost, "/admin/api/auth/2fa/disable", `{"password":"correct-horse","code":"`+code+`"}`)
	c.Set("username", "root")
	h.Disable2FA(c)
	if rec.Code != http.StatusForbidden || errorBody(t, rec) != totpCodeAlreadyUsedMsg {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if store.totpCleared {
		t.Fatal("2FA cleared with a replayed code")
	}
}

func verifyReq(h *Handler, code string) *httptest.ResponseRecorder {
	c, rec := jsonReq(http.MethodPost, "/admin/api/auth/2fa/verify", `{"code":"`+code+`"}`)
	c.Set("username", "root")
	h.Verify2FA(c)
	return rec
}

// TestVerify2FA_RejectsWhenAlreadyEnabled: re-verifying an enrolled account
// must not re-mint its recovery codes.
func TestVerify2FA_RejectsWhenAlreadyEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret) // TOTPEnabled: true
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	rec := verifyReq(h, code)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if store.recoveryReplaced {
		t.Fatal("recovery codes must not be replaced on an enrolled account")
	}
}

// TestVerify2FA_ConsumesCode: the enrolment code goes through the shared
// replay guard — it cannot be replayed on verify or used elsewhere.
func TestVerify2FA_ConsumesCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, hardeningTOTPSecret)
	store.admin.TOTPEnabled = false
	code, _ := totp.GenerateCode(hardeningTOTPSecret, time.Now())
	if rec := verifyReq(h, code); rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if h.authManager.MarkTOTPSlotUsed(1, code) {
		t.Fatal("enrolment code must be marked used by Verify2FA")
	}
}

// TestLogin_AttemptRow_FailureWhenCompletionRefuses: a password that verifies
// but whose login is refused at completion records a FAILED attempt row.
func TestLogin_AttemptRow_FailureWhenCompletionRefuses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, setup := range map[string]func(*totpFakeStore){
		"disabled": func(s *totpFakeStore) { s.byIDMutate = func(a *models.Admin) { a.Disabled = true } },
		"db-error": func(s *totpFakeStore) { s.byIDErr = errors.New("injected") },
	} {
		h, store := totpTestHandler(t, hardeningTOTPSecret)
		store.admin.TOTPEnabled = false
		setup(store)
		rec := loginReq(h)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s: login succeeded", name)
		}
		if len(store.loginAttempts) != 1 || store.loginAttempts[0].Success {
			t.Errorf("%s: want one failed attempt row, got %+v", name, store.loginAttempts)
		}
	}
}
