package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// totpFakeStore backs the 2FA login-flow tests: it serves BOTH the handler's
// database.Store dependency and auth.Database (the AuthManager's own narrow
// interface), so one fixture drives the whole flow.
type totpFakeStore struct {
	fakeStore
	admin         *auth.AdminAuth
	recoveryHash  string
	recoveryUsed  bool
	loginAttempts []models.LoginAttempt

	// Failure/race injection for the completeLogin and D1 tests.
	usernameCalls    int                 // GetAdminByUsername call counter
	failUsernameCall int                 // 1-based call that errors (0 = never)
	byIDErr          error               // GetAdminByID returns this error
	byIDMutate       func(*models.Admin) // edits the by-ID view (simulates a concurrent change)
	totpCleared      bool                // ClearAdminTOTP was called
	recoveryReplaced bool                // ReplaceRecoveryCodes was called
}

func (f *totpFakeStore) WithContextStore(ctx context.Context) database.Store { return f }

func (f *totpFakeStore) GetAdminByUsername(u string) (*auth.AdminAuth, error) {
	f.usernameCalls++
	if f.failUsernameCall != 0 && f.usernameCalls == f.failUsernameCall {
		return nil, errors.New("injected username lookup failure")
	}
	if f.admin != nil && f.admin.Username == u {
		cp := *f.admin
		return &cp, nil
	}
	return nil, nil
}
func (f *totpFakeStore) GetAdminByID(id uint) (*models.Admin, error) {
	if f.byIDErr != nil {
		return nil, f.byIDErr
	}
	if f.admin == nil || f.admin.ID != id {
		return nil, nil
	}
	a := &models.Admin{
		ID: f.admin.ID, Username: f.admin.Username, Password: f.admin.Password,
		TokenVersion: f.admin.TokenVersion, MustChangePassword: f.admin.MustChangePassword,
		Role: f.admin.Role, Disabled: f.admin.Disabled, TOTPEnabled: f.admin.TOTPEnabled,
	}
	if f.byIDMutate != nil {
		f.byIDMutate(a)
	}
	return a, nil
}
func (f *totpFakeStore) ClearAdminTOTP(id uint) error {
	f.totpCleared = true
	return nil
}
func (f *totpFakeStore) EncryptField(p string) string { return p }
func (f *totpFakeStore) SetAdminTOTP(id uint, enc string, enabled bool) error {
	f.admin.TOTPEnabled = enabled
	return nil
}
func (f *totpFakeStore) ReplaceRecoveryCodes(id uint, hashes []string) error {
	f.recoveryReplaced = true
	return nil
}
func (f *totpFakeStore) GetAdminTokenVersion(id uint) (uint, error) { return f.admin.TokenVersion, nil }
func (f *totpFakeStore) IncrementAdminTokenVersion(id uint) error   { return nil }
func (f *totpFakeStore) UpdateAdminPassword(id uint, p string) error {
	return nil
}
func (f *totpFakeStore) SaveLoginAttempt(a *models.LoginAttempt) error {
	f.loginAttempts = append(f.loginAttempts, *a)
	return nil
}
func (f *totpFakeStore) ConsumeRecoveryCode(adminID uint, hash string) (bool, error) {
	if !f.recoveryUsed && hash == f.recoveryHash {
		f.recoveryUsed = true
		return true, nil
	}
	return false, nil
}

func totpTestHandler(t *testing.T, secret string) (*Handler, *totpFakeStore) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	cfg.Auth.BcryptCost = bcrypt.MinCost
	cfg.Auth.MaxLoginAttempts = 3
	cfg.Auth.LockoutDuration = 15 * time.Minute
	cfg.Auth.TokenExpiry = time.Hour

	store := &totpFakeStore{}
	am := auth.NewAuthManager(cfg, store)
	hash, err := am.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	store.admin = &auth.AdminAuth{
		ID: 1, Username: "root", Password: hash, TokenVersion: 4,
		Role: auth.RoleAdmin, TOTPEnabled: true, TOTPSecret: secret,
	}
	return &Handler{db: store, authManager: am, config: cfg}, store
}

func jsonReq(method, path, body string) (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, rec
}

func cookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// TestLogin_TOTPRequired: a 2FA-enabled account gets NO session from the
// password step — only the pending cookie and totp_required.
func TestLogin_TOTPRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, "JBSWY3DPEHPK3PXP")

	c, rec := jsonReq(http.MethodPost, "/api/auth/login", `{"username":"root","password":"correct-horse"}`)
	h.Login(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			TOTPRequired bool `json:"totp_required"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.Data.TOTPRequired {
		t.Fatalf("expected totp_required=true, body=%s (err=%v)", rec.Body.String(), err)
	}
	if cookieByName(rec, "auth_token") != nil {
		t.Error("password step must NOT issue a session cookie when 2FA is on")
	}
	pending := cookieByName(rec, "pending_2fa")
	if pending == nil || pending.Value == "" || !pending.HttpOnly {
		t.Fatalf("pending_2fa cookie missing/wrong: %+v", pending)
	}
}

// TestTOTPLogin_Flow: valid code completes the session; a wrong code 401s and
// counts toward lockout; a recovery code works exactly once.
func TestTOTPLogin_Flow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "JBSWY3DPEHPK3PXP"
	h, store := totpTestHandler(t, secret)
	store.recoveryHash = database.HashAPIToken("recover-me")

	pendingTok, err := h.authManager.GeneratePendingToken("root", 1, 4)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	withPending := func(body string) (*gin.Context, *httptest.ResponseRecorder) {
		c, rec := jsonReq(http.MethodPost, "/api/auth/totp", body)
		c.Request.AddCookie(&http.Cookie{Name: "pending_2fa", Value: pendingTok})
		return c, rec
	}

	// Wrong code → 401.
	c, rec := withPending(`{"code":"000000"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong code: status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}

	// Valid TOTP code → session issued.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	c, rec = withPending(`{"code":"` + code + `"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid code: status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if cookieByName(rec, "auth_token") == nil {
		t.Error("valid code must issue the session cookie")
	}
	if ck := cookieByName(rec, "pending_2fa"); ck == nil || ck.MaxAge != -1 {
		t.Error("pending cookie must be cleared on success")
	}

	// Same code again (same slot) → replay-guard rejects, falls through to
	// recovery path, fails → 401.
	c, rec = withPending(`{"code":"` + code + `"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("replayed code: status = %d, want 401", rec.Code)
	}

	// Recovery code works exactly once.
	c, rec = withPending(`{"code":"recover-me"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusOK {
		t.Errorf("recovery code: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	c, rec = withPending(`{"code":"recover-me"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("reused recovery code: status = %d, want 401", rec.Code)
	}
}

// TestTOTPLogin_RequiresPendingToken: without the pending cookie — or with a
// FULL session token in its place — the second step refuses.
func TestTOTPLogin_RequiresPendingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := totpTestHandler(t, "JBSWY3DPEHPK3PXP")

	// No cookie at all.
	c, rec := jsonReq(http.MethodPost, "/api/auth/totp", `{"code":"123456"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no pending cookie: status = %d, want 401", rec.Code)
	}

	// A full session token is NOT a pending token (Stage mismatch).
	full, err := h.authManager.GenerateToken("root", 1, 4, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	c, rec = jsonReq(http.MethodPost, "/api/auth/totp", `{"code":"123456"}`)
	c.Request.AddCookie(&http.Cookie{Name: "pending_2fa", Value: full})
	h.TOTPLogin(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("full token as pending: status = %d, want 401", rec.Code)
	}
}

// TestTOTPLogin_FailuresRecorded (v0.11.283): every outcome of the second
// step writes a login_attempts row under method "totp" with the same fields
// as a password attempt — wrong code, replayed code, invalid pending login,
// lockout — and the issued session writes the success row. Before, the TOTP
// step wrote nothing and the password step had already recorded success.
func TestTOTPLogin_FailuresRecorded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "JBSWY3DPEHPK3PXP"
	h, store := totpTestHandler(t, secret)
	store.recoveryHash = database.HashAPIToken("recover-me")

	pendingTok, err := h.authManager.GeneratePendingToken("root", 1, 4)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	totpStep := func(body string) *httptest.ResponseRecorder {
		c, rec := jsonReq(http.MethodPost, "/api/auth/totp", body)
		c.Request.Header.Set("User-Agent", "totp-test-agent")
		c.Request.AddCookie(&http.Cookie{Name: "pending_2fa", Value: pendingTok})
		h.TOTPLogin(c)
		return rec
	}
	lastRow := func(step string, wantSuccess bool) {
		t.Helper()
		if len(store.loginAttempts) == 0 {
			t.Fatalf("%s: no login_attempts row written", step)
		}
		row := store.loginAttempts[len(store.loginAttempts)-1]
		if row.Success != wantSuccess || row.Username != "root" || row.IPAddress == "" ||
			row.UserAgent != "totp-test-agent" || row.Method == nil || *row.Method != loginMethodTOTP || row.Timestamp.IsZero() {
			t.Fatalf("%s: row = %+v, want success=%v username=root method=totp with ip/agent/timestamp", step, row, wantSuccess)
		}
	}

	// Wrong code: failure row; counts toward lockout.
	if rec := totpStep(`{"code":"000000"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	lastRow("wrong code", false)
	if len(store.loginAttempts) != 1 {
		t.Fatalf("wrong code: %d rows, want 1", len(store.loginAttempts))
	}

	// Valid code: the session's success row.
	code, _ := totp.GenerateCode(secret, time.Now())
	if rec := totpStep(`{"code":"` + code + `"}`); rec.Code != http.StatusOK {
		t.Fatalf("valid code: %d %s", rec.Code, rec.Body.String())
	}
	lastRow("valid code", true)

	// Replayed code: refused (distinct message, no lockout count) but still a
	// failure row.
	if rec := totpStep(`{"code":"` + code + `"}`); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), totpCodeAlreadyUsedMsg) {
		t.Fatalf("replayed code: %d %s", rec.Code, rec.Body.String())
	}
	lastRow("replayed code", false)

	// Recovery code: success row.
	if rec := totpStep(`{"code":"recover-me"}`); rec.Code != http.StatusOK {
		t.Fatalf("recovery code: %d %s", rec.Code, rec.Body.String())
	}
	lastRow("recovery code", true)

	// Pending login no longer valid (account disabled): failure row.
	store.admin.Disabled = true
	if rec := totpStep(`{"code":"000000"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled: %d", rec.Code)
	}
	lastRow("disabled account", false)
	store.admin.Disabled = false

	// Lockout (MaxLoginAttempts = 3): the locked refusal is recorded too.
	for i := 0; i < 3; i++ {
		totpStep(`{"code":"000000"}`)
	}
	if rec := totpStep(`{"code":"000000"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked: %d, want 429", rec.Code)
	}
	lastRow("locked", false)
	if got := len(store.loginAttempts); got != 9 {
		t.Fatalf("%d rows written, want 9 (one per outcome)", got)
	}
}

// TestTOTPLogin_NoPendingLogin_NoRow: without a usable pending token there is
// no username to attribute, so the refusal is not a login attempt row (a
// guard against recording unattributed rows, not a regression test).
func TestTOTPLogin_NoPendingLogin_NoRow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := totpTestHandler(t, "JBSWY3DPEHPK3PXP")
	c, rec := jsonReq(http.MethodPost, "/api/auth/totp", `{"code":"123456"}`)
	h.TOTPLogin(c)
	if rec.Code != http.StatusUnauthorized || len(store.loginAttempts) != 0 {
		t.Fatalf("no cookie: status %d rows %+v", rec.Code, store.loginAttempts)
	}
}
