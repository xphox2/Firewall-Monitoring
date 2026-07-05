package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// fakeTokenStore implements TokenAuthStore over an in-memory map keyed by
// PLAINTEXT (it delegates hashing concerns to the database package exactly
// like the real store: LookupAPIToken takes plaintext). admins backs the
// LC-15 creator-state re-check: a token's creator must exist, be enabled,
// and their CURRENT role caps the token's effective role.
type fakeTokenStore struct {
	byPlaintext map[string]*models.ApiToken
	admins      map[uint]*models.Admin
	lookupErr   error
	adminErr    error
	touched     []uint
}

func (f *fakeTokenStore) LookupAPIToken(plaintext string) (*models.ApiToken, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.byPlaintext[plaintext], nil
}
func (f *fakeTokenStore) TouchAPITokenLastUsed(id uint, t time.Time) error {
	f.touched = append(f.touched, id)
	return nil
}
func (f *fakeTokenStore) GetAdminByID(id uint) (*models.Admin, error) {
	if f.adminErr != nil {
		return nil, f.adminErr
	}
	return f.admins[id], nil // nil,nil = not found, matching the real store
}

// enabledAdminCreator seeds one enabled role=admin account (id 100) so
// pre-LC-15 test tokens keep authenticating; tokens reference it via
// CreatedByID.
func enabledAdminCreator() map[uint]*models.Admin {
	return map[uint]*models.Admin{
		100: {ID: 100, Username: "creator", Role: auth.RoleAdmin},
	}
}

func tokenTestRouter(store TokenAuthStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AdminAuth(nil, store)) // nil AuthManager: cookie path will 401, which these tests never rely on
	r.Use(RequireRole(map[string]bool{}, map[string]bool{"/admin/api/settings": true}))
	ok := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"username": c.GetString("username"),
			"method":   c.GetString("auth_method"),
			"role":     c.GetString("role"),
		})
	}
	r.GET("/admin/api/devices", ok)
	r.POST("/admin/api/devices", ok)
	r.GET("/admin/api/settings", ok)
	return r
}

func doTokenReq(r *gin.Engine, method, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestAdminAuth_TokenMatrix pins the bearer path: valid scopes map onto the
// role ladder, revoked/expired/unknown reject, DB errors fail closed, and a
// leaked stored hash presented as a bearer must not authenticate.
func TestAdminAuth_TokenMatrix(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	readTok := "fwm_read-token-plaintext"
	writeTok := "fwm_write-token-plaintext"
	adminTok := "fwm_admin-token-plaintext"
	revokedTok := "fwm_revoked-token"
	expiredTok := "fwm_expired-token"

	store := &fakeTokenStore{byPlaintext: map[string]*models.ApiToken{
		readTok:     {ID: 1, Name: "ro", Scope: "read", CreatedByID: 100},
		writeTok:    {ID: 2, Name: "rw", Scope: "write", CreatedByID: 100},
		adminTok:    {ID: 3, Name: "root", Scope: "admin", CreatedByID: 100},
		revokedTok:  {ID: 4, Name: "dead", Scope: "admin", RevokedAt: &past, CreatedByID: 100},
		expiredTok:  {ID: 5, Name: "old", Scope: "admin", ExpiresAt: &past, CreatedByID: 100},
		"fwm_fresh": {ID: 6, Name: "fresh", Scope: "read", ExpiresAt: &future, CreatedByID: 100},
	}, admins: enabledAdminCreator()}
	r := tokenTestRouter(store)

	cases := []struct {
		name   string
		method string
		path   string
		bearer string
		want   int
	}{
		{"read GET ok", http.MethodGet, "/admin/api/devices", readTok, 200},
		{"read POST denied", http.MethodPost, "/admin/api/devices", readTok, 403},
		{"write POST ok", http.MethodPost, "/admin/api/devices", writeTok, 200},
		{"write settings denied", http.MethodGet, "/admin/api/settings", writeTok, 403},
		{"admin settings ok", http.MethodGet, "/admin/api/settings", adminTok, 200},
		{"revoked rejected", http.MethodGet, "/admin/api/devices", revokedTok, 401},
		{"expired rejected", http.MethodGet, "/admin/api/devices", expiredTok, 401},
		{"unexpired accepted", http.MethodGet, "/admin/api/devices", "fwm_fresh", 200},
		{"unknown rejected", http.MethodGet, "/admin/api/devices", "fwm_nonexistent", 401},
		{"stored hash as bearer rejected", http.MethodGet, "/admin/api/devices",
			// An attacker who exfiltrated the at-rest value must not be able to
			// replay it: it lacks the fwm_ prefix, and even the raw digest form
			// would double-hash in the real store.
			database.HashAPIToken(readTok), 401},
	}
	for _, tc := range cases {
		if rec := doTokenReq(r, tc.method, tc.path, tc.bearer); rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d (body=%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}

	if len(store.touched) == 0 {
		t.Error("valid token requests should record last_used_at")
	}
}

// TestAdminAuth_TokenLookupError_FailsClosed: a store error must reject, not
// fall through to the cookie path or admit.
func TestAdminAuth_TokenLookupError_FailsClosed(t *testing.T) {
	store := &fakeTokenStore{lookupErr: errors.New("db down")}
	r := tokenTestRouter(store)
	if rec := doTokenReq(r, http.MethodGet, "/admin/api/devices", "fwm_whatever"); rec.Code != http.StatusUnauthorized {
		t.Errorf("lookup error: got %d, want 401", rec.Code)
	}
}

// TestAdminAuth_TokenCreatorLifecycle_LC15 pins that a token is only as alive
// — and as privileged — as the account behind it. Session revocation happens
// via the token-version bump; the bearer path must mirror it: disabled or
// deleted creator ⇒ 401, demoted creator ⇒ the token's effective role is
// capped at the creator's CURRENT role, and a creator-lookup DB error fails
// closed.
func TestAdminAuth_TokenCreatorLifecycle_LC15(t *testing.T) {
	tokens := map[string]*models.ApiToken{
		"fwm_of-disabled": {ID: 1, Name: "of-disabled", Scope: "admin", CreatedByID: 1},
		"fwm_of-deleted":  {ID: 2, Name: "of-deleted", Scope: "admin", CreatedByID: 2},
		"fwm_of-viewer":   {ID: 3, Name: "of-viewer", Scope: "admin", CreatedByID: 3},
		"fwm_of-operator": {ID: 4, Name: "of-operator", Scope: "admin", CreatedByID: 4},
		"fwm_of-admin":    {ID: 5, Name: "of-admin", Scope: "admin", CreatedByID: 5},
	}
	admins := map[uint]*models.Admin{
		1: {ID: 1, Username: "disabled", Role: auth.RoleAdmin, Disabled: true},
		// 2 intentionally absent — deleted account.
		3: {ID: 3, Username: "demoted-to-viewer", Role: auth.RoleViewer},
		4: {ID: 4, Username: "demoted-to-operator", Role: auth.RoleOperator},
		5: {ID: 5, Username: "still-admin", Role: auth.RoleAdmin},
	}
	r := tokenTestRouter(&fakeTokenStore{byPlaintext: tokens, admins: admins})

	cases := []struct {
		name   string
		method string
		path   string
		bearer string
		want   int
	}{
		// Disabled / deleted creator: the token dies with the account.
		{"disabled creator rejected", http.MethodGet, "/admin/api/devices", "fwm_of-disabled", 401},
		{"deleted creator rejected", http.MethodGet, "/admin/api/devices", "fwm_of-deleted", 401},

		// Demoted to viewer: admin-scope token reads, but can neither mutate
		// nor touch admin-only routes.
		{"demoted-to-viewer GET ok", http.MethodGet, "/admin/api/devices", "fwm_of-viewer", 200},
		{"demoted-to-viewer POST denied", http.MethodPost, "/admin/api/devices", "fwm_of-viewer", 403},
		{"demoted-to-viewer settings denied", http.MethodGet, "/admin/api/settings", "fwm_of-viewer", 403},

		// Demoted to operator: mutations yes, admin-only no.
		{"demoted-to-operator POST ok", http.MethodPost, "/admin/api/devices", "fwm_of-operator", 200},
		{"demoted-to-operator settings denied", http.MethodGet, "/admin/api/settings", "fwm_of-operator", 403},

		// Unchanged admin creator: full admin-scope rights (control case).
		{"admin creator settings ok", http.MethodGet, "/admin/api/settings", "fwm_of-admin", 200},
	}
	for _, tc := range cases {
		if rec := doTokenReq(r, tc.method, tc.path, tc.bearer); rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d (body=%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

// TestAdminAuth_CreatorLookupError_FailsClosed_LC15: a DB error resolving the
// creator must reject, same philosophy as the token-lookup error path.
func TestAdminAuth_CreatorLookupError_FailsClosed_LC15(t *testing.T) {
	store := &fakeTokenStore{
		byPlaintext: map[string]*models.ApiToken{
			"fwm_ok": {ID: 1, Name: "ok", Scope: "read", CreatedByID: 100},
		},
		adminErr: errors.New("db down"),
	}
	r := tokenTestRouter(store)
	if rec := doTokenReq(r, http.MethodGet, "/admin/api/devices", "fwm_ok"); rec.Code != http.StatusUnauthorized {
		t.Errorf("creator lookup error: got %d, want 401", rec.Code)
	}
}

// TestCSRF_SkippedForTokens_EnforcedForSessions: token-authenticated mutations
// bypass CSRF (no cookies → no ambient authority); cookie sessions still need
// the header.
func TestCSRF_SkippedForTokens_EnforcedForSessions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &fakeTokenStore{byPlaintext: map[string]*models.ApiToken{
		"fwm_writer": {ID: 1, Name: "w", Scope: "write", CreatedByID: 100},
	}, admins: enabledAdminCreator()}
	cfg := csrfTestConfig()

	r := gin.New()
	r.Use(AdminAuth(nil, store))
	r.Use(CSRFProtection(cfg))
	r.POST("/admin/api/devices", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Token: mutation succeeds with no CSRF header.
	if rec := doTokenReq(r, http.MethodPost, "/admin/api/devices", "fwm_writer"); rec.Code != http.StatusOK {
		t.Errorf("token POST without CSRF header: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// Session-shaped request (no bearer): CSRF must still gate mutations.
	// AdminAuth would 401 first without a cookie, so exercise CSRFProtection
	// alone the way the session chain would see it.
	r2 := gin.New()
	r2.Use(CSRFProtection(cfg))
	r2.POST("/admin/api/devices", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/admin/api/devices", nil)
	rec := httptest.NewRecorder()
	r2.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("session POST without CSRF header: got %d, want 403", rec.Code)
	}
}

// csrfTestConfig builds the minimal config CSRFProtection needs.
func csrfTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	return cfg
}

// Silence the auth import when only some tests reference it.
var _ = auth.RoleAdmin
