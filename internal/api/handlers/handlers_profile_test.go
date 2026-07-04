package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// profileTestHandler builds a handler over the real in-memory DB with a
// working AuthManager (Setup2FA re-auths with the password) and a seeded
// account of the given role.
func profileTestHandler(t *testing.T, username, role, password string) (*Handler, *database.Database, *models.Admin) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	cfg.Auth.BcryptCost = bcrypt.MinCost
	cfg.Auth.MaxLoginAttempts = 3
	cfg.Auth.LockoutDuration = 15 * time.Minute
	cfg.Auth.TokenExpiry = time.Hour
	am := auth.NewAuthManager(cfg, db)
	hash, err := am.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &models.Admin{Username: username, Password: hash, Role: role}
	if err := db.Gorm().Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return &Handler{db: db, authManager: am, config: cfg}, db, u
}

func profileReq(method, path, body, username, role string, userID uint) (*gin.Context, *bytes.Buffer) {
	c, rec := jsonReq(method, path, body)
	c.Set("username", username)
	c.Set("role", role)
	c.Set("user_id", userID)
	return c, rec.Body
}

// TestUpdateProfile_ViewerCanEditOwnProfile pins the core self-service
// contract: the lowest role can set its own email/display name, and the
// write touches nothing security-bearing.
func TestUpdateProfile_ViewerCanEditOwnProfile(t *testing.T) {
	h, db, u := profileTestHandler(t, "viewer1", auth.RoleViewer, "pw-viewer-1")

	c, _ := profileReq(http.MethodPut, "/admin/api/me",
		`{"email":"v@example.test","full_name":"View Er","role":"admin","username":"root"}`,
		"viewer1", auth.RoleViewer, u.ID)
	h.UpdateProfile(c)

	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("status = %d", c.Writer.Status())
	}
	got, _ := db.GetAdminByID(u.ID)
	if got.Email != "v@example.test" || got.FullName != "View Er" {
		t.Fatalf("profile not saved: %+v", got)
	}
	// The injected role/username fields must be ignored — self-service can
	// never rename or escalate.
	if got.Role != auth.RoleViewer || got.Username != "viewer1" {
		t.Fatalf("self-service write escalated: role=%q username=%q", got.Role, got.Username)
	}
}

func TestUpdateProfile_Validation(t *testing.T) {
	h, db, u := profileTestHandler(t, "op", auth.RoleOperator, "pw-operator")

	longName := make([]byte, 129)
	for i := range longName {
		longName[i] = 'x'
	}
	cases := []struct {
		name string
		body string
	}{
		{"bad email", `{"email":"not-an-email"}`},
		{"name-addr form rejected", `{"email":"Ops <ops@example.test>"}`},
		{"email too long", `{"email":"` + string(bytes.Repeat([]byte{'a'}, 250)) + `@example.test"}`},
		{"name too long", `{"full_name":"` + string(longName) + `"}`},
	}
	for _, tc := range cases {
		c, body := profileReq(http.MethodPut, "/admin/api/me", tc.body, "op", auth.RoleOperator, u.ID)
		h.UpdateProfile(c)
		if c.Writer.Status() != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body=%s)", tc.name, c.Writer.Status(), body.String())
		}
	}
	if got, _ := db.GetAdminByID(u.ID); got.Email != "" || got.FullName != "" {
		t.Fatalf("rejected requests must not persist: %+v", got)
	}

	// Empty values are valid (clearing).
	c, _ := profileReq(http.MethodPut, "/admin/api/me", `{"email":"","full_name":""}`, "op", auth.RoleOperator, u.ID)
	h.UpdateProfile(c)
	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("clearing must be allowed, status = %d", c.Writer.Status())
	}
}

// TestDeclineMFAPrompt covers the wizard's decline contract: explicit
// acknowledgment required, idempotent, first timestamp wins, and a no-op for
// accounts that already have 2FA on.
func TestDeclineMFAPrompt(t *testing.T) {
	h, db, u := profileTestHandler(t, "viewer1", auth.RoleViewer, "pw-viewer-1")

	// Missing / false acknowledgment → 400, nothing recorded.
	for _, body := range []string{`{}`, `{"acknowledge_risk":false}`} {
		c, _ := profileReq(http.MethodPost, "/admin/api/me/mfa-decline", body, "viewer1", auth.RoleViewer, u.ID)
		h.DeclineMFAPrompt(c)
		if c.Writer.Status() != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400", body, c.Writer.Status())
		}
	}
	if got, _ := db.GetAdminByID(u.ID); got.MFAPromptDismissedAt != nil {
		t.Fatal("unacknowledged decline must not persist")
	}

	// Real decline.
	c, _ := profileReq(http.MethodPost, "/admin/api/me/mfa-decline", `{"acknowledge_risk":true}`, "viewer1", auth.RoleViewer, u.ID)
	h.DeclineMFAPrompt(c)
	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("decline status = %d", c.Writer.Status())
	}
	got, _ := db.GetAdminByID(u.ID)
	if got.MFAPromptDismissedAt == nil {
		t.Fatal("decline not persisted")
	}
	first := *got.MFAPromptDismissedAt

	// Repeat is idempotent and keeps the first timestamp.
	time.Sleep(15 * time.Millisecond)
	c, _ = profileReq(http.MethodPost, "/admin/api/me/mfa-decline", `{"acknowledge_risk":true}`, "viewer1", auth.RoleViewer, u.ID)
	h.DeclineMFAPrompt(c)
	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("repeat decline status = %d", c.Writer.Status())
	}
	got, _ = db.GetAdminByID(u.ID)
	if !got.MFAPromptDismissedAt.Equal(first) {
		t.Fatalf("repeat decline changed the timestamp: %v -> %v", first, *got.MFAPromptDismissedAt)
	}
}

// TestGetMe_IncludesProfileFields pins the wire contract the profile page and
// the MFA wizard trigger depend on.
func TestGetMe_IncludesProfileFields(t *testing.T) {
	h, db, u := profileTestHandler(t, "op", auth.RoleOperator, "pw-operator")
	if err := db.UpdateAdminProfile(u.ID, "op@example.test", "Op Erator"); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := db.SetAdminMFAPromptDismissed(u.ID); err != nil {
		t.Fatalf("seed decline: %v", err)
	}

	c, body := profileReq(http.MethodGet, "/admin/api/me", "", "op", auth.RoleOperator, u.ID)
	h.GetMe(c)
	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("status = %d", c.Writer.Status())
	}
	var resp struct {
		Data struct {
			Email              string     `json:"email"`
			FullName           string     `json:"full_name"`
			CreatedAt          *time.Time `json:"created_at"`
			MustChange         bool       `json:"must_change_password"`
			MFAPromptDismissed bool       `json:"mfa_prompt_dismissed"`
			TOTPEnabled        bool       `json:"totp_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body.String())
	}
	d := resp.Data
	if d.Email != "op@example.test" || d.FullName != "Op Erator" || !d.MFAPromptDismissed || d.CreatedAt == nil {
		t.Fatalf("GetMe missing profile fields: %+v (body=%s)", d, body.String())
	}
}

// TestSetup2FA_QRPNG pins the wizard's QR payload: a valid, decodable PNG of
// the enrollment otpauth URI rides the setup response.
func TestSetup2FA_QRPNG(t *testing.T) {
	h, _, u := profileTestHandler(t, "op", auth.RoleOperator, "pw-operator")

	c, body := profileReq(http.MethodPost, "/admin/api/2fa/setup", `{"password":"pw-operator"}`, "op", auth.RoleOperator, u.ID)
	h.Setup2FA(c)
	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", c.Writer.Status(), body.String())
	}
	var resp struct {
		Data struct {
			Secret     string `json:"secret"`
			OtpauthURL string `json:"otpauth_url"`
			QRPNG      string `json:"qr_png"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Secret == "" || resp.Data.OtpauthURL == "" {
		t.Fatalf("setup response incomplete: %+v", resp.Data)
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Data.QRPNG)
	if err != nil {
		t.Fatalf("qr_png is not base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("qr_png is not a valid PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() < 100 || b.Dy() < 100 {
		t.Fatalf("QR unexpectedly small: %v", b)
	}
}
