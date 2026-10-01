package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/api/middleware"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/passkey"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Passkey test kit: a real SQLite store, the real auth middleware chain
// (AdminAuth → CSRF → RequirePasswordChanged → RequireRole), and a software
// authenticator that produces REAL WebAuthn attestation / assertion objects
// (P-256 key, "none" attestation, CBOR via the library's own encoder). The
// library's verification is never stubbed.

const (
	pkTestRPID   = "fwmon.example.test"
	pkTestOrigin = "https://fwmon.example.test"
	pkTestSecret = "JBSWY3DPEHPK3PXP"
	pkTestPass   = "correct-horse-battery"
)

// pkSelfServiceRoutes / pkAdminOnlyRoutes mirror the passkey-relevant
// entries of cmd/api/main.go's RequireRole maps (pinned there by
// internal/shell/passkey_routes_test.go).
var pkSelfServiceRoutes = map[string]bool{
	"/admin/api/settings/password":        true,
	"/admin/api/me":                       true,
	"/admin/api/passkeys":                 true,
	"/admin/api/passkeys/:id":             true,
	"/admin/api/passkeys/register/begin":  true,
	"/admin/api/passkeys/register/finish": true,
	"/admin/api/passkeys/notices/ack":     true,
}

var pkAdminOnlyRoutes = map[string]bool{
	"/admin/api/users/:id":                true,
	"/admin/api/users/:id/reset-password": true,
	"/admin/api/users/:id/reset-2fa":      true,
	"/admin/api/users/:id/passkeys":       true,
}

type pkEnv struct {
	t      *testing.T
	db     *database.Database
	cfg    *config.Config
	am     *auth.AuthManager
	h      *Handler
	router *gin.Engine
}

// newPasskeyEnv builds the environment; svc == nil means passkeys disabled.
func newPasskeyEnv(t *testing.T, enabled bool) *pkEnv {
	t.Helper()
	var svc *passkey.Service
	if enabled {
		var err error
		svc, err = passkey.New(passkey.Settings{RPID: pkTestRPID, Origins: []string{pkTestOrigin}})
		if err != nil {
			t.Fatalf("passkey.New: %v", err)
		}
	}
	return newPasskeyEnvWith(t, svc)
}

func newPasskeyEnvWith(t *testing.T, svc *passkey.Service) *pkEnv {
	t.Helper()
	return newPasskeyEnvDB(t, database.NewDatabaseForTesting(t), svc)
}

// newPasskeyEnvDB builds the environment over a given database (SQLite or,
// in the integration suite, real Postgres).
func newPasskeyEnvDB(t *testing.T, db *database.Database, svc *passkey.Service) *pkEnv {
	t.Helper()
	db.SetEncryptionKeyForTesting("passkey-test-encryption-key")
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "passkey-test-jwt-secret-that-is-long-enough"
	cfg.Auth.BcryptCost = bcrypt.MinCost
	cfg.Auth.MaxLoginAttempts = 5
	cfg.Auth.LockoutDuration = 15 * time.Minute
	cfg.Auth.TokenExpiry = time.Hour
	am := auth.NewAuthManager(cfg, db)
	h := NewHandler(cfg, am, db)
	h.SetPasskeys(svc)

	r := gin.New()
	api := r.Group("/api")
	api.POST("/auth/login", h.Login)
	api.POST("/auth/totp", h.TOTPLogin)
	api.GET("/auth/passkey/config", h.GetPasskeyConfig)
	api.POST("/auth/passkey/login/begin", h.PasskeyLoginBegin)
	api.POST("/auth/passkey/login/finish", h.PasskeyLoginFinish)

	admin := r.Group("/admin")
	admin.Use(middleware.AdminAuth(am, db))
	admin.Use(middleware.CSRFProtection(cfg))
	admin.Use(h.RequirePasswordChanged())
	admin.Use(middleware.RequireRole(pkSelfServiceRoutes, pkAdminOnlyRoutes))
	admin.GET("/api/me", h.GetMe)
	admin.POST("/api/settings/password", h.ChangePassword)
	admin.POST("/api/users/:id/reset-password", h.ResetUserPassword)
	admin.POST("/api/users/:id/reset-2fa", h.ResetUser2FA)
	admin.DELETE("/api/users/:id", h.DeleteUser)
	admin.GET("/api/passkeys", h.ListPasskeys)
	admin.POST("/api/passkeys/register/begin", h.PasskeyRegisterBegin)
	admin.POST("/api/passkeys/register/finish", h.PasskeyRegisterFinish)
	admin.POST("/api/passkeys/notices/ack", h.AckPasskeyNotices)
	admin.PUT("/api/passkeys/:id", h.RenamePasskey)
	admin.DELETE("/api/passkeys/:id", h.DeletePasskey)
	admin.DELETE("/api/users/:id/passkeys", h.RemoveUserPasskeys)

	return &pkEnv{t: t, db: db, cfg: cfg, am: am, h: h, router: r}
}

// createUser inserts an account; withTOTP enrolls pkTestSecret.
func (e *pkEnv) createUser(name, role string, withTOTP bool) *models.Admin {
	e.t.Helper()
	hash, err := e.am.HashPassword(pkTestPass)
	if err != nil {
		e.t.Fatalf("HashPassword: %v", err)
	}
	a := &models.Admin{Username: name, Password: hash, Role: role}
	if err := e.db.CreateAdmin(a); err != nil {
		e.t.Fatalf("CreateAdmin: %v", err)
	}
	if withTOTP {
		if err := e.db.SetAdminTOTP(a.ID, e.db.EncryptField(pkTestSecret), true); err != nil {
			e.t.Fatalf("SetAdminTOTP: %v", err)
		}
	}
	return a
}

func (e *pkEnv) admin(id uint) *models.Admin {
	e.t.Helper()
	a, err := e.db.GetAdminByID(id)
	if err != nil {
		e.t.Fatalf("GetAdminByID: %v", err)
	}
	return a
}

func (e *pkEnv) passkeyRows(adminID uint) []models.WebAuthnCredential {
	e.t.Helper()
	rows, err := e.db.ListPasskeys(adminID)
	if err != nil {
		e.t.Fatalf("ListPasskeys: %v", err)
	}
	return rows
}

func (e *pkEnv) allPasskeyCount() int64 {
	e.t.Helper()
	var n int64
	if err := e.db.Gorm().Model(&models.WebAuthnCredential{}).Count(&n).Error; err != nil {
		e.t.Fatalf("count passkeys: %v", err)
	}
	return n
}

func (e *pkEnv) auditActions() []string {
	e.t.Helper()
	var rows []models.AuditLog
	if err := e.db.Gorm().Order("id").Find(&rows).Error; err != nil {
		e.t.Fatalf("audit rows: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Action)
	}
	return out
}

func (e *pkEnv) hasAudit(action string) bool {
	for _, a := range e.auditActions() {
		if a == action {
			return true
		}
	}
	return false
}

// do performs one request. cookies are sent as-is; headers applied after.
func (e *pkEnv) do(method, path, body string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// pkSession is a logged-in browser: the auth cookie and its CSRF token.
type pkSession struct {
	e    *pkEnv
	auth string
	csrf string
}

func (s *pkSession) do(method, path, body string) *httptest.ResponseRecorder {
	return s.e.do(method, path, body,
		[]*http.Cookie{{Name: "auth_token", Value: s.auth}},
		map[string]string{"X-CSRF-Token": s.csrf})
}

// sessionFrom extracts the session a successful login/re-issue response set.
func (e *pkEnv) sessionFrom(rec *httptest.ResponseRecorder) *pkSession {
	e.t.Helper()
	at, ct := cookieByName(rec, "auth_token"), cookieByName(rec, "csrf_token")
	if at == nil || ct == nil || at.Value == "" || at.MaxAge < 0 {
		e.t.Fatalf("no session cookies in response (status %d body %s)", rec.Code, rec.Body.String())
	}
	return &pkSession{e: e, auth: at.Value, csrf: ct.Value}
}

// totpCode returns a currently-valid code for pkTestSecret at the given
// 30-second step offset (-1, 0, +1): three distinct codes are valid at once
// (Skew 1), which lets a test spend one on login and others on re-auth
// without tripping the shared replay guard.
func totpCode(t *testing.T, step int) string {
	t.Helper()
	code, err := totp.GenerateCode(pkTestSecret, time.Now().Add(time.Duration(step)*30*time.Second))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

// passwordLogin runs the password (+TOTP when code != "") login and returns
// the final response.
func (e *pkEnv) passwordLogin(username, code string) *httptest.ResponseRecorder {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/api/auth/login",
		`{"username":"`+username+`","password":"`+pkTestPass+`"}`, nil, nil)
	if code == "" {
		return rec
	}
	pending := cookieByName(rec, "pending_2fa")
	if pending == nil {
		e.t.Fatalf("password step gave no pending_2fa (status %d body %s)", rec.Code, rec.Body.String())
	}
	return e.do(http.MethodPost, "/api/auth/totp", `{"code":"`+code+`"}`, []*http.Cookie{pending}, nil)
}

func (e *pkEnv) login(username, code string) *pkSession {
	e.t.Helper()
	rec := e.passwordLogin(username, code)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("login %s: status %d body %s", username, rec.Code, rec.Body.String())
	}
	return e.sessionFrom(rec)
}

// --- software authenticator --------------------------------------------------

type softAuth struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte // learned at registration
	counter    uint32
	aaguid     []byte
	rpID       string
	origin     string
	// regFlags / loginFlags are the authenticator-data flags it reports.
	regFlags   protocol.AuthenticatorFlags
	loginFlags protocol.AuthenticatorFlags
}

func newSoftAuth(t *testing.T) *softAuth {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	full := protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState
	return &softAuth{
		t: t, key: key, credID: id,
		aaguid: []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4},
		rpID:   pkTestRPID, origin: pkTestOrigin,
		regFlags: full, loginFlags: full,
	}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *softAuth) cosePublicKey() []byte {
	a.t.Helper()
	raw, err := a.key.PublicKey.Bytes() // 0x04 || X(32) || Y(32)
	if err != nil || len(raw) != 65 {
		a.t.Fatalf("public key bytes: %v", err)
	}
	data, err := webauthncbor.Marshal(map[int64]any{
		1:  int64(webauthncose.EllipticKey),
		3:  int64(webauthncose.AlgES256),
		-1: int64(webauthncose.P256),
		-2: raw[1:33],
		-3: raw[33:65],
	})
	if err != nil {
		a.t.Fatalf("cose key: %v", err)
	}
	return data
}

func (a *softAuth) authData(flags protocol.AuthenticatorFlags, counter uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, h[:]...)
	out = append(out, byte(flags))
	out = binary.BigEndian.AppendUint32(out, counter)
	return append(out, attested...)
}

func (a *softAuth) clientData(typ, challenge string) []byte {
	a.t.Helper()
	data, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	if err != nil {
		a.t.Fatal(err)
	}
	return data
}

// registrationBody answers a creation challenge for userHandle.
func (a *softAuth) registrationBody(challenge string, userHandle []byte) string {
	a.t.Helper()
	a.userHandle = append([]byte(nil), userHandle...)
	attested := make([]byte, 0, 18+len(a.credID)+80)
	attested = append(attested, a.aaguid...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.credID))) // #nosec G115 -- 32 bytes
	attested = append(attested, a.credID...)
	attested = append(attested, a.cosePublicKey()...)
	ad := a.authData(a.regFlags|protocol.FlagAttestedCredentialData, a.counter, attested)
	attObj, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		a.t.Fatalf("attestation object: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"attestationObject": b64u(attObj),
			"clientDataJSON":    b64u(a.clientData("webauthn.create", challenge)),
			"transports":        []string{"internal", "hybrid"},
		},
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return string(body)
}

// assertionBody answers a login challenge, presenting handle as userHandle
// (normally the one learned at registration). The counter advances first.
func (a *softAuth) assertionBody(challenge string, handle []byte) string {
	a.t.Helper()
	a.counter++
	ad := a.authData(a.loginFlags, a.counter, nil)
	cd := a.clientData("webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatalf("sign: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"authenticatorData": b64u(ad),
			"clientDataJSON":    b64u(cd),
			"signature":         b64u(sig),
			"userHandle":        b64u(handle),
		},
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return string(body)
}

// --- ceremony helpers --------------------------------------------------------

type pkOptions struct {
	Data struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
			ExcludeCredentials []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	} `json:"data"`
}

func decodeOptions(t *testing.T, rec *httptest.ResponseRecorder) pkOptions {
	t.Helper()
	var o pkOptions
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatalf("decode options %q: %v", rec.Body.String(), err)
	}
	if o.Data.PublicKey.Challenge == "" {
		t.Fatalf("options carry no challenge: %s", rec.Body.String())
	}
	return o
}

func reauthBody(password, code, name string) string {
	b, _ := json.Marshal(map[string]string{"password": password, "totp_code": code, "name": name})
	return string(b)
}

// registerBegin starts a registration and returns the response.
func (s *pkSession) registerBegin(password, code, name string) *httptest.ResponseRecorder {
	return s.do(http.MethodPost, "/admin/api/passkeys/register/begin", reauthBody(password, code, name))
}

// register runs a full registration with a, failing the test on any error.
func (s *pkSession) register(a *softAuth, code, name string) *httptest.ResponseRecorder {
	s.e.t.Helper()
	rec := s.registerBegin(pkTestPass, code, name)
	if rec.Code != http.StatusOK {
		s.e.t.Fatalf("register begin: %d %s", rec.Code, rec.Body.String())
	}
	o := decodeOptions(s.e.t, rec)
	handle, err := base64.RawURLEncoding.DecodeString(o.Data.PublicKey.User.ID)
	if err != nil {
		s.e.t.Fatalf("user id: %v", err)
	}
	fin := s.do(http.MethodPost, "/admin/api/passkeys/register/finish", a.registrationBody(o.Data.PublicKey.Challenge, handle))
	if fin.Code != http.StatusOK {
		s.e.t.Fatalf("register finish: %d %s", fin.Code, fin.Body.String())
	}
	return fin
}

// loginBegin starts a passkey login; returns the challenge and the ceremony cookie.
func (e *pkEnv) loginBegin() (string, *http.Cookie) {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/api/auth/passkey/login/begin", "", nil, nil)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("login begin: %d %s", rec.Code, rec.Body.String())
	}
	ck := cookieByName(rec, passkeyLoginCookie)
	if ck == nil || ck.Value == "" {
		e.t.Fatal("login begin set no webauthn_login cookie")
	}
	return decodeOptions(e.t, rec).Data.PublicKey.Challenge, ck
}

func (e *pkEnv) loginFinish(cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	var cookies []*http.Cookie
	if cookie != nil {
		cookies = []*http.Cookie{cookie}
	}
	return e.do(http.MethodPost, "/api/auth/passkey/login/finish", body, cookies, nil)
}

// passkeyLogin runs a whole passkey login with a presenting handle.
func (e *pkEnv) passkeyLogin(a *softAuth, handle []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	challenge, ck := e.loginBegin()
	return e.loginFinish(ck, a.assertionBody(challenge, handle))
}

func assertGenericPasskeyFailure(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); msg != passkeyLoginFailedMsg {
		t.Fatalf("error = %q, want the generic %q", msg, passkeyLoginFailedMsg)
	}
	assertNoSession(t, rec)
	if ck := cookieByName(rec, passkeyLoginCookie); ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("webauthn_login cookie must be cleared on failure, got %+v", ck)
	}
}
