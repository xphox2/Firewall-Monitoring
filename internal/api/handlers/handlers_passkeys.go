package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/passkey"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Passkey (WebAuthn) login, registration and management. Design invariants,
// each covered by a test in handlers_passkeys_test.go:
//
//   - Kill switch: with h.passkeys == nil (WEBAUTHN_ENABLED unset/false or an
//     invalid configuration) every passkey endpoint answers 404 and the public
//     config reports passkeys unavailable. Stored credentials are untouched.
//   - A login assertion maps to exactly one account: credential by raw id →
//     owner by admin_id → constant-time compare of the owner's STORED user
//     handle with the one the authenticator returned → owner must exist and be
//     enabled. The library then re-checks handle and credential membership.
//   - User verification is required in the library config AND re-checked on
//     the flags of each assertion / attestation.
//   - A clone warning (counter did not advance) is rejected and audited, and
//     the stored counter is not updated.
//   - Every login failure returns the same generic 401; details go to the
//     server log, login_attempts and audit_logs only.
//   - Management is session-only (API tokens get 403), identity comes from
//     the session's user_id with the account loaded BY ID, and every query is
//     scoped by admin_id. Register-begin and delete require a fresh password
//     (+ TOTP when enrolled, shared replay guard) behind a per-user limiter.

const (
	loginMethodPasskey = "passkey"

	passkeyLoginCookie     = "webauthn_login"    // #nosec G101 -- a cookie name, not a credential
	passkeyLoginCookiePath = "/api/auth/passkey" // #nosec G101 -- a cookie path, not a credential

	// passkeyLoginFailedMsg is the ONE message every passkey login failure
	// returns, whatever the cause.
	passkeyLoginFailedMsg = "Passkey sign-in failed"

	// maxPasskeyBody caps a ceremony response body (real ones are ~1-4 KiB).
	maxPasskeyBody = 64 << 10

	maxPasskeyNameLen  = 64
	defaultPasskeyName = "Passkey"
	userHandleBytes    = 64
)

// SetPasskeys installs the enabled passkey service (nil = disabled).
func (h *Handler) SetPasskeys(s *passkey.Service) { h.passkeys = s }

// passkeysOr404 returns the service, or writes the kill-switch 404.
func (h *Handler) passkeysOr404(c *gin.Context) (*passkey.Service, bool) {
	if h.passkeys == nil {
		c.JSON(http.StatusNotFound, response.Error("Not found"))
		return nil, false
	}
	return h.passkeys, true
}

// passkeyUser adapts an account to webauthn.User. id is always the STORED
// user handle — never anything taken from the request.
type passkeyUser struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func newPasskeyUser(admin *models.Admin, rows []models.WebAuthnCredential) (*passkeyUser, error) {
	display := admin.FullName
	if display == "" {
		display = admin.Username
	}
	u := &passkeyUser{id: admin.WebAuthnUserHandle, name: admin.Username, displayName: display}
	for i := range rows {
		cred, err := libCredential(&rows[i])
		if err != nil {
			return nil, err
		}
		u.creds = append(u.creds, cred)
	}
	return u, nil
}

// libCredential rebuilds the library's credential record from a row. Only
// the fields assertion verification reads are needed.
func libCredential(row *models.WebAuthnCredential) (webauthn.Credential, error) {
	if row.SignCount < 0 || row.SignCount > math.MaxUint32 {
		return webauthn.Credential{}, fmt.Errorf("passkey %d: stored sign count %d out of range", row.ID, row.SignCount)
	}
	var transports []protocol.AuthenticatorTransport
	for _, t := range strings.Split(row.Transports, ",") {
		if t = strings.TrimSpace(t); t != "" {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID:              row.CredentialID,
		PublicKey:       row.PublicKey,
		AttestationType: row.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true, // registration required UV
			BackupEligible: row.BackupEligible,
			BackupState:    row.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    row.AAGUID,
			SignCount: uint32(row.SignCount), // #nosec G115 -- range-checked above
		},
	}, nil
}

func strPtr(s string) *string { return &s }

// credIDPrefix is the loggable form of a credential id: the first 8 bytes.
func credIDPrefix(id []byte) string {
	if len(id) > 8 {
		id = id[:8]
	}
	return hex.EncodeToString(id)
}

func aaguidString(b []byte) string {
	if u, err := uuid.FromBytes(b); err == nil {
		return u.String()
	}
	return "unknown"
}

// passkeyAudit writes an explicit audit_logs row for a passkey action.
// Best effort: a write failure is logged, never surfaced.
func passkeyAudit(c *gin.Context, db database.Store, actor string, actorID uint, action, target string, status int) {
	if db == nil {
		return
	}
	ua := c.Request.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	if err := db.SaveAuditLog(&models.AuditLog{
		CreatedAt: time.Now(),
		Actor:     actor,
		ActorID:   actorID,
		Method:    c.Request.Method,
		Action:    action,
		Target:    target,
		Status:    status,
		IPAddress: c.ClientIP(),
		UserAgent: ua,
	}); err != nil {
		log.Printf("passkeys: audit write failed for %s by %q: %v", action, actor, err)
	}
}

// --- Public login ------------------------------------------------------------

// GetPasskeyConfig (GET /api/auth/passkey/config) tells the login page whether
// passkey login is available and from which origins. Answers 200 even when
// disabled ({"enabled": false}) — it is how the UI learns that.
func (h *Handler) GetPasskeyConfig(c *gin.Context) {
	if h.passkeys == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"enabled": false}))
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"enabled": true,
		"rp_id":   h.passkeys.Settings.RPID,
		"origins": h.passkeys.Settings.Origins,
	}))
}

func (h *Handler) setPasskeyLoginCookie(c *gin.Context, value string, maxAge int) {
	secure, _, _ := h.sessionCookieParams(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     passkeyLoginCookie,
		Value:    value,
		MaxAge:   maxAge,
		Path:     passkeyLoginCookiePath,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// PasskeyLoginBegin (POST /api/auth/passkey/login/begin) starts a
// usernameless (discoverable) login: no username is taken, so nothing about
// accounts can be enumerated. The ceremony is stored in memory under a fresh
// random id carried by the webauthn_login cookie.
func (h *Handler) PasskeyLoginBegin(c *gin.Context) {
	svc, ok := h.passkeysOr404(c)
	if !ok {
		return
	}
	assertion, session, err := svc.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		httputil.InternalError(c, "Failed to start passkey sign-in", err)
		return
	}
	id, err := passkey.NewLoginCeremonyID()
	if err != nil {
		httputil.InternalError(c, "Failed to start passkey sign-in", err)
		return
	}
	svc.LoginCeremonies.Put(id, passkey.Ceremony{Kind: passkey.KindLogin, Session: *session})
	h.setPasskeyLoginCookie(c, id, int(passkey.CeremonyTimeout.Seconds()))
	c.JSON(http.StatusOK, response.Success(assertion))
}

// PasskeyLoginFinish (POST /api/auth/passkey/login/finish) verifies the
// assertion and, on success, issues a full session through completeLogin
// (no TOTP stage: a user-verified passkey is itself multi-factor). The
// ceremony cookie is cleared on every outcome.
func (h *Handler) PasskeyLoginFinish(c *gin.Context) {
	svc, ok := h.passkeysOr404(c)
	if !ok {
		return
	}
	h.setPasskeyLoginCookie(c, "", -1)

	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	username := ""
	var ownerID uint
	detail := ""
	recordAttempt := func(success bool) {
		if dbErr := db.SaveLoginAttempt(&models.LoginAttempt{
			Timestamp: time.Now(),
			Username:  username,
			IPAddress: ip,
			Success:   success,
			UserAgent: userAgent,
			Method:    strPtr(loginMethodPasskey),
		}); dbErr != nil {
			log.Printf("Failed to save login attempt: %v", dbErr)
		}
	}
	fail := func(reason string) {
		log.Printf("passkey login refused (ip=%s %s): %s", ip, detail, reason)
		recordAttempt(false)
		passkeyAudit(c, db, username, ownerID, "passkey_login_failure", strings.TrimSpace(detail+" reason="+reason), http.StatusUnauthorized)
		c.JSON(http.StatusUnauthorized, response.Error(passkeyLoginFailedMsg))
	}

	ceremonyID, err := c.Cookie(passkeyLoginCookie)
	if err != nil || ceremonyID == "" {
		fail("no ceremony cookie")
		return
	}
	ceremony, ok := svc.LoginCeremonies.Take(passkey.KindLogin, ceremonyID)
	if !ok {
		fail("ceremony unknown, expired, already used or of the wrong kind")
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(http.MaxBytesReader(c.Writer, c.Request.Body, maxPasskeyBody))
	if err != nil {
		fail(fmt.Sprintf("unparseable assertion: %v", err))
		return
	}
	detail = "cred=" + credIDPrefix(parsed.RawID)

	// The discoverable-credential handler: the ONLY way an assertion gets an
	// account. Any doubt is a refusal.
	var owner *models.Admin
	var ownerRows []models.WebAuthnCredential
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		row, err := db.GetPasskeyByCredentialID(rawID)
		if err != nil {
			return nil, fmt.Errorf("credential lookup: %w", err)
		}
		if row == nil {
			return nil, errors.New("unknown credential")
		}
		admin, err := db.GetAdminByID(row.AdminID)
		if err != nil {
			return nil, fmt.Errorf("owner lookup: %w", err)
		}
		if admin == nil {
			return nil, errors.New("credential owner no longer exists")
		}
		if len(admin.WebAuthnUserHandle) == 0 ||
			subtle.ConstantTimeCompare(admin.WebAuthnUserHandle, userHandle) != 1 {
			return nil, errors.New("user handle does not match the credential owner")
		}
		if admin.Disabled {
			return nil, errors.New("credential owner is disabled")
		}
		rows, err := db.ListPasskeys(admin.ID)
		if err != nil {
			return nil, fmt.Errorf("owner credentials: %w", err)
		}
		user, err := newPasskeyUser(admin, rows)
		if err != nil {
			return nil, err
		}
		owner, ownerRows = admin, rows
		return user, nil
	}

	_, credential, err := svc.WebAuthn.ValidatePasskeyLogin(lookup, ceremony.Session, parsed)
	if owner != nil {
		username, ownerID = owner.Username, owner.ID
	}
	if err != nil {
		fail(fmt.Sprintf("assertion rejected: %v", err))
		return
	}
	if owner == nil || credential == nil {
		fail("no owner resolved")
		return
	}
	flags := parsed.Response.AuthenticatorData.Flags
	detail = fmt.Sprintf("cred=%s aaguid=%s uv=%t be=%t bs=%t", credIDPrefix(credential.ID),
		aaguidString(credential.Authenticator.AAGUID), flags.HasUserVerified(), flags.HasBackupEligible(), flags.HasBackupState())
	if !flags.HasUserVerified() {
		fail("assertion without user verification")
		return
	}
	if credential.Authenticator.CloneWarning {
		passkeyAudit(c, db, username, ownerID, "passkey_clone_warning", detail, http.StatusUnauthorized)
		fail("clone warning: signature counter did not advance")
		return
	}
	var row *models.WebAuthnCredential
	for i := range ownerRows {
		if subtle.ConstantTimeCompare(ownerRows[i].CredentialID, credential.ID) == 1 {
			row = &ownerRows[i]
			break
		}
	}
	if row == nil {
		fail("verified credential not among the owner's rows")
		return
	}
	updated, err := db.RecordPasskeyUse(row.ID, owner.ID, credential.Authenticator.SignCount, flags.HasBackupState(), time.Now())
	if err != nil {
		fail(fmt.Sprintf("could not persist credential use: %v", err))
		return
	}
	if !updated {
		// The compare-and-set found the stored counter no longer below the
		// asserted one: a concurrent assertion with the same counter (a clone
		// racing the original) already advanced it after the clone check above
		// read the row. Same outcome as the library's clone warning — unless
		// the row simply vanished (credential deleted mid-ceremony).
		cur, lerr := db.GetPasskeyByCredentialID(credential.ID)
		if lerr != nil {
			fail(fmt.Sprintf("could not re-check credential after refused counter write: %v", lerr))
			return
		}
		if cur == nil {
			fail("credential removed during the ceremony")
			return
		}
		passkeyAudit(c, db, username, ownerID, "passkey_clone_warning", detail, http.StatusUnauthorized)
		fail("clone warning: signature counter did not advance at commit (concurrent assertion)")
		return
	}

	success := h.completeLogin(c, db, owner.ID, loginMethodPasskey)
	recordAttempt(success)
	if success {
		passkeyAudit(c, db, username, ownerID, "passkey_login_success", detail, http.StatusOK)
	} else {
		log.Printf("passkey login refused at completion (ip=%s %s)", ip, detail)
		passkeyAudit(c, db, username, ownerID, "passkey_login_failure", detail+" reason=completion refused", c.Writer.Status())
	}
}

// passkeyNoticeDTO is one "a passkey named X was added on <date>" notice.
type passkeyNoticeDTO struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// passkeyNotices returns the account's pending new-passkey notices. Never
// fails a login: nil when passkeys are disabled or the lookup errors.
func (h *Handler) passkeyNotices(db database.Store, adminID uint) []passkeyNoticeDTO {
	if h.passkeys == nil || db == nil {
		return nil
	}
	rows, err := db.ListPasskeyNotices(adminID)
	if err != nil {
		log.Printf("passkeys: notice lookup for admin %d failed: %v", adminID, err)
		return nil
	}
	out := make([]passkeyNoticeDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, passkeyNoticeDTO{Name: r.Name, CreatedAt: r.CreatedAt})
	}
	return out
}

// --- Self-service management (/admin/api/passkeys...) ------------------------

// passkeySessionUser enforces the session-only rule (API tokens never reach
// passkey management) and returns the session's own account id — the shared
// sessionUserID (handlers_reauth.go) with the passkey wording on refusal.
func passkeySessionUser(c *gin.Context) (uint, bool) {
	if c.GetString("auth_method") != "session" {
		c.JSON(http.StatusForbidden, response.Error("Passkeys can only be managed from a signed-in browser session"))
		return 0, false
	}
	return sessionUserID(c)
}

type passkeyReauthRequest struct {
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// reauthPasskeyCaller re-verifies the session's OWN account for a passkey
// change: the shared step-up (reauthPassword — session-only, per-account
// limiter, row by id, CheckPassword) plus a fresh TOTP code when 2FA is
// enrolled (reauthTOTP). Writes the response and returns nil on any failure.
func (h *Handler) reauthPasskeyCaller(c *gin.Context, db database.Store, req passkeyReauthRequest) *models.Admin {
	admin := h.reauthPassword(c, db, req.Password, "Password is incorrect")
	if admin == nil || !h.reauthTOTP(c, db, admin, req.TOTPCode) {
		return nil
	}
	return admin
}

// cleanPasskeyName validates a user-supplied passkey name ("" → default).
func cleanPasskeyName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return defaultPasskeyName, true
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxPasskeyNameLen {
		return "", false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return name, true
}

type passkeyRegisterBeginRequest struct {
	passkeyReauthRequest
	Name string `json:"name"`
}

// PasskeyRegisterBegin (POST /admin/api/passkeys/register/begin) re-verifies
// the caller and starts a registration ceremony for the caller's own account
// (at most one outstanding — a new begin supersedes the previous one). The
// account's random 64-byte user handle is created on its first registration.
func (h *Handler) PasskeyRegisterBegin(c *gin.Context) {
	svc, ok := h.passkeysOr404(c)
	if !ok {
		return
	}
	if _, ok := passkeySessionUser(c); !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req passkeyRegisterBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	name, ok := cleanPasskeyName(req.Name)
	if !ok {
		c.JSON(http.StatusBadRequest, response.Error("Passkey name must be at most 64 printable characters"))
		return
	}
	admin := h.reauthPasskeyCaller(c, db, req.passkeyReauthRequest)
	if admin == nil {
		return
	}
	rows, err := db.ListPasskeys(admin.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to load passkeys", err)
		return
	}
	if len(rows) >= database.MaxPasskeysPerUser {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("You already have the maximum of %d passkeys", database.MaxPasskeysPerUser)))
		return
	}
	if len(admin.WebAuthnUserHandle) == 0 {
		candidate := make([]byte, userHandleBytes)
		if _, err := rand.Read(candidate); err != nil {
			httputil.InternalError(c, "Failed to start passkey registration", err)
			return
		}
		handle, err := db.EnsureWebAuthnUserHandle(admin.ID, candidate)
		if err != nil {
			httputil.InternalError(c, "Failed to start passkey registration", err)
			return
		}
		admin.WebAuthnUserHandle = handle
	}
	user, err := newPasskeyUser(admin, rows)
	if err != nil {
		httputil.InternalError(c, "Failed to start passkey registration", err)
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(user.creds))
	for i := range user.creds {
		exclude = append(exclude, user.creds[i].Descriptor())
	}
	creation, session, err := svc.WebAuthn.BeginRegistration(user, webauthn.WithExclusions(exclude))
	if err != nil {
		httputil.InternalError(c, "Failed to start passkey registration", err)
		return
	}
	svc.RegisterCeremonies.Put(passkey.RegistrationKey(admin.ID), passkey.Ceremony{
		Kind: passkey.KindRegister, AdminID: admin.ID, Name: name, Session: *session,
	})
	c.JSON(http.StatusOK, response.Success(creation))
}

// PasskeyRegisterFinish (POST /admin/api/passkeys/register/finish) consumes
// the caller's registration ceremony and stores the new credential. Rejects a
// missing ceremony, an attestation without user verification, a duplicate
// credential id and an 11th passkey.
func (h *Handler) PasskeyRegisterFinish(c *gin.Context) {
	svc, ok := h.passkeysOr404(c)
	if !ok {
		return
	}
	adminID, ok := passkeySessionUser(c)
	if !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	actor := c.GetString("username")
	refuse := func(status int, msg, reason string) {
		log.Printf("passkey registration refused for admin %d: %s", adminID, reason)
		passkeyAudit(c, db, actor, adminID, "passkey_register_failure", "reason="+reason, status)
		c.JSON(status, response.Error(msg))
	}
	ceremony, ok := svc.RegisterCeremonies.Take(passkey.KindRegister, passkey.RegistrationKey(adminID))
	if !ok || ceremony.AdminID != adminID {
		refuse(http.StatusBadRequest, "No passkey registration in progress — start again", "no ceremony for this account")
		return
	}
	admin, err := db.GetAdminByID(adminID)
	if err != nil {
		httputil.InternalError(c, "Failed to load account", err)
		return
	}
	if admin == nil || admin.Disabled || len(admin.WebAuthnUserHandle) == 0 {
		refuse(http.StatusForbidden, "Passkey registration failed", "account missing, disabled or without a user handle")
		return
	}
	rows, err := db.ListPasskeys(admin.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to load passkeys", err)
		return
	}
	user, err := newPasskeyUser(admin, rows)
	if err != nil {
		httputil.InternalError(c, "Failed to load passkeys", err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(http.MaxBytesReader(c.Writer, c.Request.Body, maxPasskeyBody))
	if err != nil {
		refuse(http.StatusBadRequest, "Passkey registration failed", fmt.Sprintf("unparseable attestation: %v", err))
		return
	}
	credential, err := svc.WebAuthn.CreateCredential(user, ceremony.Session, parsed)
	if err != nil {
		refuse(http.StatusBadRequest, "Passkey registration failed", fmt.Sprintf("attestation rejected: %v", err))
		return
	}
	authFlags := parsed.Response.AttestationObject.AuthData.Flags
	if !authFlags.HasUserVerified() || !credential.Flags.UserVerified {
		refuse(http.StatusBadRequest, "Passkey registration failed", "attestation without user verification")
		return
	}
	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	row := &models.WebAuthnCredential{
		AdminID:         admin.ID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       int64(credential.Authenticator.SignCount),
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		Transports:      strings.Join(transports, ","),
		Name:            ceremony.Name,
		CreatedAt:       time.Now(),
	}
	sessionTV, tvOK := c.Get("token_version")
	tv, _ := sessionTV.(uint)
	if !tvOK {
		refuse(http.StatusBadRequest, "Passkey registration failed", "session carries no token version")
		return
	}
	switch err := db.CreatePasskey(row, tv); {
	case errors.Is(err, database.ErrPasskeyStale):
		refuse(http.StatusBadRequest, "Passkey registration failed", "account changed since the session began (reset, disable or version bump)")
		return
	case errors.Is(err, database.ErrPasskeyLimit):
		refuse(http.StatusConflict, fmt.Sprintf("You already have the maximum of %d passkeys", database.MaxPasskeysPerUser), "limit reached")
		return
	case errors.Is(err, database.ErrPasskeyDuplicate):
		refuse(http.StatusConflict, "This passkey is already registered", "duplicate credential id "+credIDPrefix(credential.ID))
		return
	case err != nil:
		httputil.InternalError(c, "Failed to store passkey", err)
		return
	}
	passkeyAudit(c, db, actor, adminID, "passkey_register",
		fmt.Sprintf("id=%d name=%q cred=%s aaguid=%s be=%t bs=%t", row.ID, row.Name, credIDPrefix(row.CredentialID),
			aaguidString(row.AAGUID), row.BackupEligible, row.BackupState), http.StatusOK)
	c.JSON(http.StatusOK, response.Success(toPasskeyDTO(row)))
}

type passkeyDTO struct {
	ID             uint       `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
}

func toPasskeyDTO(r *models.WebAuthnCredential) passkeyDTO {
	return passkeyDTO{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt,
		BackupEligible: r.BackupEligible, BackupState: r.BackupState}
}

// ListPasskeys (GET /admin/api/passkeys) lists the caller's own passkeys and
// any pending new-passkey notices.
func (h *Handler) ListPasskeys(c *gin.Context) {
	if _, ok := h.passkeysOr404(c); !ok {
		return
	}
	adminID, ok := passkeySessionUser(c)
	if !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	rows, err := db.ListPasskeys(adminID)
	if err != nil {
		httputil.InternalError(c, "Failed to load passkeys", err)
		return
	}
	out := make([]passkeyDTO, 0, len(rows))
	for i := range rows {
		out = append(out, toPasskeyDTO(&rows[i]))
	}
	notices := h.passkeyNotices(db, adminID)
	if notices == nil {
		notices = []passkeyNoticeDTO{}
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"passkeys": out,
		"notices":  notices,
		"max":      database.MaxPasskeysPerUser,
	}))
}

// AckPasskeyNotices (POST /admin/api/passkeys/notices/ack) marks the caller's
// new-passkey notices as seen — only those of passkeys created before the
// calling session was issued.
func (h *Handler) AckPasskeyNotices(c *gin.Context) {
	if _, ok := h.passkeysOr404(c); !ok {
		return
	}
	adminID, ok := passkeySessionUser(c)
	if !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	// Only notices of passkeys created BEFORE this session began are
	// acknowledged: a key registered during this session stays pending until a
	// later login, so a hijacked session cannot hide its own rogue key.
	iatVal, _ := c.Get("session_issued_at")
	iat, _ := iatVal.(time.Time)
	if err := db.AckPasskeyNotices(adminID, iat); err != nil {
		httputil.InternalError(c, "Failed to update notices", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"acknowledged": true}))
}

type passkeyRenameRequest struct {
	Name string `json:"name" binding:"required"`
}

// RenamePasskey (PUT /admin/api/passkeys/:id) renames one of the caller's own
// passkeys. No re-authentication (a name grants nothing).
func (h *Handler) RenamePasskey(c *gin.Context) {
	if _, ok := h.passkeysOr404(c); !ok {
		return
	}
	adminID, ok := passkeySessionUser(c)
	if !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var req passkeyRenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("name is required"))
		return
	}
	name, ok := cleanPasskeyName(req.Name)
	if !ok || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, response.Error("Passkey name must be 1-64 printable characters"))
		return
	}
	found, err := db.RenamePasskey(id, adminID, name)
	if err != nil {
		httputil.InternalError(c, "Failed to rename passkey", err)
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, response.Error("Passkey not found"))
		return
	}
	passkeyAudit(c, db, c.GetString("username"), adminID, "passkey_rename", fmt.Sprintf("id=%d name=%q", id, name), http.StatusOK)
	c.JSON(http.StatusOK, response.Success(gin.H{"id": id, "name": name}))
}

// DeletePasskey (DELETE /admin/api/passkeys/:id, body {password, totp_code})
// re-verifies the caller, deletes one of their own passkeys, bumps their
// token_version — ending every other session, in case the key was
// compromised — and re-issues the caller's session in the same response.
func (h *Handler) DeletePasskey(c *gin.Context) {
	if _, ok := h.passkeysOr404(c); !ok {
		return
	}
	adminID, ok := passkeySessionUser(c)
	if !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var req passkeyReauthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("password is required"))
		return
	}
	if h.reauthPasskeyCaller(c, db, req) == nil {
		return
	}
	// Delete + token_version bump in one transaction.
	found, err := db.DeletePasskeyAndEndSessions(id, adminID)
	if err != nil {
		httputil.InternalError(c, "Failed to delete passkey", err)
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, response.Error("Passkey not found"))
		return
	}
	passkeyAudit(c, db, c.GetString("username"), adminID, "passkey_delete", fmt.Sprintf("id=%d", id), http.StatusOK)
	h.reissueOwnSession(c, db, adminID, gin.H{
		"deleted": id,
		"message": "Passkey deleted. Other sessions have been signed out.",
	})
}

// reissueOwnSession mints a fresh session for the caller after an action that
// bumped their own token_version, re-reading the account by id.
func (h *Handler) reissueOwnSession(c *gin.Context, db database.Store, adminID uint, extra gin.H) {
	admin, err := db.GetAdminByID(adminID)
	if err != nil || admin == nil || admin.Disabled || !auth.ValidRole(admin.Role) {
		httputil.InternalError(c, "Done; please sign in again", err)
		return
	}
	h.issueSession(c, admin.Username, admin.ID, admin.TokenVersion, admin.Role, extra)
}

// discardRegistration drops any outstanding registration ceremony of the
// account (every reset does this; CreatePasskey's token_version check is the
// backstop).
func (h *Handler) discardRegistration(adminID uint) {
	if h.passkeys != nil {
		h.passkeys.RegisterCeremonies.Discard(passkey.RegistrationKey(adminID))
	}
}

// RemoveUserPasskeys (DELETE /admin/api/users/:id/passkeys, admin-only)
// removes every passkey of account :id and ends its sessions (one
// transaction). When :id is the caller, the caller's session is re-issued.
func (h *Handler) RemoveUserPasskeys(c *gin.Context) {
	if _, ok := h.passkeysOr404(c); !ok {
		return
	}
	callerID, ok := passkeySessionUser(c)
	if !ok {
		return
	}
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, target, ok := h.loadUserParam(c)
	if !ok {
		return
	}
	// Delete all + token_version bump in one transaction.
	n, err := db.ResetAdminCredentials(id, database.AdminReset{})
	if err != nil {
		httputil.InternalError(c, "Failed to remove passkeys", err)
		return
	}
	h.discardRegistration(id)
	passkeyAudit(c, db, c.GetString("username"), callerID, "passkey_admin_remove_all",
		fmt.Sprintf("user=%s id=%d removed=%d", target.Username, id, n), http.StatusOK)
	if id == callerID {
		// The bump ended the caller's own session: re-issue it.
		h.reissueOwnSession(c, db, callerID, gin.H{"user_id": id, "removed": n})
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"user_id": id, "removed": n}))
}
