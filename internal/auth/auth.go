package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"firewall-mon/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrAccountLocked      = errors.New("account is locked")
	ErrNoJWTSecret        = errors.New("JWT secret key not configured")
)

type Claims struct {
	Username     string `json:"username"`
	UserID       uint   `json:"user_id"`
	TokenVersion uint   `json:"token_version"`
	// Role is the RBAC role baked into the session at login. Tokens minted
	// before the RBAC upgrade have no role claim; EffectiveRole defaults those
	// to admin — safe because pre-upgrade exactly one user existed and it was
	// the admin, and such tokens age out within TokenExpiry (≤24h). Role
	// changes bump TokenVersion, so a stale role can't outlive revocation.
	Role string `json:"role,omitempty"`
	// Stage marks a partially-authenticated token. "" = full session;
	// StageTOTP = password verified, TOTP code still owed (P0-3). Every
	// admin-facing auth middleware MUST reject Stage != "" — a pending token
	// grants exactly one thing: the right to call POST /api/auth/totp.
	Stage string `json:"stage,omitempty"`
	jwt.RegisteredClaims
}

// StageTOTP is the Claims.Stage value of a pending two-factor login.
const StageTOTP = "totp"

// PendingTokenExpiry bounds how long a password-verified login may wait for
// its TOTP code before starting over.
const PendingTokenExpiry = 5 * time.Minute

// EffectiveRole returns the role this session grants, defaulting legacy
// pre-RBAC tokens (no role claim) to admin. See the Role field comment.
func (c *Claims) EffectiveRole() string {
	if c.Role == "" {
		return RoleAdmin
	}
	return c.Role
}

type AdminAuth struct {
	ID                 uint
	Username           string
	Password           string
	TokenVersion       uint
	MustChangePassword bool
	Role               string
	Disabled           bool
	TOTPEnabled        bool
	// TOTPSecret is DECRYPTED by the store (like device secrets) — empty when
	// 2FA is not enrolled or the encryption key is unavailable (fail-closed:
	// an empty secret validates no code).
	TOTPSecret string
}

type Database interface {
	GetAdminByUsername(username string) (*AdminAuth, error)
	UpdateAdminPassword(id uint, password string) error
	GetAdminTokenVersion(id uint) (uint, error)
	IncrementAdminTokenVersion(id uint) error
}

type AuthManager struct {
	db            Database
	config        *config.Config
	loginAttempts map[string][]time.Time
	attemptsMu    sync.RWMutex
	// lastTOTPSlot records, per user, the most recent 30s TOTP time-slot that
	// successfully authenticated — a valid code is single-use within its slot
	// (replay guard). The map is PER-PROCESS: under the normal AUDIT-040
	// singleton exactly one cmd/api serves logins, so the guard is complete.
	// Under ALLOW_MULTI_API=true each instance keeps its own map, so a
	// still-fresh intercepted code could be replayed once per extra instance
	// — an accepted follower-mode divergence, documented alongside the
	// lockout/rate-limit caveats in docs/OPERATIONS.md.
	lastTOTPSlot map[uint]int64
}

func NewAuthManager(cfg *config.Config, db Database) *AuthManager {
	return &AuthManager{
		db:            db,
		config:        cfg,
		loginAttempts: make(map[string][]time.Time),
		lastTOTPSlot:  make(map[uint]int64),
	}
}

// lockoutParams returns the configured attempt ceiling and window.
func (am *AuthManager) lockoutParams() (int, time.Duration) {
	maxAttempts := 5
	lockoutDuration := 15 * time.Minute
	if am.config != nil {
		maxAttempts = am.config.Auth.MaxLoginAttempts
		lockoutDuration = am.config.Auth.LockoutDuration
	}
	return maxAttempts, lockoutDuration
}

// lockoutKeyFor builds the per-username+IP tracking key.
func lockoutKeyFor(username, ip string) string {
	if ip != "" {
		return username + ":" + ip
	}
	return username
}

// recentFailuresLocked prunes expired attempts for key and returns the live
// ones. Caller must hold attemptsMu.
func (am *AuthManager) recentFailuresLocked(key string, window time.Duration) []time.Time {
	cutoff := time.Now().Add(-window)
	attempts := am.loginAttempts[key]
	recent := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(am.loginAttempts, key)
	} else {
		am.loginAttempts[key] = recent
	}
	return recent
}

// IsLocked reports whether username+ip has exhausted its attempt budget.
// Password and TOTP failures share the same bucket (P0-3), so the second
// factor cannot be brute-forced on a fresh budget.
func (am *AuthManager) IsLocked(username, ip string) bool {
	if am == nil {
		return true
	}
	maxAttempts, window := am.lockoutParams()
	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()
	return len(am.recentFailuresLocked(lockoutKeyFor(username, ip), window)) >= maxAttempts
}

// RecordFailure counts a failed authentication attempt (password or TOTP)
// toward the shared lockout bucket.
func (am *AuthManager) RecordFailure(username, ip string) {
	if am == nil {
		return
	}
	_, window := am.lockoutParams()
	key := lockoutKeyFor(username, ip)
	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()
	am.loginAttempts[key] = append(am.recentFailuresLocked(key, window), time.Now())
}

// ClearFailures resets the bucket after a fully successful authentication.
func (am *AuthManager) ClearFailures(username, ip string) {
	if am == nil {
		return
	}
	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()
	delete(am.loginAttempts, lockoutKeyFor(username, ip))
}

// MarkTOTPSlotUsed atomically records the current 30s TOTP slot for a user,
// returning false when that slot already authenticated once — the replay
// guard: an intercepted still-fresh code cannot be used a second time.
func (am *AuthManager) MarkTOTPSlotUsed(userID uint) bool {
	slot := time.Now().Unix() / 30
	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()
	if am.lastTOTPSlot[userID] == slot {
		return false
	}
	am.lastTOTPSlot[userID] = slot
	return true
}

// ValidateCredentials checks username/password with per-IP lockout tracking.
// The ip parameter is the client's IP address; lockout is tracked per username+IP
// pair so that an attacker cannot DoS a legitimate user from a different IP.
func (am *AuthManager) ValidateCredentials(username, password string, ips ...string) error {
	if am == nil {
		return ErrInvalidCredentials
	}

	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()

	maxAttempts := 5
	lockoutDuration := 15 * time.Minute
	if am.config != nil {
		maxAttempts = am.config.Auth.MaxLoginAttempts
		lockoutDuration = am.config.Auth.LockoutDuration
	}

	// Build lockout key: username+IP for per-source tracking
	lockoutKey := username
	if len(ips) > 0 && ips[0] != "" {
		lockoutKey = username + ":" + ips[0]
	}

	// Filter out attempts older than lockout duration
	cutoff := time.Now().Add(-lockoutDuration)
	attempts := am.loginAttempts[lockoutKey]
	recentAttempts := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if t.After(cutoff) {
			recentAttempts = append(recentAttempts, t)
		}
	}
	if len(recentAttempts) == 0 {
		delete(am.loginAttempts, lockoutKey)
	} else {
		am.loginAttempts[lockoutKey] = recentAttempts
	}

	if len(recentAttempts) >= maxAttempts {
		return ErrAccountLocked
	}

	if am.db == nil {
		am.loginAttempts[lockoutKey] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	admin, err := am.db.GetAdminByUsername(username)
	if err != nil || admin == nil {
		am.loginAttempts[lockoutKey] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	if admin.Password == "" {
		am.loginAttempts[lockoutKey] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) != nil {
		am.loginAttempts[lockoutKey] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	// A disabled account is indistinguishable from bad credentials to the
	// caller (no account-state oracle), and the failed attempt still counts
	// toward lockout. Checked only after the bcrypt compare so timing stays
	// uniform with the credential-failure path.
	if admin.Disabled {
		am.loginAttempts[lockoutKey] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	// Successful login clears attempts for this IP
	delete(am.loginAttempts, lockoutKey)
	return nil
}

func (am *AuthManager) HashPassword(password string) (string, error) {
	cost := bcrypt.DefaultCost
	if am.config != nil && am.config.Auth.BcryptCost > 0 {
		cost = am.config.Auth.BcryptCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (am *AuthManager) CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (am *AuthManager) GenerateToken(username string, userID uint, tokenVersion uint, role string) (string, error) {
	if am.config == nil || am.config.Server.JWTSecretKey == "" {
		return "", ErrNoJWTSecret
	}

	secretKey := am.config.Server.JWTSecretKey

	tokenExpiry := 24 * time.Hour
	if am.config.Auth.TokenExpiry > 0 {
		tokenExpiry = am.config.Auth.TokenExpiry
	}

	claims := Claims{
		Username:     username,
		UserID:       userID,
		TokenVersion: tokenVersion,
		Role:         role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

// GeneratePendingToken mints the short-lived Stage=totp JWT issued after a
// correct password when the account has 2FA enabled (P0-3). It carries no
// role (it grants no admin access — middleware rejects Stage != "") and lives
// PendingTokenExpiry. Version-checked like any token, so revocation applies.
func (am *AuthManager) GeneratePendingToken(username string, userID uint, tokenVersion uint) (string, error) {
	if am.config == nil || am.config.Server.JWTSecretKey == "" {
		return "", ErrNoJWTSecret
	}
	claims := Claims{
		Username:     username,
		UserID:       userID,
		TokenVersion: tokenVersion,
		Stage:        StageTOTP,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(PendingTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(am.config.Server.JWTSecretKey))
}

func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	if am.config == nil || am.config.Server.JWTSecretKey == "" {
		return nil, ErrNoJWTSecret
	}

	secretKey := am.config.Server.JWTSecretKey

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check token version against DB to reject revoked tokens. Fail CLOSED:
		// if the version lookup errors (transient DB failure, statement_timeout,
		// or the row is gone), reject the token rather than accept it — otherwise
		// logout / password-change / compromise revocation silently stops working
		// exactly when the DB is under stress. A legitimate admin simply
		// re-authenticates; a stolen-but-unexpired JWT does not slip through.
		if am.db != nil {
			currentVersion, err := am.db.GetAdminTokenVersion(claims.UserID)
			if err != nil || claims.TokenVersion != currentVersion {
				return nil, ErrInvalidToken
			}
		}
		return claims, nil
	}

	return nil, ErrInvalidToken
}

func GenerateSecureToken(length int) (string, error) {
	// Compute enough random bytes so base64 output >= desired length
	needed := (length*3 + 3) / 4
	b := make([]byte, needed)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(b)
	if len(encoded) < length {
		return encoded, nil
	}
	return encoded[:length], nil
}

// PruneExpiredAttempts removes login attempt entries where all attempts have expired.
func (am *AuthManager) PruneExpiredAttempts() {
	lockoutDuration := 15 * time.Minute
	if am.config != nil {
		lockoutDuration = am.config.Auth.LockoutDuration
	}
	cutoff := time.Now().Add(-lockoutDuration)

	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()

	for username, attempts := range am.loginAttempts {
		recent := make([]time.Time, 0, len(attempts))
		for _, t := range attempts {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(am.loginAttempts, username)
		} else {
			am.loginAttempts[username] = recent
		}
	}
}

func (am *AuthManager) UpdatePassword(username, newPassword string) error {
	if am.db == nil {
		return errors.New("database not configured")
	}

	admin, err := am.db.GetAdminByUsername(username)
	if err != nil {
		return err
	}
	if admin == nil {
		return errors.New("admin not found")
	}

	hashedPassword, err := am.HashPassword(newPassword)
	if err != nil {
		return err
	}

	return am.db.UpdateAdminPassword(admin.ID, hashedPassword)
}
