package auth_test

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AUDIT-117: first tests for internal/auth — the security boundary. Covers the
// login-lockout state machine, the bcrypt round-trip, JWT sign/validate
// including alg-confusion + wrong-secret + expiry rejection, and the
// token-version revocation check, plus the GenerateSecureToken length invariant.

// fakeDB is an in-memory auth.Database for tests.
type fakeDB struct {
	admins     map[string]*auth.AdminAuth
	version    map[uint]uint
	versionErr error
}

func newFakeDB() *fakeDB {
	return &fakeDB{admins: map[string]*auth.AdminAuth{}, version: map[uint]uint{}}
}

func (f *fakeDB) GetAdminByUsername(u string) (*auth.AdminAuth, error) {
	a, ok := f.admins[u]
	if !ok {
		return nil, nil
	}
	return a, nil
}

func (f *fakeDB) UpdateAdminPassword(id uint, password string) error {
	for _, a := range f.admins {
		if a.ID == id {
			a.Password = password
		}
	}
	return nil
}

func (f *fakeDB) GetAdminTokenVersion(id uint) (uint, error) {
	if f.versionErr != nil {
		return 0, f.versionErr
	}
	return f.version[id], nil
}

func (f *fakeDB) IncrementAdminTokenVersion(id uint) error {
	f.version[id]++
	return nil
}

// testConfig returns a config wired for fast tests (cheap bcrypt, 3-attempt
// lockout) with a fixed JWT secret.
func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	cfg.Auth.BcryptCost = bcrypt.MinCost
	cfg.Auth.MaxLoginAttempts = 3
	cfg.Auth.LockoutDuration = 15 * time.Minute
	cfg.Auth.TokenExpiry = time.Hour
	return cfg
}

// managerWithUser builds an AuthManager whose DB holds one admin with the given
// plaintext password (hashed at the test cost).
func managerWithUser(t *testing.T, username, password string) (*auth.AuthManager, *fakeDB) {
	t.Helper()
	cfg := testConfig()
	db := newFakeDB()
	am := auth.NewAuthManager(cfg, db)
	hash, err := am.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	db.admins[username] = &auth.AdminAuth{ID: 1, Username: username, Password: hash}
	return am, db
}

func TestHashPassword_RoundTrip_AUDIT117(t *testing.T) {
	am := auth.NewAuthManager(testConfig(), nil)
	hash, err := am.HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "hunter2" {
		t.Fatal("password stored in plaintext")
	}
	if !am.CheckPassword("hunter2", hash) {
		t.Error("CheckPassword rejected the correct password")
	}
	if am.CheckPassword("wrong", hash) {
		t.Error("CheckPassword accepted a wrong password")
	}
}

func TestValidateCredentials_SuccessAndFailure_AUDIT117(t *testing.T) {
	am, _ := managerWithUser(t, "admin", "correct-horse")

	if err := am.ValidateCredentials("admin", "correct-horse", "1.2.3.4"); err != nil {
		t.Errorf("valid credentials rejected: %v", err)
	}
	if err := am.ValidateCredentials("admin", "wrong", "1.2.3.4"); err != auth.ErrInvalidCredentials {
		t.Errorf("wrong password: got %v, want ErrInvalidCredentials", err)
	}
	if err := am.ValidateCredentials("ghost", "whatever", "1.2.3.4"); err != auth.ErrInvalidCredentials {
		t.Errorf("unknown user: got %v, want ErrInvalidCredentials", err)
	}
}

func TestValidateCredentials_LockoutAfterMaxAttempts_AUDIT117(t *testing.T) {
	am, _ := managerWithUser(t, "admin", "correct-horse")
	const ip = "10.0.0.1"

	// 3 failures (MaxLoginAttempts) are allowed through as ErrInvalidCredentials.
	for i := 0; i < 3; i++ {
		if err := am.ValidateCredentials("admin", "nope", ip); err != auth.ErrInvalidCredentials {
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	// The next attempt — even with the CORRECT password — is locked out.
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != auth.ErrAccountLocked {
		t.Errorf("after max attempts: got %v, want ErrAccountLocked", err)
	}
	// A different source IP is tracked separately and is NOT locked.
	if err := am.ValidateCredentials("admin", "correct-horse", "10.0.0.2"); err != nil {
		t.Errorf("a different IP must not inherit the lockout: got %v", err)
	}
}

func TestValidateCredentials_SuccessClearsAttempts_AUDIT117(t *testing.T) {
	am, _ := managerWithUser(t, "admin", "correct-horse")
	const ip = "10.0.0.9"

	for i := 0; i < 2; i++ { // below the limit
		_ = am.ValidateCredentials("admin", "nope", ip)
	}
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Fatalf("valid login after some failures should succeed: %v", err)
	}
	// Counter was cleared, so we can fail the full budget again without lockout.
	for i := 0; i < 3; i++ {
		if err := am.ValidateCredentials("admin", "nope", ip); err != auth.ErrInvalidCredentials {
			t.Fatalf("post-clear attempt %d: got %v, want ErrInvalidCredentials", i+1, err)
		}
	}
}

func TestGenerateAndValidateToken_RoundTrip_AUDIT117(t *testing.T) {
	am, db := managerWithUser(t, "admin", "pw")
	db.version[1] = 7 // current token version in DB must match the minted token
	tok, err := am.GenerateToken("admin", 1, 7)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := am.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Username != "admin" || claims.UserID != 1 || claims.TokenVersion != 7 {
		t.Errorf("claims round-trip mismatch: %+v", claims)
	}
}

func TestGenerateToken_NoSecret_AUDIT117(t *testing.T) {
	cfg := testConfig()
	cfg.Server.JWTSecretKey = ""
	am := auth.NewAuthManager(cfg, newFakeDB())
	if _, err := am.GenerateToken("admin", 1, 0); err != auth.ErrNoJWTSecret {
		t.Errorf("got %v, want ErrNoJWTSecret", err)
	}
}

func TestValidateToken_RejectsWrongSecret_AUDIT117(t *testing.T) {
	am, _ := managerWithUser(t, "admin", "pw")
	// Mint a token with the right claims but a DIFFERENT signing secret.
	claims := auth.Claims{Username: "admin", UserID: 1, RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("a-different-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := am.ValidateToken(forged); err != auth.ErrInvalidToken {
		t.Errorf("wrong-secret token: got %v, want ErrInvalidToken", err)
	}
}

func TestValidateToken_RejectsAlgConfusion_AUDIT117(t *testing.T) {
	am, _ := managerWithUser(t, "admin", "pw")
	// "alg: none" — the classic JWT bypass. ValidateToken's keyfunc must reject
	// any non-HMAC signing method.
	claims := auth.Claims{Username: "admin", UserID: 1, RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	noneTok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := am.ValidateToken(noneTok); err != auth.ErrInvalidToken {
		t.Errorf("alg=none token: got %v, want ErrInvalidToken", err)
	}
}

func TestValidateToken_RejectsExpired_AUDIT117(t *testing.T) {
	am, _ := managerWithUser(t, "admin", "pw")
	claims := auth.Claims{Username: "admin", UserID: 1, RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // already expired
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
	}}
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testConfig().Server.JWTSecretKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := am.ValidateToken(expired); err != auth.ErrInvalidToken {
		t.Errorf("expired token: got %v, want ErrInvalidToken", err)
	}
}

func TestValidateToken_TokenVersionMismatch_AUDIT117(t *testing.T) {
	am, db := managerWithUser(t, "admin", "pw")
	// Issue at version 1, then the DB advances to version 2 (a forced logout /
	// password change). The old token must be rejected.
	tok, err := am.GenerateToken("admin", 1, 1)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	db.version[1] = 2
	if _, err := am.ValidateToken(tok); err != auth.ErrInvalidToken {
		t.Errorf("stale token version: got %v, want ErrInvalidToken", err)
	}
	// A freshly issued token at the current version still validates.
	fresh, _ := am.GenerateToken("admin", 1, 2)
	if _, err := am.ValidateToken(fresh); err != nil {
		t.Errorf("current-version token rejected: %v", err)
	}
}

func TestGenerateSecureToken_LengthInvariant_AUDIT117(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range []int{1, 8, 16, 32, 43, 64, 100} {
		tok, err := auth.GenerateSecureToken(n)
		if err != nil {
			t.Fatalf("GenerateSecureToken(%d): %v", n, err)
		}
		if len(tok) != n {
			t.Errorf("GenerateSecureToken(%d): len=%d", n, len(tok))
		}
		if strings.ContainsAny(tok, "+/=") {
			t.Errorf("GenerateSecureToken(%d) is not URL-safe: %q", n, tok)
		}
		if seen[tok] {
			t.Errorf("GenerateSecureToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}
