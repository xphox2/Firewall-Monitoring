package auth_test

import (
	"encoding/base64"
	"testing"
	"time"

	"firewall-mon/internal/auth"

	"github.com/golang-jwt/jwt/v5"
)

// L-7: every minted JWT carries a random, unique jti; a present-but-malformed
// jti is rejected; a token without one (minted before the claim existed) is
// still accepted until it expires.

// signClaims signs arbitrary claims with the testConfig secret.
func signClaims(t *testing.T, c auth.Claims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(testConfig().Server.JWTSecretKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestGenerateToken_UniqueWellFormedJTI_L7(t *testing.T) {
	t.Parallel()
	am := auth.NewAuthManager(testConfig(), nil)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		var tok string
		var err error
		if i%2 == 0 {
			tok, err = am.GenerateToken("admin", 1, 0, auth.RoleAdmin)
		} else {
			tok, err = am.GeneratePendingToken("admin", 1, 0)
		}
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		claims, err := am.ValidateToken(tok)
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil || len(raw) != 16 {
			t.Fatalf("jti %q is not 16 random bytes in base64url (err=%v)", claims.ID, err)
		}
		if seen[claims.ID] {
			t.Fatalf("jti %q repeated", claims.ID)
		}
		seen[claims.ID] = true
	}
}

func TestValidateToken_JTIShape_L7(t *testing.T) {
	t.Parallel()
	am := auth.NewAuthManager(testConfig(), nil)
	base := func(id string) auth.Claims {
		return auth.Claims{
			Username: "admin", UserID: 1, Role: auth.RoleAdmin,
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        id,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
	}
	// Pre-upgrade token: no jti at all — accepted (backwards compatibility).
	if _, err := am.ValidateToken(signClaims(t, base(""))); err != nil {
		t.Errorf("token without jti rejected: %v", err)
	}
	for _, bad := range []string{"x", "not base64!!", base64.RawURLEncoding.EncodeToString(make([]byte, 8))} {
		if _, err := am.ValidateToken(signClaims(t, base(bad))); err == nil {
			t.Errorf("token with malformed jti %q accepted", bad)
		}
	}
}
