package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/config"

	"github.com/gin-gonic/gin"
)

const csrfTestSecret = "test-only-csrf-secret-not-a-real-key-xxxxxxxxxxxx"

// TestGenerateCSRFToken_RandomPerCall pins D-13: two tokens for the same
// session differ (the pre-fix token was a pure function of the auth cookie),
// and both verify.
func TestGenerateCSRFToken_RandomPerCall(t *testing.T) {
	a, err := GenerateCSRFToken("session-A", csrfTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateCSRFToken("session-A", csrfTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two tokens for one session are identical (%q): token is deterministic", a)
	}
	for _, tok := range []string{a, b} {
		if !ValidCSRFToken(tok, "session-A", csrfTestSecret) {
			t.Errorf("freshly minted token %q does not verify", tok)
		}
	}
}

func TestValidCSRFToken_Rejects(t *testing.T) {
	tok, err := GenerateCSRFToken("session-A", csrfTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	nonce, sig, _ := strings.Cut(tok, ".")
	flip := func(s string) string {
		b := []byte(s)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		return string(b)
	}
	// The pre-D-13 format: HMAC(jwtSecret, authToken), no nonce.
	legacy := hmac.New(sha256.New, []byte(csrfTestSecret))
	legacy.Write([]byte("session-A"))

	cases := map[string]struct{ token, session, secret string }{
		"other session":        {tok, "session-B", csrfTestSecret},
		"other secret":         {tok, "session-A", csrfTestSecret + "x"},
		"tampered nonce":       {flip(nonce) + "." + sig, "session-A", csrfTestSecret},
		"tampered signature":   {nonce + "." + flip(sig), "session-A", csrfTestSecret},
		"no separator":         {nonce + sig, "session-A", csrfTestSecret},
		"short nonce":          {nonce[:8] + "." + sig, "session-A", csrfTestSecret},
		"non-hex nonce":        {strings.Repeat("z", len(nonce)) + "." + sig, "session-A", csrfTestSecret},
		"empty":                {"", "session-A", csrfTestSecret},
		"empty session":        {tok, "", csrfTestSecret},
		"legacy deterministic": {hex.EncodeToString(legacy.Sum(nil)), "session-A", csrfTestSecret},
	}
	for name, c := range cases {
		if ValidCSRFToken(c.token, c.session, c.secret) {
			t.Errorf("%s: token accepted", name)
		}
	}
}

// TestCSRFToken_KeySeparatedFromJWT pins the D-13 key derivation: a token
// whose MAC uses the raw JWT secret (no "fwmon-csrf-v1" derivation) must not
// verify, so CSRF and JWT signing never share a key.
func TestCSRFToken_KeySeparatedFromJWT(t *testing.T) {
	nonce := strings.Repeat("ab", csrfNonceBytes)
	raw := hmac.New(sha256.New, []byte(csrfTestSecret))
	raw.Write([]byte(nonce))
	raw.Write([]byte{0})
	raw.Write([]byte("session-A"))
	forged := nonce + "." + hex.EncodeToString(raw.Sum(nil))
	if ValidCSRFToken(forged, "session-A", csrfTestSecret) {
		t.Fatal("token MACed with the raw JWT secret verified: the CSRF key is not domain-separated")
	}
	if _, err := GenerateCSRFToken("", csrfTestSecret); err == nil {
		t.Error("GenerateCSRFToken accepted an empty session")
	}
}

// TestCSRFProtection_RandomToken drives the middleware end to end: a minted
// token for the request's own auth cookie passes, one minted for another
// session is refused.
func TestCSRFProtection_RandomToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = csrfTestSecret
	r := gin.New()
	r.Use(CSRFProtection(cfg))
	r.POST("/x", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	do := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "session-A"})
		req.Header.Set("X-CSRF-Token", token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	own, _ := GenerateCSRFToken("session-A", csrfTestSecret)
	if code := do(own); code != http.StatusNoContent {
		t.Errorf("own token: status = %d, want 204", code)
	}
	other, _ := GenerateCSRFToken("session-B", csrfTestSecret)
	if code := do(other); code != http.StatusForbidden {
		t.Errorf("token for another session: status = %d, want 403", code)
	}
}
