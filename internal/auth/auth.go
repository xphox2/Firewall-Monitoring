package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrAccountLocked      = errors.New("account is locked due to too many failed attempts")
)

type Claims struct {
	Username string `json:"username"`
	UserID   uint   `json:"user_id"`
	jwt.RegisteredClaims
}

type AuthManager struct {
	config        *config.Config
	loginAttempts map[string][]time.Time
}

func NewAuthManager(cfg *config.Config) *AuthManager {
	return &AuthManager{
		config:        cfg,
		loginAttempts: make(map[string][]time.Time),
	}
}

func (am *AuthManager) ValidateCredentials(username, password string) error {
	if username != am.config.Auth.AdminUsername {
		return ErrInvalidCredentials
	}

	am.cleanOldAttempts(username)

	if len(am.loginAttempts[username]) >= am.config.Auth.MaxLoginAttempts {
		return ErrAccountLocked
	}

	err := bcrypt.CompareHashAndPassword(
		[]byte(am.hashPassword(am.config.Auth.AdminPassword)),
		[]byte(password),
	)

	if err != nil {
		am.loginAttempts[username] = append(am.loginAttempts[username], time.Now())
		return err
	}

	am.loginAttempts[username] = []time.Time{}
	return nil
}

func (am *AuthManager) hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + "fortigate-mon-salt"))
	return hex.EncodeToString(hash[:])
}

func (am *AuthManager) cleanOldAttempts(username string) []time.Time {
	cutoff := time.Now().Add(-am.config.Auth.LockoutDuration)
	var valid []time.Time
	for _, t := range am.loginAttempts[username] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	am.loginAttempts[username] = valid
	return valid
}

func (am *AuthManager) IsLocked(username string) bool {
	am.cleanOldAttempts(username)
	return len(am.loginAttempts[username]) >= am.config.Auth.MaxLoginAttempts
}

func (am *AuthManager) GenerateToken(username string, userID uint) (string, error) {
	claims := Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(am.config.Auth.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "fortigate-mon",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(am.config.Server.JWTSecretKey))
}

func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(am.config.Server.JWTSecretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

func (am *AuthManager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(am.hashPassword(password)),
		am.config.Auth.BcryptCost,
	)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (am *AuthManager) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(am.hashPassword(password)))
	return err == nil
}

func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func RecordLoginAttempt(cfg *config.Config, username, ip, userAgent string, success bool) {
	attempt := models.LoginAttempt{
		Timestamp: time.Now(),
		Username:  username,
		IPAddress: ip,
		Success:   success,
		UserAgent: userAgent,
	}
	_ = attempt
}

func GetLockedIPs(attempts map[string][]time.Time, lockoutDuration time.Duration) []string {
	var locked []string
	cutoff := time.Now().Add(-lockoutDuration)
	for ip, times := range attempts {
		for _, t := range times {
			if t.After(cutoff) {
				locked = append(locked, ip)
				break
			}
		}
	}
	return locked
}
