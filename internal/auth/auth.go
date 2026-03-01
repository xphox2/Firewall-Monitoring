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
	Username string `json:"username"`
	UserID   uint   `json:"user_id"`
	jwt.RegisteredClaims
}

type AdminAuth struct {
	ID       uint
	Username string
	Password string
}

type Database interface {
	GetAdminByUsername(username string) (*AdminAuth, error)
	UpdateAdminPassword(id uint, password string) error
}

type AuthManager struct {
	db            Database
	config        *config.Config
	loginAttempts map[string][]time.Time
	attemptsMu    sync.RWMutex
}

func NewAuthManager(cfg *config.Config, db Database) *AuthManager {
	return &AuthManager{
		db:            db,
		config:        cfg,
		loginAttempts: make(map[string][]time.Time),
	}
}

func (am *AuthManager) ValidateCredentials(username, password string) error {
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

	// Filter out attempts older than lockout duration
	cutoff := time.Now().Add(-lockoutDuration)
	attempts := am.loginAttempts[username]
	recentAttempts := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if t.After(cutoff) {
			recentAttempts = append(recentAttempts, t)
		}
	}
	if len(recentAttempts) == 0 {
		delete(am.loginAttempts, username)
	} else {
		am.loginAttempts[username] = recentAttempts
	}

	if len(recentAttempts) >= maxAttempts {
		return ErrAccountLocked
	}

	if am.db == nil {
		am.loginAttempts[username] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	admin, err := am.db.GetAdminByUsername(username)
	if err != nil || admin == nil {
		am.loginAttempts[username] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	if admin.Password == "" {
		am.loginAttempts[username] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) != nil {
		am.loginAttempts[username] = append(recentAttempts, time.Now())
		return ErrInvalidCredentials
	}

	// Successful login clears attempts
	delete(am.loginAttempts, username)
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

func (am *AuthManager) GenerateToken(username string, userID uint) (string, error) {
	if am.config == nil || am.config.Server.JWTSecretKey == "" {
		return "", ErrNoJWTSecret
	}

	secretKey := am.config.Server.JWTSecretKey

	tokenExpiry := 24 * time.Hour
	if am.config.Auth.TokenExpiry > 0 {
		tokenExpiry = am.config.Auth.TokenExpiry
	}

	claims := Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
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
