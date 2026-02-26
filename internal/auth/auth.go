package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"fortiGate-Mon/internal/config"

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

type Database interface {
	GetAdminByUsername() (interface{}, error)
	UpdateAdminPassword(id uint, password string) error
}

type AdminAuth struct {
	ID       uint
	Username string
	Password string
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
	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()

	if am.config == nil {
		return ErrInvalidCredentials
	}

	// Clean old attempts
	cutoff := time.Now().Add(-am.config.Auth.LockoutDuration)
	valid := []time.Time{}
	for _, t := range am.loginAttempts[username] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	am.loginAttempts[username] = valid

	// Check lockout
	if len(am.loginAttempts[username]) >= am.config.Auth.MaxLoginAttempts {
		return ErrAccountLocked
	}

	// Simple auth: admin/admin or from config
	if (username == "admin" && password == "admin") ||
		(username == am.config.Auth.AdminUsername && password == am.config.Auth.AdminPassword) {
		am.loginAttempts[username] = []time.Time{}
		return nil
	}

	// Record failed attempt
	am.loginAttempts[username] = append(am.loginAttempts[username], time.Now())
	return ErrInvalidCredentials
}

func (am *AuthManager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (am *AuthManager) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (am *AuthManager) GenerateToken(username string, userID uint) (string, error) {
	if am.config == nil {
		return "", errors.New("configuration not available")
	}
	claims := Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(am.config.Auth.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "firewall-mon",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(am.config.Server.JWTSecretKey))
}

func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	if am.config == nil {
		return nil, ErrInvalidToken
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(am.config.Server.JWTSecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

func (am *AuthManager) UpdatePassword(username, newPassword string) error {
	if am.db == nil {
		return errors.New("database not configured")
	}

	adminRaw, err := am.db.GetAdminByUsername()
	if err != nil {
		return err
	}
	if adminRaw == nil {
		return errors.New("admin not found")
	}

	admin, ok := adminRaw.(*AdminAuth)
	if !ok {
		return errors.New("invalid admin data type")
	}

	hashedPassword, err := am.HashPassword(newPassword)
	if err != nil {
		return err
	}

	return am.db.UpdateAdminPassword(admin.ID, hashedPassword)
}
