package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"sync"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/database"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrAccountLocked      = errors.New("account is locked")
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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] ValidateCredentials: %v", r)
		}
	}()

	if am == nil {
		log.Printf("[DEBUG] AuthManager is nil")
		return ErrInvalidCredentials
	}

	log.Printf("[DEBUG] ValidateCredentials: user=%s", username)

	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()

	maxAttempts := 5
	if am.config != nil {
		maxAttempts = am.config.Auth.MaxLoginAttempts
	}

	attempts := am.loginAttempts[username]
	if len(attempts) >= maxAttempts {
		return ErrAccountLocked
	}

	if am.db == nil {
		log.Printf("[DEBUG] No database configured")
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	adminRaw, err := am.db.GetAdminByUsername()
	if err != nil {
		log.Printf("[DEBUG] GetAdminByUsername error: %v", err)
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	if adminRaw == nil {
		log.Printf("[DEBUG] No admin found in database")
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	admin, ok := adminRaw.(*database.AdminAuth)
	if !ok {
		log.Printf("[DEBUG] Invalid admin type: %T", adminRaw)
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	if admin.Username != username {
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	if admin.Password == "" {
		log.Printf("[DEBUG] Admin password is empty")
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) != nil {
		log.Printf("[DEBUG] Password mismatch")
		am.loginAttempts[username] = append(attempts, time.Now())
		return ErrInvalidCredentials
	}

	am.loginAttempts[username] = nil
	log.Printf("[DEBUG] Login successful for user=%s", username)
	return nil
}

func (am *AuthManager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (am *AuthManager) CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (am *AuthManager) GenerateToken(username string, userID uint) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] GenerateToken: %v", r)
		}
	}()

	log.Printf("[DEBUG] GenerateToken: user=%s, userID=%d", username, userID)

	secretKey := "dev-secret-key"
	if am.config != nil && am.config.Server.JWTSecretKey != "" {
		secretKey = am.config.Server.JWTSecretKey
	}

	log.Printf("[DEBUG] Using secretKey: %s", secretKey)

	claims := Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	secretKey := "dev-secret-key"
	if am.config != nil && am.config.Server.JWTSecretKey != "" {
		secretKey = am.config.Server.JWTSecretKey
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		log.Printf("Token parse error: %v", err)
		return nil, ErrInvalidToken
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

	admin, ok := adminRaw.(*database.AdminAuth)
	if !ok {
		return errors.New("invalid admin data")
	}

	hashedPassword, err := am.HashPassword(newPassword)
	if err != nil {
		return err
	}

	return am.db.UpdateAdminPassword(admin.ID, hashedPassword)
}
