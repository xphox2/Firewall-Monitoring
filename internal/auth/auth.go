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

	log.Printf("[DEBUG] ValidateCredentials: user=%s", username)
	log.Printf("[DEBUG] am.db=%v, am.config=%v", am.db != nil, am.config != nil)

	am.attemptsMu.Lock()
	defer am.attemptsMu.Unlock()

	// Check lockout
	maxAttempts := 5
	if am.config != nil {
		maxAttempts = am.config.Auth.MaxLoginAttempts
	}

	attempts := am.loginAttempts[username]
	if attempts == nil {
		attempts = []time.Time{}
	}

	if len(attempts) >= maxAttempts {
		log.Printf("[DEBUG] Account locked for %s", username)
		return ErrAccountLocked
	}

	// Try database first
	if am.db != nil {
		log.Printf("[DEBUG] Checking database for admin")
		adminRaw, err := am.db.GetAdminByUsername()
		if err != nil {
			log.Printf("[DEBUG] GetAdminByUsername error: %v", err)
		} else if adminRaw != nil {
			log.Printf("[DEBUG] Got admin from DB: %+v", adminRaw)
			// Handle both auth.AdminAuth and database.AdminAuth types
			switch admin := adminRaw.(type) {
			case *database.AdminAuth:
				if admin.Username == username && admin.Password != "" {
					if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) == nil {
						am.loginAttempts[username] = nil
						return nil
					}
				}
			case *AdminAuth:
				if admin.Username == username && admin.Password != "" {
					if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) == nil {
						am.loginAttempts[username] = nil
						return nil
					}
				}
			default:
				log.Printf("[DEBUG] Unknown admin type: %T", adminRaw)
			}
		}
	}

	// Fallback: config credentials
	if am.config != nil && am.config.Auth.AdminUsername != "" && am.config.Auth.AdminPassword != "" {
		if username == am.config.Auth.AdminUsername && password == am.config.Auth.AdminPassword {
			am.loginAttempts[username] = nil
			return nil
		}
	}

	// Record failed attempt
	if attempts == nil {
		attempts = []time.Time{}
	}
	am.loginAttempts[username] = append(attempts, time.Now())
	return ErrInvalidCredentials
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

	admin, ok := adminRaw.(*AdminAuth)
	if !ok {
		return errors.New("invalid admin data")
	}

	hashedPassword, err := am.HashPassword(newPassword)
	if err != nil {
		return err
	}

	return am.db.UpdateAdminPassword(admin.ID, hashedPassword)
}
