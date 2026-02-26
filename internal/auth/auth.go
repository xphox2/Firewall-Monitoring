package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
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
	configPath    string
	loginAttempts map[string][]time.Time
	attemptsMu    sync.RWMutex
}

func NewAuthManager(cfg *config.Config, db Database) *AuthManager {
	return &AuthManager{
		db:            db,
		config:        cfg,
		configPath:    os.Getenv("CONFIG_FILE"),
		loginAttempts: make(map[string][]time.Time),
	}
}

func (am *AuthManager) getConfig() *config.Config {
	// Use cached config if available
	if am.config != nil {
		// Reload password from config file if it exists
		if am.configPath != "" {
			if data, err := os.ReadFile(am.configPath); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "ADMIN_PASSWORD=") {
						parts := strings.SplitN(line, "=", 2)
						if len(parts) == 2 {
							am.config.Auth.AdminPassword = strings.TrimSpace(parts[1])
						}
					}
					if strings.HasPrefix(line, "ADMIN_USERNAME=") {
						parts := strings.SplitN(line, "=", 2)
						if len(parts) == 2 {
							am.config.Auth.AdminUsername = strings.TrimSpace(parts[1])
						}
					}
				}
			}
		}
		return am.config
	}

	// Fallback: load new config
	cfg := config.Load()

	// Reload password from config file if it exists
	if am.configPath != "" {
		if data, err := os.ReadFile(am.configPath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ADMIN_PASSWORD=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						cfg.Auth.AdminPassword = strings.TrimSpace(parts[1])
					}
				}
				if strings.HasPrefix(line, "ADMIN_USERNAME=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						cfg.Auth.AdminUsername = strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}

	return cfg
}

func (am *AuthManager) ValidateCredentials(username, password string) error {
	cfg := am.config
	if cfg == nil {
		cfg = am.getConfig()
	}

	if cfg == nil {
		return ErrInvalidCredentials
	}

	am.attemptsMu.Lock()
	am.cleanOldAttempts(username)

	if len(am.loginAttempts[username]) >= cfg.Auth.MaxLoginAttempts {
		am.attemptsMu.Unlock()
		return ErrAccountLocked
	}

	if am.db != nil {
		adminRaw, err := am.db.GetAdminByUsername()
		if err == nil && adminRaw != nil {
			admin, ok := adminRaw.(*AdminAuth)
			if !ok {
				am.attemptsMu.Unlock()
				return ErrInvalidCredentials
			}
			if strings.ToLower(username) != strings.ToLower(admin.Username) {
				am.attemptsMu.Unlock()
				return ErrInvalidCredentials
			}
			if !am.CheckPassword(password, admin.Password) {
				am.loginAttempts[username] = append(am.loginAttempts[username], time.Now())
				am.attemptsMu.Unlock()
				return ErrInvalidCredentials
			}
			am.loginAttempts[username] = []time.Time{}
			am.attemptsMu.Unlock()
			return nil
		}
	}

	if username != cfg.Auth.AdminUsername {
		am.attemptsMu.Unlock()
		return ErrInvalidCredentials
	}

	if password != cfg.Auth.AdminPassword {
		am.loginAttempts[username] = append(am.loginAttempts[username], time.Now())
		am.attemptsMu.Unlock()
		return ErrInvalidCredentials
	}

	am.loginAttempts[username] = []time.Time{}
	am.attemptsMu.Unlock()
	return nil
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

func (am *AuthManager) cleanOldAttempts(username string) []time.Time {
	cfg := am.config
	if cfg == nil {
		cfg = am.getConfig()
	}
	if cfg == nil {
		return nil
	}
	cutoff := time.Now().Add(-cfg.Auth.LockoutDuration)
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
	am.attemptsMu.RLock()
	defer am.attemptsMu.RUnlock()

	cfg := am.config
	if cfg == nil {
		return false
	}

	cutoff := time.Now().Add(-cfg.Auth.LockoutDuration)
	var valid []time.Time
	for _, t := range am.loginAttempts[username] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	return len(valid) >= cfg.Auth.MaxLoginAttempts
}

func (am *AuthManager) GenerateToken(username string, userID uint) (string, error) {
	cfg := am.getConfig()
	if cfg == nil {
		return "", errors.New("configuration not available")
	}
	claims := Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.Auth.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "fortigate-mon",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Server.JWTSecretKey))
}

func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	cfg := am.getConfig()
	if cfg == nil {
		return nil, ErrInvalidToken
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.Server.JWTSecretKey), nil
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
		log.Printf("ERROR: Admin data has unexpected type: %T", adminRaw)
		return ErrInvalidCredentials
	}

	hashedPassword, err := am.HashPassword(newPassword)
	if err != nil {
		return err
	}

	return am.db.UpdateAdminPassword(admin.ID, hashedPassword)
}

func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
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
