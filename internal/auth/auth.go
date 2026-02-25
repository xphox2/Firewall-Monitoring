package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
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

	am.cleanOldAttempts(username)

	if len(am.loginAttempts[username]) >= cfg.Auth.MaxLoginAttempts {
		return ErrAccountLocked
	}

	if am.db != nil {
		adminRaw, err := am.db.GetAdminByUsername()
		if err == nil && adminRaw != nil {
			admin, ok := adminRaw.(*AdminAuth)
			if !ok {
				return ErrInvalidCredentials
			}
			if username != admin.Username {
				return ErrInvalidCredentials
			}
			if !am.CheckPassword(password, admin.Password) {
				am.loginAttempts[username] = append(am.loginAttempts[username], time.Now())
				return ErrInvalidCredentials
			}
			am.loginAttempts[username] = []time.Time{}
			return nil
		}
	}

	if username != cfg.Auth.AdminUsername {
		return ErrInvalidCredentials
	}

	if password != cfg.Auth.AdminPassword {
		am.loginAttempts[username] = append(am.loginAttempts[username], time.Now())
		return ErrInvalidCredentials
	}

	am.loginAttempts[username] = []time.Time{}
	return nil
}

func (am *AuthManager) hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + "fortigate-mon-salt"))
	return hex.EncodeToString(hash[:])
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
	am.cleanOldAttempts(username)
	cfg := am.config
	if cfg == nil {
		cfg = am.getConfig()
	}
	if cfg == nil {
		return false
	}
	return len(am.loginAttempts[username]) >= cfg.Auth.MaxLoginAttempts
}

func (am *AuthManager) GenerateToken(username string, userID uint) (string, error) {
	claims := Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(am.getConfig().Auth.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "fortigate-mon",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(am.getConfig().Server.JWTSecretKey))
}

func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(am.getConfig().Server.JWTSecretKey), nil
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
		am.getConfig().Auth.BcryptCost,
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

	admin := adminRaw.(*AdminAuth)

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
