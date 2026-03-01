package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Server   ServerConfig
	SNMP     SNMPConfig
	Database DatabaseConfig
	Auth     AuthConfig
	Alerts   AlertsConfig
	Uptime   UptimeConfig
}

type ServerConfig struct {
	Host           string
	Port           string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	EnableTLS      bool
	TLSCertFile    string
	TLSKeyFile     string
	AdminSecretKey string
	JWTSecretKey   string
	CookieSecure   bool
	CookieSameSite string
}

type SNMPConfig struct {
	FortiGateHost  string
	FortiGatePort  int
	Community      string
	Version        string
	Timeout        time.Duration
	Retries        int
	PollInterval   time.Duration
	TrapListenAddr string
	TrapCommunity  string
}

type DatabaseConfig struct {
	Type     string
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	FilePath string
}

type AuthConfig struct {
	AdminUsername    string
	AdminPassword    string
	BcryptCost       int
	TokenExpiry      time.Duration
	MaxLoginAttempts int
	LockoutDuration  time.Duration
}

type AlertsConfig struct {
	EmailEnabled       bool
	SMTPHost           string
	SMTPPort           int
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	SMTPTo             string
	SlackWebhookURL    string
	DiscordWebhookURL  string
	WebHookURL         string
	CPUThreshold       float64
	MemoryThreshold    float64
	DiskThreshold      float64
	SessionThreshold   int
	InterfaceDownAlert bool
}

type UptimeConfig struct {
	BaselineFile    string
	TrackingEnabled bool
}

func Load() *Config {
	// Clear the module-level default password after building the config
	defer func() { defaultPassword = "" }()

	return &Config{
		Server: ServerConfig{
			Host:           getEnv("SERVER_HOST", "0.0.0.0"),
			Port:           getEnv("SERVER_PORT", "8080"),
			ReadTimeout:    getDurationEnv("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:   getDurationEnv("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:    getDurationEnv("SERVER_IDLE_TIMEOUT", 120*time.Second),
			EnableTLS:      getBoolEnv("SERVER_ENABLE_TLS", false),
			TLSCertFile:    getEnv("SERVER_TLS_CERT", "/etc/fortigate-mon/tls.crt"),
			TLSKeyFile:     getEnv("SERVER_TLS_KEY", "/etc/fortigate-mon/tls.key"),
			AdminSecretKey: getEnv("ADMIN_SECRET_KEY", ""),
			JWTSecretKey:   getEnv("JWT_SECRET_KEY", ""),
			CookieSecure:   getBoolEnv("COOKIE_SECURE", false),
			CookieSameSite: getEnv("COOKIE_SAMESITE", "Strict"),
		},
		SNMP: SNMPConfig{
			FortiGateHost:  getEnv("FORTIGATE_HOST", "192.168.1.1"),
			FortiGatePort:  getIntEnv("FORTIGATE_SNMP_PORT", 161),
			Community:      getEnv("SNMP_COMMUNITY", ""),
			Version:        getEnv("SNMP_VERSION", "2c"),
			Timeout:        getDurationEnv("SNMP_TIMEOUT", 5*time.Second),
			Retries:        getIntEnv("SNMP_RETRIES", 2),
			PollInterval:   getDurationEnv("SNMP_POLL_INTERVAL", 60*time.Second),
			TrapListenAddr: getEnv("SNMP_TRAP_LISTEN", "0.0.0.0:162"),
			TrapCommunity:  getEnv("SNMP_TRAP_COMMUNITY", "public"),
		},
		Database: DatabaseConfig{
			Type:     getEnv("DB_TYPE", "sqlite"),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getIntEnv("DB_PORT", 5432),
			Name:     getEnv("DB_NAME", "fortigate_mon"),
			User:     getEnv("DB_USER", "fortigate_mon"),
			Password: getEnv("DB_PASSWORD", ""),
			FilePath: getEnv("DB_FILE_PATH", "/data/fortigate.db"),
		},
		Auth: AuthConfig{
			AdminUsername:    getEnv("ADMIN_USERNAME", "admin"),
			AdminPassword:    getEnv("ADMIN_PASSWORD", getDefaultPassword()),
			BcryptCost:       getIntEnv("BCRYPT_COST", 12),
			TokenExpiry:      getDurationEnv("TOKEN_EXPIRY", 24*time.Hour),
			MaxLoginAttempts: getIntEnv("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:  getDurationEnv("LOCKOUT_DURATION", 15*time.Minute),
		},
		Alerts: AlertsConfig{
			EmailEnabled:       getBoolEnv("EMAIL_ENABLED", false),
			SMTPHost:           getEnv("SMTP_HOST", ""),
			SMTPPort:           getIntEnv("SMTP_PORT", 587),
			SMTPUsername:       getEnv("SMTP_USERNAME", ""),
			SMTPPassword:       getEnv("SMTP_PASSWORD", ""),
			SMTPFrom:           getEnv("SMTP_FROM", "fortigate-mon@example.com"),
			SMTPTo:             getEnv("SMTP_TO", "admin@example.com"),
			SlackWebhookURL:    getEnv("SLACK_WEBHOOK_URL", ""),
			DiscordWebhookURL:  getEnv("DISCORD_WEBHOOK_URL", ""),
			WebHookURL:         getEnv("WEBHOOK_URL", ""),
			CPUThreshold:       getFloatEnv("CPU_THRESHOLD", 80.0),
			MemoryThreshold:    getFloatEnv("MEMORY_THRESHOLD", 80.0),
			DiskThreshold:      getFloatEnv("DISK_THRESHOLD", 90.0),
			SessionThreshold:   getIntEnv("SESSION_THRESHOLD", 100000),
			InterfaceDownAlert: getBoolEnv("INTERFACE_DOWN_ALERT", true),
		},
		Uptime: UptimeConfig{
			BaselineFile:    getEnv("UPTIME_BASELINE_FILE", "/var/lib/fortigate-mon/uptime.json"),
			TrackingEnabled: getBoolEnv("UPTIME_TRACKING_ENABLED", true),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

var defaultPassword string

func getDefaultPassword() string {
	if defaultPassword == "" {
		defaultPassword = generateRandomPassword(16)
	}
	return defaultPassword
}

func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fatal: crypto/rand failed: %v\n", err)
			os.Exit(1)
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// IsGeneratedPassword returns true if the admin password was auto-generated (not set via env)
func (c *Config) IsGeneratedPassword() bool {
	_, exists := os.LookupEnv("ADMIN_PASSWORD")
	return !exists
}

func getIntEnv(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getFloatEnv(key string, defaultValue float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func init() {
	if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
		if err := loadEnvFile(configFile); err != nil {
			// Use fmt since log may not be initialized in init()
			fmt.Fprintf(os.Stderr, "Warning: failed to load config file %s: %v\n", configFile, err)
		}
	}
}

func loadEnvFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Strip surrounding quotes (single or double)
			if len(value) >= 2 {
				if (value[0] == '"' && value[len(value)-1] == '"') ||
					(value[0] == '\'' && value[len(value)-1] == '\'') {
					value = value[1 : len(value)-1]
				}
			}
			if key != "" && os.Getenv(key) == "" {
				os.Setenv(key, value)
			}
		}
	}
	return nil
}
