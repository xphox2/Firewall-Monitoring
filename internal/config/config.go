package config

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type Config struct {
	Server    ServerConfig
	SNMP      SNMPConfig
	Database  DatabaseConfig
	Auth      AuthConfig
	Alerts    AlertsConfig
	Uptime    UptimeConfig
	Probe     ProbeConfig
	Retention RetentionConfig
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
	JWTSecretKey   string
	EncryptionKey  string
	CookieSecure   bool
	CookieSameSite string
	// CookieSecureExplicit tracks whether the operator explicitly set
	// COOKIE_SECURE=true in config.env, as opposed to inheriting the
	// default from SERVER_ENABLE_TLS. AUDIT-024: when CookieSecure is
	// true but EnableTLS is false, browsers silently drop the session
	// cookie on every response and the operator gets a "login button
	// does nothing" report. The startup warning in Validate() keys off
	// this flag to fire only when the mismatch is the operator's own
	// doing, not the safe default.
	CookieSecureExplicit bool
	// AllowMultiAPI opts out of the AUDIT-040 singleton guard. Default false:
	// a second cmd/api refuses to start (the IRC bots / login-lockout /
	// rate-limit / uptime state is in-process and would double-run). true =>
	// follower mode (serve HTTP, no IRC bots; lockout/rate-limit/uptime are
	// per-instance and diverge).
	AllowMultiAPI bool
	// APISingletonLockWait is how long a starting API retries the singleton
	// advisory lock before giving up, so a graceful predecessor mid-shutdown
	// doesn't trigger a false refuse (AUDIT-040).
	APISingletonLockWait time.Duration
}

type SNMPConfig struct {
	SNMPHost       string
	SNMPPort       int
	Community      string
	Version        string
	Timeout        time.Duration
	Retries        int
	PollInterval   time.Duration
	TrapListenAddr string
	TrapCommunity  string
	// SNMPv3 fields
	V3Username string
	V3AuthType string // "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512", ""
	V3AuthPass string
	V3PrivType string // "DES", "AES", "AES192", "AES256", ""
	V3PrivPass string
}

type DatabaseConfig struct {
	Type     string
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
	// AUDIT-037: per-connection statement timeout (Postgres
	// only). Pre-fix a single slow query could hold a
	// connection for tens of seconds, blocking other
	// handlers from getting one. The Postgres-side
	// `statement_timeout` (set via the connection string's
	// `options=-c statement_timeout=...`) is the right place
	// to enforce this — it's enforced by the server, not the
	// client, so it survives slow application code that
	// forgets to set a `context.WithTimeout`. Default 30s,
	// configurable via DB_STATEMENT_TIMEOUT. Set to 0 to
	// disable (not recommended for production).
	StatementTimeout time.Duration

	// AUDIT-036: max open connections for THIS process's pool. The container
	// runs three daemons (api/poller/trap-receiver), each with its own pool,
	// so a single hardcoded 25 meant a 75-conn/host ceiling that saturates a
	// busy Postgres. 0 means "use the caller's per-process default" (set in
	// each daemon's main: 15 api / 10 poller / 5 trap-receiver); the
	// DB_MAX_OPEN_CONNS env var overrides for all processes.
	MaxOpenConns int
}

type RetentionConfig struct {
	DefaultDays        int
	SyslogDays         int
	SyslogInfoDays     int // days to keep raw informational syslog (severity 6-7) before aggregation (default 7)
	SyslogCriticalDays int // days to keep raw critical syslog (severity 0-5), 0=forever (default 0)
	FlowDays           int
	TrapDays           int
	StatusDays         int
	PingDays           int
	AlertDays          int
	// AUDIT-029: the four tables that previously had no retention
	// knob and grew unbounded. Defaults below match the audit's
	// recommendation: 30 days for errors / processor / process
	// stats, 7 days for IRC message logs. The IRC logs are higher-
	// volume (one row per chat line) and lower-signal than the
	// alerting tables, so they get the shorter retention.
	InterfaceErrorsDays int // interface_errors (default 30)
	ProcessorStatsDays  int // processor_stats  (default 30)
	ProcessStatsDays    int // process_stats    (default 30)
	IRCMessageLogDays   int // irc_message_logs (default 7)
	// AUDIT-031: unacknowledged alerts have a separate, longer
	// retention than acked alerts. Pre-fix the cleanup query
	// had `WHERE acknowledged = true AND timestamp < ?`, which
	// meant a critical device that pages off-hours and goes
	// unacked accumulated alert rows forever. 90 days gives an
	// operator plenty of time to ack, after which the row is
	// auto-archived with a warning log so the operator can
	// reconstruct the "stale unack" event from the logs.
	UnackAlertDays int // unack alerts (default 90)
}

type AuthConfig struct {
	AdminUsername    string
	AdminPassword    string
	BcryptCost       int
	TokenExpiry      time.Duration
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	// AdminUsernameExplicit tracks whether the operator explicitly
	// set ADMIN_USERNAME in config.env, as opposed to inheriting the
	// default. AUDIT-105: when AdminUsername is the well-known
	// "admin" default (case-insensitive), the operator gets a
	// startup warning pointing at the brute-force surface. The
	// warning only fires when the value was inherited from the
	// default AND that default is the dangerous one — an operator
	// who explicitly set ADMIN_USERNAME=admin and KNOWS they're
	// doing it doesn't get nagged. (They might still want to
	// change it, but they made a conscious choice.)
	AdminUsernameExplicit bool
	// AdminPasswordGenerated tracks whether the admin password was
	// auto-generated (i.e. ADMIN_PASSWORD was not set in the
	// environment). AUDIT-136: pre-fix, callers did
	// `os.LookupEnv("ADMIN_PASSWORD")` at every decision point,
	// which is fragile (the env could change between calls) and
	// duplicated work. The flag is captured once at config-load
	// time and read by every consumer.
	AdminPasswordGenerated bool
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
	// Probe data flow monitoring
	ProbeDataLagAlertMinutes int // Alert when probe sends no data for this many minutes (0 = disabled)
	// Report settings
	ReportDailyEnabled  bool
	ReportDailyTime     string // HH:MM format
	ReportWeeklyEnabled bool
	ReportWeeklyDay     string // monday, tuesday, etc.
	ReportRecipients    string // comma-separated, defaults to SMTPTo
	ReportTimezone      string // IANA timezone, default UTC
	// Spike detection
	SpikeStdDevThreshold float64
	SpikeAlertEnabled    bool
}

type UptimeConfig struct {
	BaselineFile    string
	TrackingEnabled bool
}

type ProbeConfig struct {
	EnableProbeServer    bool
	ListenAddress        string
	ListenPort           int
	ServerURL            string
	EnableTLS            bool
	TLSCertFile          string
	TLSKeyFile           string
	ClientTLSCertFile    string
	ClientTLSKeyFile     string
	EnableMTLS           bool
	ICMPEnabled          bool
	ICMPInterval         time.Duration
	SyslogEnabled        bool
	SyslogPort           int
	SyslogUseTLS         bool
	SyslogAllowedSources string // Comma-separated list of allowed source IPs
	SFlowEnabled         bool
	SFlowPort            int
	SFlowAllowedSources  string // Comma-separated list of allowed source IPs
}

func Load() *Config {
	// AUDIT-158: the pre-fix code had a `defer func() { defaultPassword = "" }()`
	// here to scrub the module-level cache after Load returned. That was
	// defense-in-depth against the module-level cache (which we've now
	// removed — see getDefaultPassword), but it also implied the
	// zeroing was sufficient, which it wasn't: the string's underlying
	// bytes had already been copied into `cfg.Auth.AdminPassword` and
	// the bcrypt hash, and those copies are what the post-Load
	// lifecycle sees. The new code (no module-level cache) means
	// the only copy of the password in memory is the one we hand
	// to the caller; the caller is now responsible for zeroing it
	// after use (handled in `cmd/api/main.go`).
	return &Config{
		Server: ServerConfig{
			Host:                 getEnv("SERVER_HOST", "0.0.0.0"),
			Port:                 getEnv("SERVER_PORT", "8080"),
			ReadTimeout:          getDurationEnv("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:         getDurationEnv("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:          getDurationEnv("SERVER_IDLE_TIMEOUT", 120*time.Second),
			EnableTLS:            getBoolEnv("SERVER_ENABLE_TLS", false),
			TLSCertFile:          getEnv("SERVER_TLS_CERT", "/etc/firewall-mon/tls.crt"),
			TLSKeyFile:           getEnv("SERVER_TLS_KEY", "/etc/firewall-mon/tls.key"),
			JWTSecretKey:         getEnv("JWT_SECRET_KEY", ""),
			EncryptionKey:        getEnv("ENCRYPTION_KEY", ""),
			CookieSecure:         getBoolEnv("COOKIE_SECURE", getBoolEnv("SERVER_ENABLE_TLS", false)),
			CookieSecureExplicit: os.Getenv("COOKIE_SECURE") != "",
			CookieSameSite:       getEnv("COOKIE_SAMESITE", "Strict"),
			AllowMultiAPI:        getBoolEnv("ALLOW_MULTI_API", false),
			APISingletonLockWait: getDurationEnv("API_SINGLETON_LOCK_WAIT", 10*time.Second),
		},
		SNMP: SNMPConfig{
			SNMPHost:       getEnv("SNMP_HOST", "192.168.1.1"),
			SNMPPort:       getIntEnv("SNMP_PORT", 161),
			Community:      getEnv("SNMP_COMMUNITY", ""),
			Version:        getEnv("SNMP_VERSION", "2c"),
			Timeout:        getDurationEnv("SNMP_TIMEOUT", 5*time.Second),
			Retries:        getIntEnv("SNMP_RETRIES", 2),
			PollInterval:   getDurationEnv("SNMP_POLL_INTERVAL", 60*time.Second),
			TrapListenAddr: getEnv("SNMP_TRAP_LISTEN", "0.0.0.0:162"),
			TrapCommunity:  getEnv("SNMP_TRAP_COMMUNITY", ""),
			V3Username:     getEnv("SNMP_V3_USERNAME", ""),
			V3AuthType:     getEnv("SNMP_V3_AUTH_TYPE", ""),
			V3AuthPass:     getEnv("SNMP_V3_AUTH_PASS", ""),
			V3PrivType:     getEnv("SNMP_V3_PRIV_TYPE", ""),
			V3PrivPass:     getEnv("SNMP_V3_PRIV_PASS", ""),
		},
		Database: DatabaseConfig{
			Type:     getEnv("DB_TYPE", "postgres"),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getIntEnv("DB_PORT", 5432),
			Name:     getEnv("DB_NAME", "firewall_mon"),
			User:     getEnv("DB_USER", "firewall_mon"),
			Password: getEnv("DB_PASSWORD", ""),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
			// AUDIT-037: per-connection statement timeout
			// (Postgres only). 0 = disabled. See the field
			// doc for the rationale.
			StatementTimeout: getDurationEnv("DB_STATEMENT_TIMEOUT", 30*time.Second),
			// AUDIT-036: 0 => the daemon's main picks a per-process default.
			MaxOpenConns: getIntEnv("DB_MAX_OPEN_CONNS", 0),
		},
		Retention: RetentionConfig{
			DefaultDays:        getIntEnv("RETENTION_DEFAULT_DAYS", 90),
			SyslogDays:         getIntEnv("RETENTION_SYSLOG_DAYS", 0),
			SyslogInfoDays:     getIntEnv("RETENTION_SYSLOG_INFO_DAYS", 7),
			SyslogCriticalDays: getIntEnv("RETENTION_SYSLOG_CRITICAL_DAYS", 0),
			FlowDays:           getIntEnv("RETENTION_FLOW_DAYS", 365),
			TrapDays:           getIntEnv("RETENTION_TRAP_DAYS", 0),
			StatusDays:         getIntEnv("RETENTION_STATUS_DAYS", 0),
			PingDays:           getIntEnv("RETENTION_PING_DAYS", 0),
			AlertDays:          getIntEnv("RETENTION_ALERT_DAYS", 0),
			// AUDIT-029: the four tables that previously had no
			// retention knob. Defaults match the audit's
			// recommendation: 30 days for error / processor /
			// process stats, 7 days for IRC message logs. The
			// IRC logs are higher-volume and lower-signal than
			// the alerting tables.
			InterfaceErrorsDays: getIntEnv("RETENTION_INTERFACE_ERRORS_DAYS", 30),
			ProcessorStatsDays:  getIntEnv("RETENTION_PROCESSOR_STATS_DAYS", 30),
			ProcessStatsDays:    getIntEnv("RETENTION_PROCESS_STATS_DAYS", 30),
			IRCMessageLogDays:   getIntEnv("RETENTION_IRC_MESSAGE_LOG_DAYS", 7),
			// AUDIT-031: see the field doc above. 0 = use
			// DefaultDays (90) via ret.Days(); we set the
			// explicit default here so a `RETENTION_DEFAULT_DAYS=30`
			// operator doesn't accidentally shorten unack
			// alert retention to 30 days.
			UnackAlertDays: getIntEnv("RETENTION_UNACK_ALERT_DAYS", 90),
		},
		Auth: AuthConfig{
			AdminUsername:         getEnv("ADMIN_USERNAME", "admin"),
			AdminUsernameExplicit: os.Getenv("ADMIN_USERNAME") != "",
			AdminPassword:         getEnv("ADMIN_PASSWORD", getDefaultPassword()),
			// AUDIT-136: capture "was ADMIN_PASSWORD set in the env"
			// once at config-load time, so every consumer
			// (`IsGeneratedPassword`, the secrets-persistence
			// flow in `cmd/api/main.go`, the startup-warning
			// logic) reads the same authoritative value rather
			// than re-querying the env and risking TOCTOU. We
			// use `LookupEnv` (not `Getenv == ""`) because an
			// operator who explicitly sets ADMIN_PASSWORD=""
			// has made a deliberate choice — "I want an
			// empty admin password" — and that should NOT
			// trigger the auto-generated-password flow. The
			// distinction is the whole point of the fix.
			AdminPasswordGenerated: func() bool { _, ok := os.LookupEnv("ADMIN_PASSWORD"); return !ok }(),
			BcryptCost:             getIntEnv("BCRYPT_COST", 12),
			TokenExpiry:            getDurationEnv("TOKEN_EXPIRY", 24*time.Hour),
			MaxLoginAttempts:       getIntEnv("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:        getDurationEnv("LOCKOUT_DURATION", 15*time.Minute),
		},
		Alerts: AlertsConfig{
			EmailEnabled:             getBoolEnv("EMAIL_ENABLED", false),
			SMTPHost:                 getEnv("SMTP_HOST", ""),
			SMTPPort:                 getIntEnv("SMTP_PORT", 587),
			SMTPUsername:             getEnv("SMTP_USERNAME", ""),
			SMTPPassword:             getEnv("SMTP_PASSWORD", ""),
			SMTPFrom:                 getEnv("SMTP_FROM", "firewall-mon@example.com"),
			SMTPTo:                   getEnv("SMTP_TO", "admin@example.com"),
			SlackWebhookURL:          getEnv("SLACK_WEBHOOK_URL", ""),
			DiscordWebhookURL:        getEnv("DISCORD_WEBHOOK_URL", ""),
			WebHookURL:               getEnv("WEBHOOK_URL", ""),
			CPUThreshold:             getFloatEnv("CPU_THRESHOLD", 80.0),
			MemoryThreshold:          getFloatEnv("MEMORY_THRESHOLD", 80.0),
			DiskThreshold:            getFloatEnv("DISK_THRESHOLD", 90.0),
			SessionThreshold:         getIntEnv("SESSION_THRESHOLD", 100000),
			InterfaceDownAlert:       getBoolEnv("INTERFACE_DOWN_ALERT", true),
			ReportDailyEnabled:       getBoolEnv("REPORT_DAILY_ENABLED", false),
			ReportDailyTime:          getEnv("REPORT_DAILY_TIME", "07:00"),
			ReportWeeklyEnabled:      getBoolEnv("REPORT_WEEKLY_ENABLED", false),
			ReportWeeklyDay:          getEnv("REPORT_WEEKLY_DAY", "monday"),
			ReportRecipients:         getEnv("REPORT_RECIPIENTS", ""),
			ReportTimezone:           getEnv("REPORT_TIMEZONE", "UTC"),
			SpikeStdDevThreshold:     getFloatEnv("SPIKE_STDDEV_THRESHOLD", 3.0),
			SpikeAlertEnabled:        getBoolEnv("SPIKE_ALERT_ENABLED", false),
			ProbeDataLagAlertMinutes: getIntEnv("PROBE_DATA_LAG_ALERT_MINUTES", 60),
		},
		Uptime: UptimeConfig{
			BaselineFile:    getEnv("UPTIME_BASELINE_FILE", "/var/lib/firewall-mon/uptime.json"),
			TrackingEnabled: getBoolEnv("UPTIME_TRACKING_ENABLED", true),
		},
		Probe: ProbeConfig{
			EnableProbeServer:    getBoolEnv("PROBE_SERVER_ENABLED", false),
			ListenAddress:        getEnv("PROBE_LISTEN_ADDRESS", "0.0.0.0"),
			ListenPort:           getIntEnv("PROBE_LISTEN_PORT", 8089),
			ServerURL:            getEnv("PROBE_SERVER_URL", ""),
			EnableTLS:            getBoolEnv("PROBE_TLS_ENABLED", false),
			TLSCertFile:          getEnv("PROBE_TLS_CERT", "/etc/firewall-mon/probe.crt"),
			TLSKeyFile:           getEnv("PROBE_TLS_KEY", "/etc/firewall-mon/probe.key"),
			ClientTLSCertFile:    getEnv("PROBE_CLIENT_TLS_CERT", "/etc/firewall-mon/client.crt"),
			ClientTLSKeyFile:     getEnv("PROBE_CLIENT_TLS_KEY", "/etc/firewall-mon/client.key"),
			EnableMTLS:           getBoolEnv("PROBE_MTLS_ENABLED", false),
			ICMPEnabled:          getBoolEnv("PROBE_ICMP_ENABLED", true),
			ICMPInterval:         getDurationEnv("PROBE_ICMP_INTERVAL", 30*time.Second),
			SyslogEnabled:        getBoolEnv("PROBE_SYSLOG_ENABLED", true),
			SyslogPort:           getIntEnv("PROBE_SYSLOG_PORT", 514),
			SyslogUseTLS:         getBoolEnv("PROBE_SYSLOG_TLS", false),
			SyslogAllowedSources: getEnv("SYSLOG_ALLOWED_SOURCES", ""),
			SFlowEnabled:         getBoolEnv("PROBE_SFLOW_ENABLED", true),
			SFlowPort:            getIntEnv("PROBE_SFLOW_PORT", 6343),
			SFlowAllowedSources:  getEnv("SFLOW_ALLOWED_SOURCES", ""),
		},
	}
}

// Validate checks configuration for common mistakes and logs warnings.
// Returns an error only for fatal misconfigurations.
func (c *Config) Validate() error {
	// Port range checks
	if port, err := strconv.Atoi(c.Server.Port); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("SERVER_PORT must be 1-65535, got %q", c.Server.Port)
	}
	if c.SNMP.SNMPPort < 1 || c.SNMP.SNMPPort > 65535 {
		return fmt.Errorf("SNMP_PORT must be 1-65535, got %d", c.SNMP.SNMPPort)
	}

	// SNMP version
	switch c.SNMP.Version {
	case "1", "2c", "3":
		// valid
	default:
		return fmt.Errorf("SNMP_VERSION must be '1', '2c', or '3', got %q", c.SNMP.Version)
	}

	// SNMPv3 credential consistency
	if c.SNMP.Version == "3" {
		if c.SNMP.V3Username == "" {
			log.Println("WARNING: SNMP_VERSION=3 but SNMP_V3_USERNAME not set")
		}
		if c.SNMP.V3AuthType != "" && c.SNMP.V3AuthPass == "" {
			log.Println("WARNING: SNMP_V3_AUTH_TYPE set but SNMP_V3_AUTH_PASS is empty")
		}
		if c.SNMP.V3PrivType != "" && c.SNMP.V3PrivPass == "" {
			log.Println("WARNING: SNMP_V3_PRIV_TYPE set but SNMP_V3_PRIV_PASS is empty")
		}
	}

	// TLS cert files
	if c.Server.EnableTLS {
		if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
			return fmt.Errorf("SERVER_ENABLE_TLS=true but TLS cert/key files not configured")
		}
	}

	// AUDIT-024: COOKIE_SECURE=true over a non-TLS connection is a
	// silent-login-break — the browser drops the Secure cookie on every
	// response, the operator sees "click login, nothing happens", and
	// the only fix is to either flip COOKIE_SECURE=false or put a TLS
	// terminator in front. We warn loudly (and refuse to fail — some
	// operators run a reverse proxy in front and only need this app
	// to be plain HTTP) but make the message explicit. The warning
	// only fires when the operator EXPLICITLY set COOKIE_SECURE in
	// config.env, not when it was inherited from the SERVER_ENABLE_TLS
	// default (which would be a self-consistent config).
	if c.Server.CookieSecure && !c.Server.EnableTLS && c.Server.CookieSecureExplicit {
		log.Println("WARNING: COOKIE_SECURE=true is set explicitly, but SERVER_ENABLE_TLS=false.")
		log.Println("         Browsers will silently drop the session cookie over plain HTTP, so")
		log.Println("         login will appear to do nothing. Either set COOKIE_SECURE=false")
		log.Println("         (recommended for plain-HTTP deployments), or enable TLS by setting")
		log.Println("         SERVER_ENABLE_TLS=true and configuring SERVER_TLS_CERT / SERVER_TLS_KEY.")
	}

	// Secrets warnings
	if c.Server.JWTSecretKey == "" {
		log.Println("WARNING: JWT_SECRET_KEY not set — a random key will be generated (tokens invalidated on restart)")
	}
	if c.Server.EncryptionKey == "" && c.Server.JWTSecretKey == "" {
		log.Println("WARNING: Neither ENCRYPTION_KEY nor JWT_SECRET_KEY set — database credentials will not be encrypted")
	}

	// Alert email config consistency
	if c.Alerts.EmailEnabled && c.Alerts.SMTPHost == "" {
		log.Println("WARNING: EMAIL_ENABLED=true but SMTP_HOST not set — email alerts will fail")
	}

	// Bcrypt cost bounds
	if c.Auth.BcryptCost < 4 || c.Auth.BcryptCost > 31 {
		return fmt.Errorf("BCRYPT_COST must be 4-31, got %d", c.Auth.BcryptCost)
	}

	// AUDIT-105: default ADMIN_USERNAME=admin is the textbook brute-
	// force target. The pre-fix behavior was to silently ship the
	// default. We warn loudly when the operator kept the default
	// (i.e. didn't set ADMIN_USERNAME at all) and that default is
	// exactly the well-known "admin" string. An operator who
	// explicitly set ADMIN_USERNAME=admin and KNOWS they're doing
	// it is not nagged (but they should still reconsider).
	//
	// The warning is intentionally not fatal — some operators run
	// Firewall Mon behind a SSO portal / VPN that has its own
	// brute-force protection, in which case the in-app username
	// is unguessable to anyone who can reach the login page. But
	// the default-exposed case is a real and common misconfig
	// (it's the OWASP #1 for 20 years running) and the operator
	// should be told.
	if !c.Auth.AdminUsernameExplicit && strings.EqualFold(c.Auth.AdminUsername, "admin") {
		log.Println("WARNING: ADMIN_USERNAME is the default 'admin'. This is the most")
		log.Println("         brute-forced username on the internet; consider setting")
		log.Println("         ADMIN_USERNAME to a unique value in config.env. Example:")
		log.Println("             ADMIN_USERNAME=ops-jane")
		log.Println("         (or any non-default value you can remember). The warning")
		log.Println("         only fires when ADMIN_USERNAME is unset; explicitly setting")
		log.Println("         it to 'admin' is treated as a conscious operator choice.")
	}

	// PostgreSQL requires DB_HOST
	if c.Database.Type == "postgres" && c.Database.Host == "" {
		return fmt.Errorf("DB_HOST is required when DB_TYPE=postgres")
	}

	return nil
}

// V3MsgFlags returns the SNMPv3 message flags based on configured auth/priv.
func (s *SNMPConfig) V3MsgFlags() gosnmp.SnmpV3MsgFlags {
	hasAuth := s.V3AuthType != "" && s.V3AuthPass != ""
	hasPriv := s.V3PrivType != "" && s.V3PrivPass != ""
	if hasAuth && hasPriv {
		return gosnmp.AuthPriv
	}
	if hasAuth {
		return gosnmp.AuthNoPriv
	}
	return gosnmp.NoAuthNoPriv
}

// V3AuthProto returns the gosnmp authentication protocol.
func (s *SNMPConfig) V3AuthProto() gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s.V3AuthType) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

// V3PrivProto returns the gosnmp privacy protocol.
func (s *SNMPConfig) V3PrivProto() gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s.V3PrivType) {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.NoPriv
	}
}

// Days returns the retention period for a given data type, falling back to DefaultDays.
func (r *RetentionConfig) Days(perType int) int {
	if perType > 0 {
		return perType
	}
	if r.DefaultDays > 0 {
		return r.DefaultDays
	}
	return 90
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getDefaultPassword returns a freshly-generated 16-character random
// password. AUDIT-158: the pre-fix implementation cached the
// generated password in a module-level `var defaultPassword string`,
// which lingered in GC until the next collection and could
// surface in core dumps even after the caller zeroed
// `cfg.Auth.AdminPassword` (the password bytes are duplicated by
// the Go runtime in unpredictable places). The fix: don't store
// the password anywhere. The caller is responsible for zeroing
// the returned string's underlying byte slice after the password
// has been hashed (see the AUDIT-158 fix in `cmd/api/main.go`).
func getDefaultPassword() string {
	return generateRandomPassword(16)
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

// IsGeneratedPassword returns true if the admin password was auto-generated
// (ADMIN_PASSWORD was not set in the env at config-load time). AUDIT-136:
// pre-fix this re-queried `os.LookupEnv` on every call, which is fragile
// (TOCTOU: the env could change between config-load and a later call
// to `IsGeneratedPassword()`). Post-fix the answer is captured once
// in `Auth.AdminPasswordGenerated` at config-load time and read here.
func (c *Config) IsGeneratedPassword() bool {
	return c.Auth.AdminPasswordGenerated
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
