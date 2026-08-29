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
	Server     ServerConfig
	SNMP       SNMPConfig
	Database   DatabaseConfig
	Auth       AuthConfig
	Alerts     AlertsConfig
	Uptime     UptimeConfig
	Retention  RetentionConfig
	Detect     DetectConfig
	ThreatFeed ThreatFeedConfig
}

// DetectConfig holds the operator-tunable sFlow detection-engine thresholds
// (DETECT_* env). A zero value means "use the detector's built-in default", so
// only the knobs the operator sets are overridden. These feed detect.Config in
// the poller's detection cycle.
type DetectConfig struct {
	PortScanPorts      int     // DETECT_PORT_SCAN_PORTS — distinct dst ports from one src (default 100)
	SuperSpreaderHosts int     // DETECT_SUPER_SPREADER_HOSTS — distinct dst hosts (default 100)
	DataExfilBytes     int64   // DETECT_DATA_EXFIL_BYTES — outbound (src,dst) bytes (default 1 GiB)
	BeaconMinSamples   int     // DETECT_BEACON_MIN_SAMPLES (default 8)
	BeaconMaxAvgBytes  int     // DETECT_BEACON_MAX_AVG_BYTES (default 1500)
	BeaconMaxCV        float64 // DETECT_BEACON_MAX_CV (default 0.35)
	CapacityThreshold  float64 // DETECT_CAPACITY_THRESHOLD — utilisation fraction (default 0.80)

	// Tranche 4 Phase 1 — DDoS volumetric OR-thresholds (peak-minute, per
	// victim; defaults follow FastNetMon community edition), prefix variant
	// (<=0 inherits the per-host value), sampling-rate-change guard.
	DDoSBps         int64 // DETECT_DDOS_BPS (default 1e9)
	DDoSPps         int64 // DETECT_DDOS_PPS (default 20000)
	DDoSFps         int   // DETECT_DDOS_FPS (default 3500; complete rows only)
	DDoSPrefixBps   int64 // DETECT_DDOS_PREFIX_BPS
	DDoSPrefixPps   int64 // DETECT_DDOS_PREFIX_PPS
	DDoSPrefixFps   int   // DETECT_DDOS_PREFIX_FPS
	SampRateMinRows int   // DETECT_SAMPRATE_MIN_ROWS (default 3)
	// Per-detector kill switches, stored inverted (Disabled) so the zero value
	// of DetectConfig keeps every detector ENABLED — a hand-constructed
	// config.Config{} (tests, tools) must not silently disable detection. Set
	// at load from the DETECT_*_ENABLED envs (default true). The detect_*
	// env+DB layered pattern predates the admin-UI-only knob preference and is
	// kept for consistency with the seven existing detector knobs.
	DDoSVolumetricDisabled     bool // !DETECT_DDOS_VOLUMETRIC_ENABLED
	DDoSPrefixDisabled         bool // !DETECT_DDOS_PREFIX_ENABLED
	SamplingRateChangeDisabled bool // !DETECT_SAMPLING_RATE_CHANGE_ENABLED

	// Tranche 4 Phase 2 — deny detectors (syslog action="deny" → denied_events).
	DenyStormExternal         int  // DETECT_DENY_STORM_MIN_DENIES — WAN-src denies/15m (default 300)
	DenyStormInternal         int  // DETECT_DENY_STORM_MIN_DENIES_INTERNAL — LAN-src (default 100)
	DenyVictimSources         int  // DETECT_DENY_STORM_VICTIM_MIN_SOURCES — distinct srcs/victim (default 200)
	DenyVictimCount           int  // DETECT_DENY_STORM_VICTIM_MIN_DENIES — raw denies/victim (default 2000)
	DeniedThenAllowedMin      int  // DETECT_DENIED_THEN_ALLOWED_MIN — prior denies before an allow (default 2)
	DenyStormDisabled         bool // !DETECT_DENY_STORM_ENABLED
	DenyStormVictimDisabled   bool // !DETECT_DENY_STORM_VICTIM_ENABLED
	DeniedThenAllowedDisabled bool // !DETECT_DENIED_THEN_ALLOWED_ENABLED
	// DenyPolicyPattern: block-policy-name glob whose action="start" sessions
	// also count as denials (the accept-log-drop scan convention). Applied at
	// syslog projection (internal/deny), overridable via the
	// detect_deny_policy_pattern admin setting. Default matches the common
	// IP_BLOCK* convention; empty disables.
	DenyPolicyPattern string // DETECT_DENY_POLICY_PATTERN (default "IP_BLOCK*")
}

// ThreatFeedConfig controls the optional auto-population of the threat-intel feed
// from free open-source bad-IP lists (THREAT_FEEDS_* env). Opt-in: the server
// makes no outbound feed requests unless Enabled is set.
type ThreatFeedConfig struct {
	Enabled       bool          // THREAT_FEEDS_ENABLED (default true — curated free public feeds)
	Interval      time.Duration // THREAT_FEEDS_INTERVAL (default 12h)
	TTLDays       int           // THREAT_FEEDS_TTL_DAYS — entries expire if not re-fed (default 14)
	ExtraURLs     string        // THREAT_FEEDS_EXTRA_URLS — CSV of name|url|category|severity to add to the defaults
	DisableBundle bool          // THREAT_FEEDS_DISABLE_BUNDLE — if true, use ONLY ExtraURLs (skip the built-in list)
	// AuthHeader is an optional HTTP header applied to EVERY feed fetch (built-in
	// and extra), formatted "Name: value" — e.g. "Authorization: Bearer <token>"
	// — so a user can plug in a paid/commercial subscription endpoint that
	// requires an API key. Empty = no header (the default free feeds need none).
	AuthHeader string // THREAT_FEEDS_AUTH_HEADER
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
	// GeoIPEnabled turns on geo/ASN enrichment of sFlow flows (src/dst country
	// + ASN), looked up at ingest. Default TRUE: a free DB-IP Lite database is
	// embedded in the binary, so enrichment works out of the box. Set false to
	// disable entirely (columns stay empty, Flows geo widgets hide).
	GeoIPEnabled bool
	// GeoIPDBDir is the "live" directory the optional paid MaxMind updater
	// writes into (GeoIP2/GeoLite2 .mmdb). Files here take precedence over the
	// embedded bundle. In Docker this is a volume mount.
	GeoIPDBDir string
	// GeoIPCacheDir is a writable directory the embedded DB-IP Lite bundle is
	// extracted to (geoip2 memory-maps real files). Empty = a per-OS temp
	// subdir. Distinct from GeoIPDBDir, which may be a read-only mount.
	GeoIPCacheDir string
	// MaxMindLicenseKey enables the paid live-update path: when set, the server
	// downloads the configured editions from MaxMind and writes them into
	// GeoIPDBDir (which then wins over the bundle). Empty = stay on the bundle.
	MaxMindLicenseKey string
	// MaxMindAccountID accompanies the license key for the Basic-auth form of
	// the download endpoint (optional for the query-param form).
	MaxMindAccountID string
	// MaxMindEditionIDs is the comma-separated edition list to download
	// (e.g. "GeoLite2-Country,GeoLite2-ASN" for a free key, or
	// "GeoIP2-City,GeoIP2-ISP" for a paid key).
	MaxMindEditionIDs string
	// GeoIPUpdateInterval is how often the live updater re-downloads. MaxMind
	// refreshes ~twice weekly, so weekly is a sensible default.
	GeoIPUpdateInterval time.Duration
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
	// H4 of the 2026-07-01 audit: the three sFlow-analytics tables that had no
	// retention path and grew unbounded. Terminal '1d' flow rollups are keyed by
	// the full conversation tuple (one row per distinct conversation per day),
	// flow_detections appends every 5-min detection cycle, and flow_agent_drops
	// appends per (agent, sampling_rate, window). The rollup default is a year —
	// rollups ARE the long-term flow history; detections and agent-drop windows
	// are operational events with shorter useful lives.
	FlowRollupDays    int // flow_rollups     (default 365)
	FlowDetectionDays int // flow_detections  (default 90)
	AgentDropsDays    int // flow_agent_drops (default 30)
	// Tranche 4 Phase 2: denied_events is a high-churn deny projection consumed
	// by the deny detectors on a 60-min lookback; 2 days covers investigation
	// without bloat. It is NOT the syslog retention (raw denies stay in
	// syslog_messages under the syslog knobs).
	DeniedEventDays int // denied_events   (default 2)
	// LC-20 (2026-07-04 audit): the five per-poll status tables that had no
	// retention path at all — every poll cycle (and every collector push)
	// appended rows forever. vpn_status/ha_status/security_stats/sdwan_health
	// are charted per-poll telemetry like interface_stats, so 0 here follows
	// StatusDays (the knob their chart siblings use) rather than DefaultDays.
	// license_info is a slow-moving expiry snapshot whose history is useful
	// year-over-year, so it gets its own longer default.
	VPNStatusDays     int // vpn_status     (default 0 = follow RETENTION_STATUS_DAYS)
	HAStatusDays      int // ha_status      (default 0 = follow RETENTION_STATUS_DAYS)
	SecurityStatsDays int // security_stats (default 0 = follow RETENTION_STATUS_DAYS)
	SDWANHealthDays   int // sdwan_health   (default 0 = follow RETENTION_STATUS_DAYS)
	LicenseInfoDays   int // license_info   (default 365)
	// LC-22 (2026-07-04 audit): resolved incidents (T2/F12 outage groupings)
	// age out like alert history — 0 = DefaultDays (90), matching how
	// RETENTION_ALERT_DAYS defaults. Open incidents are never deleted; the
	// device-recovery path (or a device delete, LC-21) closes them first.
	IncidentDays int // resolved incidents (default 0 = RETENTION_DEFAULT_DAYS)
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
	// auto-generated (i.e. ADMIN_PASSWORD was unset OR set-but-empty
	// in the environment — AUDIT-173 makes empty behave like unset,
	// since the shipped config.env.example seeds `ADMIN_PASSWORD=`
	// and an empty password can never pass login). AUDIT-136:
	// pre-fix, callers did
	// `os.LookupEnv("ADMIN_PASSWORD")` at every decision point,
	// which is fragile (the env could change between calls) and
	// duplicated work. The flag is captured once at config-load
	// time and read by every consumer.
	AdminPasswordGenerated bool
}

type AlertsConfig struct {
	EmailEnabled      bool
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTo            string
	SlackWebhookURL   string
	DiscordWebhookURL string
	WebHookURL        string
	// WebhookSecret enables HMAC signing of generic-webhook payloads (F18):
	// X-FirewallMon-Signature over timestamp+body. Empty = unsigned (legacy).
	WebhookSecret      string
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
	SpikeStdDevThreshold    float64
	SpikeAlertEnabled       bool
	SpikeMinDurationMinutes int // a real-time spike must persist this long before it alerts
	// SpikeMinThroughputMbps is the absolute noise floor (v0.11.121): no spike
	// alert unless the interface's busiest normal period reaches this rate AND
	// the spike itself exceeds it. 0 disables the floor (legacy pure z-score).
	SpikeMinThroughputMbps float64
	// Incident-channel credentials (T2-5). Presence = configured, mirroring
	// the Slack/Discord/webhook convention; per-policy flags gate routing.
	PagerDutyRoutingKey string
	OpsgenieAPIKey      string
	TeamsWebhookURL     string
	// PublicBaseURL is the externally-reachable base URL of this server (e.g.
	// https://fwmon.example.net), used to build clickable "view alert" deep-links
	// in notifications: <PublicBaseURL>/admin/#alert/<id>. Empty = omit the link.
	PublicBaseURL string
	// Flap suppression (F13): when an alert fires and auto-resolves in under
	// FlapMinActiveSeconds at least FlapMaxFires times within
	// FlapWindowMinutes, the next fire is saved suppressed (no notification)
	// until the flapping stops. FlapMaxFires=0 disables.
	FlapMaxFires         int
	FlapWindowMinutes    int
	FlapMinActiveSeconds int
}

type UptimeConfig struct {
	BaselineFile    string
	TrackingEnabled bool
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

	// AUDIT-173: read ADMIN_PASSWORD exactly once so AdminPassword and
	// AdminPasswordGenerated can never desync on a mid-Load env mutation.
	adminPasswordEnv := os.Getenv("ADMIN_PASSWORD")

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
			GeoIPEnabled:         getBoolEnv("GEOIP_ENABLED", true),
			GeoIPDBDir:           getEnv("GEOIP_DB_DIR", "/etc/firewall-mon/geoip"),
			GeoIPCacheDir:        getEnv("GEOIP_CACHE_DIR", ""),
			MaxMindLicenseKey:    getEnv("MAXMIND_LICENSE_KEY", ""),
			MaxMindAccountID:     getEnv("MAXMIND_ACCOUNT_ID", ""),
			MaxMindEditionIDs:    getEnv("MAXMIND_EDITION_IDS", "GeoLite2-Country,GeoLite2-ASN"),
			GeoIPUpdateInterval:  getDurationEnv("GEOIP_UPDATE_INTERVAL", 7*24*time.Hour),
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
			// H4 of the 2026-07-01 audit: see the field docs above.
			FlowRollupDays:    getIntEnv("RETENTION_FLOW_ROLLUP_DAYS", 365),
			FlowDetectionDays: getIntEnv("RETENTION_FLOW_DETECTION_DAYS", 90),
			AgentDropsDays:    getIntEnv("RETENTION_AGENT_DROPS_DAYS", 30),
			DeniedEventDays:   getIntEnv("RETENTION_DENIED_EVENT_DAYS", 2),
			// LC-20 / LC-22 (2026-07-04 audit): see the field docs above.
			VPNStatusDays:     getIntEnv("RETENTION_VPN_STATUS_DAYS", 0),
			HAStatusDays:      getIntEnv("RETENTION_HA_STATUS_DAYS", 0),
			SecurityStatsDays: getIntEnv("RETENTION_SECURITY_STATS_DAYS", 0),
			SDWANHealthDays:   getIntEnv("RETENTION_SDWAN_HEALTH_DAYS", 0),
			LicenseInfoDays:   getIntEnv("RETENTION_LICENSE_INFO_DAYS", 365),
			IncidentDays:      getIntEnv("RETENTION_INCIDENT_DAYS", 0),
		},
		Detect: DetectConfig{
			PortScanPorts:      getIntEnv("DETECT_PORT_SCAN_PORTS", 0),
			SuperSpreaderHosts: getIntEnv("DETECT_SUPER_SPREADER_HOSTS", 0),
			DataExfilBytes:     int64(getIntEnv("DETECT_DATA_EXFIL_BYTES", 0)),
			BeaconMinSamples:   getIntEnv("DETECT_BEACON_MIN_SAMPLES", 0),
			BeaconMaxAvgBytes:  getIntEnv("DETECT_BEACON_MAX_AVG_BYTES", 0),
			BeaconMaxCV:        getFloatEnv("DETECT_BEACON_MAX_CV", 0),
			CapacityThreshold:  getFloatEnv("DETECT_CAPACITY_THRESHOLD", 0),
			DDoSBps:            int64(getIntEnv("DETECT_DDOS_BPS", 0)),
			DDoSPps:            int64(getIntEnv("DETECT_DDOS_PPS", 0)),
			DDoSFps:            getIntEnv("DETECT_DDOS_FPS", 0),
			DDoSPrefixBps:      int64(getIntEnv("DETECT_DDOS_PREFIX_BPS", 0)),
			DDoSPrefixPps:      int64(getIntEnv("DETECT_DDOS_PREFIX_PPS", 0)),
			DDoSPrefixFps:      getIntEnv("DETECT_DDOS_PREFIX_FPS", 0),
			SampRateMinRows:    getIntEnv("DETECT_SAMPRATE_MIN_ROWS", 0),

			DDoSVolumetricDisabled:     !getBoolEnv("DETECT_DDOS_VOLUMETRIC_ENABLED", true),
			DDoSPrefixDisabled:         !getBoolEnv("DETECT_DDOS_PREFIX_ENABLED", true),
			SamplingRateChangeDisabled: !getBoolEnv("DETECT_SAMPLING_RATE_CHANGE_ENABLED", true),

			DenyStormExternal:         getIntEnv("DETECT_DENY_STORM_MIN_DENIES", 0),
			DenyStormInternal:         getIntEnv("DETECT_DENY_STORM_MIN_DENIES_INTERNAL", 0),
			DenyVictimSources:         getIntEnv("DETECT_DENY_STORM_VICTIM_MIN_SOURCES", 0),
			DenyVictimCount:           getIntEnv("DETECT_DENY_STORM_VICTIM_MIN_DENIES", 0),
			DeniedThenAllowedMin:      getIntEnv("DETECT_DENIED_THEN_ALLOWED_MIN", 0),
			DenyStormDisabled:         !getBoolEnv("DETECT_DENY_STORM_ENABLED", true),
			DenyStormVictimDisabled:   !getBoolEnv("DETECT_DENY_STORM_VICTIM_ENABLED", true),
			DeniedThenAllowedDisabled: !getBoolEnv("DETECT_DENIED_THEN_ALLOWED_ENABLED", true),
			DenyPolicyPattern:         getEnv("DETECT_DENY_POLICY_PATTERN", "IP_BLOCK*"),
		},
		ThreatFeed: ThreatFeedConfig{
			Enabled:       getBoolEnv("THREAT_FEEDS_ENABLED", true),
			Interval:      getDurationEnv("THREAT_FEEDS_INTERVAL", 12*time.Hour),
			TTLDays:       getIntEnv("THREAT_FEEDS_TTL_DAYS", 14),
			ExtraURLs:     getEnv("THREAT_FEEDS_EXTRA_URLS", ""),
			DisableBundle: getBoolEnv("THREAT_FEEDS_DISABLE_BUNDLE", false),
			AuthHeader:    getEnv("THREAT_FEEDS_AUTH_HEADER", ""),
		},
		Auth: AuthConfig{
			AdminUsername:         getEnv("ADMIN_USERNAME", "admin"),
			AdminUsernameExplicit: os.Getenv("ADMIN_USERNAME") != "",
			// AUDIT-173: an EMPTY ADMIN_PASSWORD (set-but-blank, exactly what
			// config.env.example ships and deploy.sh seeds) must behave like
			// UNSET and take the auto-generate+persist path. The pre-fix
			// LookupEnv semantics (AUDIT-136) treated blank as "the operator
			// deliberately wants an empty password", but the login handler
			// rejects empty passwords (binding:"required"), so that choice
			// produced an admin with bcrypt("") that nobody can ever log in
			// as and InitAdmin never replaces — a permanent lockout. Every
			// other secret in the tree (secrets.LoadOrGenerate, entrypoint
			// ${VAR:-...}) already treats blank as unset; this aligns
			// ADMIN_PASSWORD with them. The closure also keeps
			// getDefaultPassword() (a fresh CSPRNG value) from being
			// materialized when the operator did set a real password.
			// AUDIT-136's TOCTOU goal is preserved: both fields are captured
			// once, here, at config-load time.
			AdminPassword: func() string {
				if adminPasswordEnv != "" {
					return adminPasswordEnv
				}
				return getDefaultPassword()
			}(),
			AdminPasswordGenerated: adminPasswordEnv == "",
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
			WebhookSecret:            getEnv("WEBHOOK_SECRET", ""),
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
			SpikeMinDurationMinutes:  getIntEnv("SPIKE_MIN_DURATION_MINUTES", 15),
			SpikeMinThroughputMbps:   getFloatEnv("SPIKE_MIN_THROUGHPUT_MBPS", 1.0),
			FlapMaxFires:             getIntEnv("ALERT_FLAP_MAX_FIRES", 5),
			FlapWindowMinutes:        getIntEnv("ALERT_FLAP_WINDOW_MINUTES", 60),
			FlapMinActiveSeconds:     getIntEnv("ALERT_FLAP_MIN_ACTIVE_SECONDS", 120),
			PagerDutyRoutingKey:      getEnv("PAGERDUTY_ROUTING_KEY", ""),
			OpsgenieAPIKey:           getEnv("OPSGENIE_API_KEY", ""),
			TeamsWebhookURL:          getEnv("TEAMS_WEBHOOK_URL", ""),
			PublicBaseURL:            strings.TrimRight(getEnv("PUBLIC_BASE_URL", ""), "/"),
			ProbeDataLagAlertMinutes: getIntEnv("PROBE_DATA_LAG_ALERT_MINUTES", 60),
		},
		Uptime: UptimeConfig{
			BaselineFile:    getEnv("UPTIME_BASELINE_FILE", "/var/lib/firewall-mon/uptime.json"),
			TrackingEnabled: getBoolEnv("UPTIME_TRACKING_ENABLED", true),
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

	// Secrets warnings.
	// AUDIT-310: the old text here ("tokens invalidated on restart") predated
	// the AUDIT-008 persistence flow — every binary now runs
	// secrets.LoadOrGenerate, which persists the generated key to
	// <SECRETS_DIR>/.jwt-secret and reloads it on later boots. The companion
	// "credentials will not be encrypted" warning was likewise false (the DB
	// layer always derives an AES key from the JWT secret when ENCRYPTION_KEY
	// is unset, and logs its own accurate warning) and was removed.
	if c.Server.JWTSecretKey == "" {
		log.Println("NOTICE: JWT_SECRET_KEY not set — a key will be auto-generated and persisted to <SECRETS_DIR>/.jwt-secret. Tokens survive restarts as long as that directory persists; if it is lost, every login token is invalidated (and, unless ENCRYPTION_KEY is set, every stored encrypted credential becomes unreadable too). Set JWT_SECRET_KEY explicitly for portable deployments.")
	} else if len(c.Server.JWTSecretKey) < 32 {
		// AUDIT L2: HS256 with a low-entropy operator-set secret is offline
		// brute-forceable (and it also seeds the AES key when ENCRYPTION_KEY is
		// unset). The auto-generated key is 32 bytes; hold operator-set keys to
		// the same floor. Warn (not fatal) so an upgrade can't brick boot.
		log.Printf("WARNING: JWT_SECRET_KEY is only %d characters — use at least 32 random characters; a short secret is brute-forceable and weakens token + credential security", len(c.Server.JWTSecretKey))
	}
	// AUDIT-173 (belt-and-braces): with the empty-as-unset resolution above,
	// AdminPassword can never be empty here; if a future refactor breaks that
	// invariant, fail loudly instead of bootstrapping an admin with
	// bcrypt("") that the login handler can never accept.
	if c.Auth.AdminPassword == "" {
		return fmt.Errorf("ADMIN_PASSWORD resolved empty — refusing to bootstrap an admin account with an empty password")
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
// (ADMIN_PASSWORD was unset or set-but-empty in the env at config-load
// time — AUDIT-173 treats empty as unset). AUDIT-136:
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
