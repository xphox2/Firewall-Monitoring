package models

import (
	"encoding/json"
	"time"
)

// AlertType is the typed enum of alert categories raised by the AlertManager.
// It is a named string so a typo in a switch arm or assignment is a compile
// error. Wire/DB encoding is identical to a plain string (JSON + GORM scan the
// underlying value), so persisted rows and API payloads are unchanged.
type AlertType string

const (
	AlertTypeCPUHigh            AlertType = "CPU_HIGH"
	AlertTypeMemoryHigh         AlertType = "MEMORY_HIGH"
	AlertTypeDiskHigh           AlertType = "DISK_HIGH"
	AlertTypeSessionsHigh       AlertType = "SESSIONS_HIGH"
	AlertTypeDeviceOffline      AlertType = "DEVICE_OFFLINE"
	AlertTypeInterfaceDown      AlertType = "INTERFACE_DOWN"
	AlertTypeInterfaceErrors    AlertType = "INTERFACE_ERRORS"
	AlertTypeVPNTunnelDown      AlertType = "VPN_TUNNEL_DOWN"
	AlertTypeConfigChange       AlertType = "CONFIG_CHANGE"
	AlertTypeSSHHostKeyChanged  AlertType = "SSH_HOST_KEY_CHANGED"
	AlertTypeTrafficSpike       AlertType = "TRAFFIC_SPIKE"
	AlertTypeProbeDataLag       AlertType = "PROBE_DATA_LAG"
	AlertTypeProbeDataTruncated AlertType = "PROBE_DATA_TRUNCATED"
	AlertTypeHAHeartbeatFail    AlertType = "HA_HEARTBEAT_FAIL"
	AlertTypeHAMemberDown       AlertType = "HA_MEMBER_DOWN"
	AlertTypeHAMemberUp         AlertType = "HA_MEMBER_UP"
	AlertTypeHAStateChange      AlertType = "HA_STATE_CHANGE"
	AlertTypeHASwitch           AlertType = "HA_SWITCH"
	AlertTypeSyslogEmergency    AlertType = "SYSLOG_EMERGENCY"
	AlertTypeSyslogCritical     AlertType = "SYSLOG_CRITICAL"
	AlertTypeSyslogAlert        AlertType = "SYSLOG_ALERT"
	AlertTypeSFlowAgentDrops    AlertType = "SFLOW_AGENT_DROPS"
	AlertTypeTestAlert          AlertType = "TEST_ALERT"
)

// Severity is the typed enum of alert severities. Underlying values match the
// historical strings ("info" | "warning" | "critical"); arbitrary strings
// remain representable via conversion so no value is lost on scan.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// CommandType is the typed enum of IRC bot command kinds.
type CommandType string

const (
	CommandTypeStatic CommandType = "static"
	CommandTypeStatus CommandType = "status"
	CommandTypeStats  CommandType = "stats"
	CommandTypeCustom CommandType = "custom"
	CommandTypeHelp   CommandType = "help"
)

type SystemStatus struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Timestamp    time.Time `json:"timestamp" gorm:"index:idx_sysstatus_device_ts,priority:2"`
	DeviceID     uint      `json:"device_id" gorm:"index;index:idx_sysstatus_device_ts,priority:1"`
	Hostname     string    `json:"hostname"`
	Version      string    `json:"version"`
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  float64   `json:"memory_usage"`
	MemoryTotal  uint64    `json:"memory_total"`
	DiskUsage    float64   `json:"disk_usage"`
	DiskTotal    uint64    `json:"disk_total"`
	SessionCount int       `json:"session_count"`
	Uptime       uint64    `json:"uptime"`
	// Extended session/memory/signature telemetry
	SessionRate1  int    `json:"session_rate_1"`
	SessionRate10 int    `json:"session_rate_10"`
	SessionRate30 int    `json:"session_rate_30"`
	SessionRate60 int    `json:"session_rate_60"`
	SessionCount6 int    `json:"session_count_6"`
	LowMemUsage   int    `json:"low_mem_usage"`
	LowMemCap     int    `json:"low_mem_cap"`
	AVVersion     string `json:"av_version"`
	IPSVersion    string `json:"ips_version"`
	SSLVPNUsers   int    `json:"sslvpn_users"`
	SSLVPNTunnels int    `json:"sslvpn_tunnels"`
	// Network throughput (kbps) from SSH performance status
	NetworkInKbps  float64 `json:"network_in_kbps"`
	NetworkOutKbps float64 `json:"network_out_kbps"`
	// CPU breakdown from SSH performance status
	CPUUser    float64 `json:"cpu_user"`
	CPUSystem  float64 `json:"cpu_system"`
	CPUNice    float64 `json:"cpu_nice"`
	CPUIdle    float64 `json:"cpu_idle"`
	CPUIowait  float64 `json:"cpu_iowait"`
	CPUIrq     float64 `json:"cpu_irq"`
	CPUSoftirq float64 `json:"cpu_softirq"`
	// Memory breakdown
	MemoryFree     uint64 `json:"memory_free"`
	MemoryFreeable uint64 `json:"memory_freeable"`
}

type InterfaceStats struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp" gorm:"index:idx_iface_device_ts,priority:2;index:idx_iface_device_idx_ts,priority:3"`
	DeviceID    uint      `json:"device_id" gorm:"index;index:idx_iface_device_ts,priority:1;index:idx_iface_device_idx_ts,priority:1"`
	Name        string    `json:"name"`
	Index       int       `json:"index" gorm:"index:idx_iface_device_idx_ts,priority:2"`
	Type        int       `json:"type"`
	Speed       uint64    `json:"speed"`
	Status      string    `json:"status"`
	InBytes     uint64    `json:"in_bytes"`
	InPackets   uint64    `json:"in_packets"`
	InErrors    uint64    `json:"in_errors"`
	InDiscards  uint64    `json:"in_discards"`
	OutBytes    uint64    `json:"out_bytes"`
	OutPackets  uint64    `json:"out_packets"`
	OutErrors   uint64    `json:"out_errors"`
	OutDiscards uint64    `json:"out_discards"`
	AdminStatus string    `json:"admin_status"`
	Description string    `json:"description"`
	Alias       string    `json:"alias"`
	MTU         int       `json:"mtu"`
	MACAddress  string    `json:"mac_address"`
	TypeName    string    `json:"type_name"`
	HighSpeed   uint64    `json:"high_speed"`
	VLANID      int       `json:"vlan_id"`
}

type VPNStatus struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	Timestamp     time.Time `json:"timestamp" gorm:"index:idx_vpn_device_ts,priority:2"`
	DeviceID      uint      `json:"device_id" gorm:"index;index:idx_vpn_device_ts,priority:1"`
	TunnelName    string    `json:"tunnel_name"`
	TunnelType    string    `json:"tunnel_type"`
	RemoteIP      string    `json:"remote_ip"`
	Status        string    `json:"status"`
	BytesIn       uint64    `json:"bytes_in"`
	BytesOut      uint64    `json:"bytes_out"`
	PacketsIn     uint64    `json:"packets_in"`
	PacketsOut    uint64    `json:"packets_out"`
	State         string    `json:"state"`
	Phase1Name    string    `json:"phase1_name"`
	LocalSubnet   string    `json:"local_subnet"`
	RemoteSubnet  string    `json:"remote_subnet"`
	TunnelUptime  uint64    `json:"tunnel_uptime"`
	InterfaceName string    `json:"interface_name"`
	Mode          string    `json:"mode"`
	// LastUpAt — most recent timestamp at which this tunnel reported
	// `status='up'` for this device. Computed (not stored) by
	// GetLatestVPNStatuses (v0.10.217, bundle D4) by scanning historical
	// rows. Nil when no historical 'up' is known. Lets the UI render
	// "last seen up 2h ago" for tunnels currently down.
	LastUpAt *time.Time `json:"last_up_at,omitempty" gorm:"-"`
	// RemoteDeviceID — resolved peer device id when GetLatestVPNStatuses
	// is able to match this tunnel to a peer's VPN snapshot by RemoteIP
	// (v0.10.218, bundle G3). Lets the frontend link the remote_ip cell
	// to the peer's /admin/devices/:id page when known. Nil when no peer
	// match exists (typical for tunnels to non-monitored remote sites).
	RemoteDeviceID *uint `json:"remote_device_id,omitempty" gorm:"-"`
}

type HAStatus struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp" gorm:"index:idx_ha_device_ts,priority:2"`
	DeviceID       uint      `json:"device_id" gorm:"index;index:idx_ha_device_ts,priority:1"`
	SystemMode     string    `json:"system_mode"`
	GroupID        int       `json:"group_id"`
	GroupName      string    `json:"group_name"`
	MemberIndex    int       `json:"member_index"`
	MemberSerial   string    `json:"member_serial"`
	MemberHostname string    `json:"member_hostname"`
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	NetworkUsage   int       `json:"network_usage"`
	SessionCount   int       `json:"session_count"`
	PacketCount    uint64    `json:"packet_count"`
	ByteCount      uint64    `json:"byte_count"`
	SyncStatus     string    `json:"sync_status"`
	MasterSerial   string    `json:"master_serial"`
}

type SecurityStats struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp" gorm:"index:idx_secstats_device_ts,priority:2"`
	DeviceID       uint      `json:"device_id" gorm:"index;index:idx_secstats_device_ts,priority:1"`
	AVDetected     uint64    `json:"av_detected"`
	AVBlocked      uint64    `json:"av_blocked"`
	AVHTTPDetected uint64    `json:"av_http_detected"`
	AVHTTPBlocked  uint64    `json:"av_http_blocked"`
	AVSMTPDetected uint64    `json:"av_smtp_detected"`
	AVSMTPBlocked  uint64    `json:"av_smtp_blocked"`
	IPSDetected    uint64    `json:"ips_detected"`
	IPSBlocked     uint64    `json:"ips_blocked"`
	IPSCritical    uint64    `json:"ips_critical"`
	IPSHigh        uint64    `json:"ips_high"`
	IPSMedium      uint64    `json:"ips_medium"`
	IPSLow         uint64    `json:"ips_low"`
	IPSInfo        uint64    `json:"ips_info"`
	WFHTTPBlocked  uint64    `json:"wf_http_blocked"`
	WFHTTPSBlocked uint64    `json:"wf_https_blocked"`
	WFURLBlocked   uint64    `json:"wf_url_blocked"`
}

type SDWANHealth struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	Timestamp  time.Time `json:"timestamp" gorm:"index:idx_sdwan_device_ts,priority:2"`
	DeviceID   uint      `json:"device_id" gorm:"index;index:idx_sdwan_device_ts,priority:1"`
	Name       string    `json:"name"`
	Interface  string    `json:"interface"`
	State      string    `json:"state"`
	Latency    float64   `json:"latency"`
	PacketLoss float64   `json:"packet_loss"`
	PacketSend uint64    `json:"packet_send"`
	PacketRecv uint64    `json:"packet_recv"`
}

type LicenseInfo struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp" gorm:"index:idx_license_device_ts,priority:2"`
	DeviceID    uint      `json:"device_id" gorm:"index;index:idx_license_device_ts,priority:1"`
	Description string    `json:"description"`
	ExpiryDate  string    `json:"expiry_date"`
	Status      string    `json:"status"`
	Details     string    `json:"details"`
}

type HardwareSensor struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Timestamp time.Time `json:"timestamp" gorm:"index:idx_hwsensor_device_ts,priority:2"`
	DeviceID  uint      `json:"device_id" gorm:"index;index:idx_hwsensor_device_ts,priority:1"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     float64   `json:"value"`
	Status    string    `json:"status"`
	Unit      string    `json:"unit"`
}

type ProcessorStats struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Timestamp time.Time `json:"timestamp" gorm:"index:idx_proc_device_ts,priority:2"`
	DeviceID  uint      `json:"device_id" gorm:"index;index:idx_proc_device_ts,priority:1"`
	Index     int       `json:"index"`
	Usage     float64   `json:"usage"`
}

func (ProcessorStats) TableName() string { return "processor_stats" }

type TrapEvent struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Timestamp time.Time `json:"timestamp" gorm:"index:idx_trap_device_ts,priority:2"`
	DeviceID  uint      `json:"device_id" gorm:"index;index:idx_trap_device_ts,priority:1"`
	ProbeID   uint      `json:"probe_id" gorm:"index"`
	SourceIP  string    `json:"source_ip"`
	TrapOID   string    `json:"trap_oid"`
	TrapType  string    `json:"trap_type"`
	Severity  string    `json:"severity" gorm:"index:idx_trap_severity"`
	Message   string    `json:"message"`
	Processed bool      `json:"processed"`
}

type Alert struct {
	ID              uint       `json:"id" gorm:"primaryKey"`
	Timestamp       time.Time  `json:"timestamp" gorm:"index:idx_alert_device_ts,priority:2;index:idx_alert_unack,priority:3"`
	DeviceID        uint       `json:"device_id" gorm:"index;index:idx_alert_device_ts,priority:1"`
	ProbeID         *uint      `json:"probe_id" gorm:"index"`
	AlertType       AlertType  `json:"alert_type"`
	Severity        Severity   `json:"severity"`
	Message         string     `json:"message"`
	MetricName      string     `json:"metric_name"`
	Threshold       float64    `json:"threshold"`
	CurrentValue    float64    `json:"current_value"`
	Notified        bool       `json:"notified"`
	Acknowledged    bool       `json:"acknowledged" gorm:"index:idx_alert_ack;index:idx_alert_unack,priority:1"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	Notes           string     `json:"notes"`
	PolicyID        *uint      `json:"policy_id" gorm:"index"`
	EscalationCount int        `json:"escalation_count" gorm:"default:0"`
	Suppressed      bool       `json:"suppressed" gorm:"default:false;index:idx_alert_unack,priority:2"`
	// Snooze controls (v0.10.218, bundle G2). An alert can be snoozed
	// for a duration without being acknowledged — distinct from
	// `Acknowledged` because snoozing is "ack temporarily, surface
	// again once the snooze expires". Implemented as a future
	// timestamp; alerts where SnoozedUntil > now are filtered out of
	// the default alerts list. SnoozedBy + SnoozedReason are audit-
	// only and never displayed to non-admin viewers.
	SnoozedUntil  *time.Time `json:"snoozed_until,omitempty" gorm:"index"`
	SnoozedBy     string     `json:"snoozed_by,omitempty"`
	SnoozedReason string     `json:"snoozed_reason,omitempty"`
}

type AlertPolicy struct {
	ID                uint        `json:"id" gorm:"primaryKey"`
	Name              string      `json:"name" gorm:"uniqueIndex;not null"`
	Description       string      `json:"description"`
	IsDefault         bool        `json:"is_default" gorm:"default:false;index"`
	NotifyEmail       bool        `json:"notify_email" gorm:"default:false"`
	NotifySlack       bool        `json:"notify_slack" gorm:"default:false"`
	NotifyDiscord     bool        `json:"notify_discord" gorm:"default:false"`
	NotifyWebhook     bool        `json:"notify_webhook" gorm:"default:false"`
	EmailRecipients   string      `json:"email_recipients"`
	SlackWebhookURL   string      `json:"slack_webhook_url"`
	DiscordWebhookURL string      `json:"discord_webhook_url"`
	WebhookURL        string      `json:"webhook_url"`
	CooldownMinutes   int         `json:"cooldown_minutes" gorm:"default:5"`
	EscalationEnabled bool        `json:"escalation_enabled" gorm:"default:false"`
	EscalationMinutes int         `json:"escalation_minutes" gorm:"default:30"`
	EscalationRepeat  int         `json:"escalation_repeat" gorm:"default:3"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdatedAt         time.Time   `json:"updated_at"`
	Rules             []AlertRule `json:"rules,omitempty" gorm:"foreignKey:PolicyID"`
}

func (AlertPolicy) TableName() string { return "alert_policies" }

type AlertRule struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	PolicyID        uint      `json:"policy_id" gorm:"uniqueIndex:idx_policy_alert_type,priority:1;not null"`
	AlertType       AlertType `json:"alert_type" gorm:"uniqueIndex:idx_policy_alert_type,priority:2;not null"`
	Enabled         bool      `json:"enabled" gorm:"default:true"`
	Severity        Severity  `json:"severity"`
	Threshold       float64   `json:"threshold"`
	NotifyEmail     *bool     `json:"notify_email"`
	NotifySlack     *bool     `json:"notify_slack"`
	NotifyDiscord   *bool     `json:"notify_discord"`
	NotifyWebhook   *bool     `json:"notify_webhook"`
	CooldownMinutes *int      `json:"cooldown_minutes"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (AlertRule) TableName() string { return "alert_rules" }

type DeviceAlertConfig struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	DeviceID         uint      `json:"device_id" gorm:"uniqueIndex;not null"`
	PolicyID         *uint     `json:"policy_id" gorm:"index"`
	CPUThreshold     float64   `json:"cpu_threshold"`
	MemoryThreshold  float64   `json:"memory_threshold"`
	DiskThreshold    float64   `json:"disk_threshold"`
	SessionThreshold int       `json:"session_threshold"`
	CooldownMinutes  int       `json:"cooldown_minutes"`
	AlertsEnabled    bool      `json:"alerts_enabled" gorm:"default:true"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (DeviceAlertConfig) TableName() string { return "device_alert_configs" }

type SiteAlertConfig struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	SiteID           uint      `json:"site_id" gorm:"uniqueIndex;not null"`
	PolicyID         *uint     `json:"policy_id" gorm:"index"`
	CPUThreshold     float64   `json:"cpu_threshold"`
	MemoryThreshold  float64   `json:"memory_threshold"`
	DiskThreshold    float64   `json:"disk_threshold"`
	SessionThreshold int       `json:"session_threshold"`
	CooldownMinutes  int       `json:"cooldown_minutes"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (SiteAlertConfig) TableName() string { return "site_alert_configs" }

type MaintenanceWindow struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	DeviceID    *uint     `json:"device_id" gorm:"index"`
	SiteID      *uint     `json:"site_id" gorm:"index"`
	Name        string    `json:"name" gorm:"not null"`
	StartTime   time.Time `json:"start_time" gorm:"not null;index"`
	EndTime     time.Time `json:"end_time" gorm:"not null;index"`
	Recurring   bool      `json:"recurring" gorm:"default:false"`
	RecurRule   string    `json:"recur_rule"`
	RecurDays   string    `json:"recur_days"`
	SuppressAll bool      `json:"suppress_all" gorm:"default:true"`
	AlertTypes  string    `json:"alert_types"`
	Notes       string    `json:"notes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (MaintenanceWindow) TableName() string { return "maintenance_windows" }

type UptimeRecord struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp" gorm:"index:idx_uptime_device_ts,priority:2"`
	DeviceID       uint      `json:"device_id" gorm:"index;index:idx_uptime_device_ts,priority:1"`
	DeviceUptime   uint64    `json:"device_uptime"`
	TotalDowntime  float64   `json:"total_downtime_seconds"`
	UptimePercent  float64   `json:"uptime_percent"`
	DowntimeEvents int       `json:"downtime_events"`
}

// ProcessedBatch records the idempotency key of a probe data batch that has
// been successfully ingested (AUDIT-042). The collector sends a stable
// `X-Probe-Batch-ID` per batch and reuses it across its retry attempts; the
// server records the (probe_id, batch_id) pair after a successful save and
// short-circuits any later request carrying the same pair, so a response that
// times out after the data was saved doesn't produce duplicate rows on retry.
type ProcessedBatch struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	ProbeID   uint      `json:"probe_id" gorm:"uniqueIndex:idx_processed_batch,priority:1;not null"`
	BatchID   string    `json:"batch_id" gorm:"uniqueIndex:idx_processed_batch,priority:2;not null"`
	Timestamp time.Time `json:"timestamp" gorm:"index"`
}

type LoginAttempt struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	IPAddress string    `json:"ip_address"`
	Success   bool      `json:"success"`
	UserAgent string    `json:"user_agent"`
}

// SchemaMigration records one applied DB migration (AUDIT-044). The
// schema_migrations table is created by the migration runner via raw DDL
// before any migration runs (so the "which versions are applied?" query never
// depends on a migration having created it) — this struct is therefore the
// READ model only and is intentionally NOT added to any AutoMigrate list.
type SchemaMigration struct {
	Version    int       `json:"version" gorm:"primaryKey"`
	Name       string    `json:"name"`
	AppVersion string    `json:"app_version"`
	AppliedAt  time.Time `json:"applied_at"`
}

func (SchemaMigration) TableName() string { return "schema_migrations" }

// AuditLog records a privileged admin mutation (AUDIT-078): who did what, to
// which target, from where, and whether it succeeded. The audit middleware
// writes one row per authenticated POST/PUT/DELETE/PATCH under /admin. It is
// append-only — there is no update or delete path in the application, so the
// trail can't be silently rewritten through the API. `login_attempts` already
// covers authentication; this covers everything an authenticated admin changes.
type AuditLog struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	Actor     string    `json:"actor" gorm:"index"`  // username from the JWT
	ActorID   uint      `json:"actor_id"`            // admin user id
	Method    string    `json:"method"`              // POST / PUT / DELETE / PATCH
	Action    string    `json:"action" gorm:"index"` // matched route template, e.g. /admin/api/devices/:id
	Target    string    `json:"target"`              // concrete path params, e.g. id=5
	Status    int       `json:"status"`              // HTTP status the handler returned
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

type Device struct {
	ID              uint   `json:"id" gorm:"primaryKey"`
	Name            string `json:"name" gorm:"uniqueIndex;not null"`
	Hostname        string `json:"hostname"`
	IPAddress       string `json:"ip_address" gorm:"not null"`
	SNMPPort        int    `json:"snmp_port" gorm:"default:161"`
	SNMPCommunity   string `json:"snmp_community"`
	SNMPVersion     string `json:"snmp_version" gorm:"default:2c"`
	SNMPV3Username  string `json:"snmpv3_username"`
	SNMPV3AuthType  string `json:"snmpv3_auth_type"`
	SNMPV3AuthPass  string `json:"snmpv3_auth_pass"`
	SNMPV3PrivType  string `json:"snmpv3_priv_type"`
	SNMPV3PrivPass  string `json:"snmpv3_priv_pass"`
	Enabled         bool   `json:"enabled" gorm:"default:true"`
	PublicVisible   bool   `json:"public_visible" gorm:"default:true"`
	Vendor          string `json:"vendor" gorm:"default:fortigate"`
	SiteID          *uint  `json:"site_id" gorm:"index"`
	Site            *Site  `json:"site,omitempty" gorm:"foreignKey:SiteID"`
	ProbeID         *uint  `json:"probe_id" gorm:"index"`
	Probe           *Probe `json:"probe,omitempty" gorm:"foreignKey:ProbeID"`
	Location        string `json:"location"`
	Description     string `json:"description"`
	WanSpeedMbps    int    `json:"wan_speed_mbps" gorm:"default:1000"` // WAN link speed in Mbps (default 1Gbps)
	SSLVPNUsers     int    `json:"sslvpn_users" gorm:"default:0"`
	SSLVPNTunnels   int    `json:"sslvpn_tunnels" gorm:"default:0"`
	SSHUsername     string `json:"ssh_username"`
	SSHPassword     string `json:"ssh_password"`
	SSHPort         int    `json:"ssh_port" gorm:"default:22"`
	SSHPollEnabled  bool   `json:"ssh_poll_enabled" gorm:"default:false"`
	SSHPollInterval int    `json:"ssh_poll_interval" gorm:"default:900"`
	// SSHHostKeys is the newline-joined set of known-good SSH host-key
	// fingerprints ("SHA256:...") for this device. A device legitimately has
	// more than one when it is a FortiGate HA cluster — each member presents its
	// own key — so the server learns each via trust-on-first-use rather than
	// treating any change as suspicious. A reported fingerprint not in this set
	// raises an SSH_HOST_KEY_CHANGED alert (CRITICAL if unexplained, WARNING if
	// it correlates with a recent HA failover) and is then added. Blank until the
	// first observation. Public data — stored plaintext (column kept as
	// ssh_host_key), NOT encrypted like the SSH password.
	SSHHostKeys string    `gorm:"column:ssh_host_key" json:"ssh_host_keys"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastPolled  time.Time `json:"last_polled"`
	Status      string    `json:"status" gorm:"default:unknown"`
}

type DeviceTunnel struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	DeviceID      uint      `json:"device_id" gorm:"not null;index"`
	Name          string    `json:"name" gorm:"not null"`
	RemoteGateway string    `json:"remote_gateway"`
	LocalSubnet   string    `json:"local_subnet"`
	RemoteSubnet  string    `json:"remote_subnet"`
	TunnelType    string    `json:"tunnel_type" gorm:"default:ipsec"`
	Status        string    `json:"status" gorm:"default:unknown"`
	BytesIn       uint64    `json:"bytes_in"`
	BytesOut      uint64    `json:"bytes_out"`
	LastChange    time.Time `json:"last_change"`
}

type DeviceConnection struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Name           string    `json:"name" gorm:"not null"`
	SourceDeviceID uint      `json:"source_device_id" gorm:"not null;index"`
	SourceDevice   *Device   `json:"source_device,omitempty" gorm:"foreignKey:SourceDeviceID"`
	SourceTunnelID uint      `json:"source_tunnel_id"`
	DestDeviceID   uint      `json:"dest_device_id" gorm:"not null;index"`
	DestDevice     *Device   `json:"dest_device,omitempty" gorm:"foreignKey:DestDeviceID"`
	DestTunnelID   uint      `json:"dest_tunnel_id"`
	ConnectionType string    `json:"connection_type" gorm:"default:ipsec"`
	Status         string    `json:"status" gorm:"default:unknown"`
	Latency        float64   `json:"latency"`
	LastCheck      time.Time `json:"last_check"`
	Notes          string    `json:"notes"`
	AutoDetected   bool      `json:"auto_detected" gorm:"default:false"`
	TunnelNames    string    `json:"tunnel_names"`
	MatchMethod    string    `json:"match_method" gorm:"default:ip_match"`
}

type InterfaceAddress struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Timestamp time.Time `json:"timestamp" gorm:"index:idx_ifaddr_device_ts,priority:2"`
	DeviceID  uint      `json:"device_id" gorm:"index;index:idx_ifaddr_device_ts,priority:1;uniqueIndex:idx_ifaddr_dev_ip,priority:1"`
	IfIndex   int       `json:"if_index"`
	IPAddress string    `json:"ip_address" gorm:"index:idx_ifaddr_ip,priority:1;uniqueIndex:idx_ifaddr_dev_ip,priority:2"`
	NetMask   string    `json:"net_mask"`
}

type SystemSetting struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Key       string    `json:"key" gorm:"uniqueIndex;not null"`
	Value     string    `json:"value"`
	Type      string    `json:"type" gorm:"default:string"`
	Label     string    `json:"label"`
	Category  string    `json:"category"`
	IsSecret  bool      `json:"is_secret" gorm:"default:false"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Admin struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Username     string    `json:"username" gorm:"uniqueIndex;not null"`
	Password     string    `json:"-" gorm:"not null"`
	TokenVersion uint      `json:"-" gorm:"default:0"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Site struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name" gorm:"uniqueIndex;not null"`
	Region       string    `json:"region"`
	Country      string    `json:"country"`
	Address      string    `json:"address"`
	Timezone     string    `json:"timezone"`
	ParentSiteID *uint     `json:"parent_site_id" gorm:"index"`
	ParentSite   *Site     `json:"parent_site,omitempty" gorm:"foreignKey:ParentSiteID"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Probes       []Probe   `json:"probes,omitempty" gorm:"foreignKey:SiteID"`
}

type Probe struct {
	ID               uint       `json:"id" gorm:"primaryKey"`
	Name             string     `json:"name" gorm:"uniqueIndex;not null"`
	SiteID           uint       `json:"site_id" gorm:"index"`
	Site             *Site      `json:"site,omitempty" gorm:"foreignKey:SiteID"`
	RegistrationKey  string     `json:"registration_key" gorm:"uniqueIndex"`
	Enabled          bool       `json:"enabled" gorm:"default:true"`
	Status           string     `json:"status" gorm:"default:pending"`
	ApprovalStatus   string     `json:"approval_status" gorm:"default:pending;index:idx_probe_approval"`
	ApprovedAt       *time.Time `json:"approved_at"`
	ApprovedBy       *uint      `json:"approved_by"`
	RejectedAt       *time.Time `json:"rejected_at"`
	RejectedReason   string     `json:"rejected_reason"`
	LastSeen         time.Time  `json:"last_seen"`
	LastDataReceived time.Time  `json:"last_data_received" gorm:"index"`
	ListenAddress    string     `json:"listen_address"`
	ListenPort       int        `json:"listen_port" gorm:"default:8089"`
	TLSCertPath      string     `json:"tls_cert_path"`
	TLSKeyPath       string     `json:"tls_key_path"`
	ServerURL        string     `json:"server_url"`
	ServerTLSCert    string     `json:"server_tls_cert"`
	Description      string     `json:"description"`
	TFTPServerIP     string     `json:"tftp_server_ip"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	// DecommissionedAt marks a probe as retired (decommissioned/replaced)
	// WITHOUT deleting its row or any of its telemetry, so historical running
	// totals continue to include it. Non-null => decommissioned: hidden from
	// active probe lists and excluded from the "active probes" count, but its
	// data is preserved. Cleared by RecommissionProbe.
	DecommissionedAt *time.Time `json:"decommissioned_at,omitempty" gorm:"index"`
}

type ProbeSite struct {
	ProbeID uint `json:"probe_id" gorm:"primaryKey"`
	SiteID  uint `json:"site_id" gorm:"primaryKey"`
}

type ProbeApproval struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	ProbeID        uint       `json:"probe_id" gorm:"uniqueIndex;not null"`
	Probe          *Probe     `json:"probe,omitempty" gorm:"foreignKey:ProbeID"`
	RequestedAt    time.Time  `json:"requested_at"`
	ApprovedAt     *time.Time `json:"approved_at"`
	ApprovedBy     *uint      `json:"approved_by"`
	ApprovedByUser string     `json:"approved_by_user"`
	RejectedAt     *time.Time `json:"rejected_at"`
	RejectedReason string     `json:"rejected_reason"`
	Status         string     `json:"status" gorm:"default:pending"` // pending, approved, rejected
	Notes          string     `json:"notes"`
}

type ProbeHeartbeat struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	ProbeID   uint      `json:"probe_id" gorm:"index:idx_heartbeat_probe_ts,priority:1;not null"`
	Probe     *Probe    `json:"probe,omitempty" gorm:"foreignKey:ProbeID"`
	Status    string    `json:"status"` // online, offline
	IPAddress string    `json:"ip_address"`
	Version   string    `json:"version"`
	Uptime    uint64    `json:"uptime"`
	Timestamp time.Time `json:"timestamp" gorm:"index:idx_heartbeat_probe_ts,priority:2"`
}

type PingResult struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Timestamp    time.Time `json:"timestamp" gorm:"index;index:idx_ping_device_ts,priority:2"`
	DeviceID     uint      `json:"device_id" gorm:"index;index:idx_ping_device_ts,priority:1"`
	ProbeID      uint      `json:"probe_id" gorm:"index"`
	TargetIP     string    `json:"target_ip"`
	Success      bool      `json:"success"`
	Latency      float64   `json:"latency"`
	PacketLoss   float64   `json:"packet_loss"`
	TTL          int       `json:"ttl"`
	ErrorMessage string    `json:"error_message"`
}

type PingStats struct {
	ID uint `json:"id" gorm:"primaryKey"`
	// Ping stats are a single continuous series per (device_id, target_ip) so a
	// device's reachability history stays unified across probe replacements.
	// probe_id is kept as last-writer provenance only — it is NOT part of the
	// uniqueness key (see migration v3 unify_ping_stats_by_device_target).
	DeviceID   uint      `json:"device_id" gorm:"index:idx_pingstats_device_target,unique,priority:1"`
	ProbeID    uint      `json:"probe_id" gorm:"index"`
	TargetIP   string    `json:"target_ip" gorm:"index:idx_pingstats_device_target,unique,priority:2"`
	MinLatency float64   `json:"min_latency"`
	MaxLatency float64   `json:"max_latency"`
	AvgLatency float64   `json:"avg_latency"`
	PacketLoss float64   `json:"packet_loss"`
	Samples    int       `json:"samples"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (SystemStatus) TableName() string     { return "system_status" }
func (InterfaceStats) TableName() string   { return "interface_stats" }
func (VPNStatus) TableName() string        { return "vpn_status" }
func (HAStatus) TableName() string         { return "ha_status" }
func (SecurityStats) TableName() string    { return "security_stats" }
func (SDWANHealth) TableName() string      { return "sdwan_health" }
func (LicenseInfo) TableName() string      { return "license_info" }
func (HardwareSensor) TableName() string   { return "hardware_sensors" }
func (TrapEvent) TableName() string        { return "trap_events" }
func (Alert) TableName() string            { return "alerts" }
func (UptimeRecord) TableName() string     { return "uptime_records" }
func (ProcessedBatch) TableName() string   { return "processed_batches" }
func (LoginAttempt) TableName() string     { return "login_attempts" }
func (Device) TableName() string           { return "devices" }
func (DeviceTunnel) TableName() string     { return "device_tunnels" }
func (DeviceConnection) TableName() string { return "device_connections" }
func (InterfaceAddress) TableName() string { return "interface_addresses" }
func (SystemSetting) TableName() string    { return "system_settings" }
func (Admin) TableName() string            { return "admins" }
func (Site) TableName() string             { return "sites" }
func (Probe) TableName() string            { return "probes" }
func (ProbeApproval) TableName() string    { return "probe_approvals" }
func (ProbeHeartbeat) TableName() string   { return "probe_heartbeats" }
func (PingResult) TableName() string       { return "ping_results" }
func (PingStats) TableName() string        { return "ping_stats" }

type SyslogMessage struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp" gorm:"index;index:idx_syslog_device_ts,priority:2"`
	DeviceID       uint      `json:"device_id" gorm:"index;index:idx_syslog_device_ts,priority:1"`
	ProbeID        uint      `json:"probe_id" gorm:"index"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"app_name"`
	ProcessID      string    `json:"process_id"`
	MessageID      string    `json:"message_id"`
	StructuredData string    `json:"structured_data"`
	Message        string    `json:"message"`
	Priority       int       `json:"priority"`
	Facility       int       `json:"facility"`
	Severity       int       `json:"severity" gorm:"index:idx_syslog_severity"`
	SourceIP       string    `json:"source_ip"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SyslogMessage) TableName() string { return "syslog_messages" }

type SyslogSummary struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp" gorm:"index;index:idx_syslog_summary_device_ts,priority:2"` // standalone + composite
	DeviceID       uint      `json:"device_id" gorm:"index:idx_syslog_summary_device_ts,priority:1"`
	IntervalType   string    `json:"interval_type" gorm:"size:4;index:idx_syslog_summary_interval,priority:1"` // "1h", "1d"
	Severity       int       `json:"severity" gorm:"index:idx_syslog_summary_severity"`                        // 6=Info, 7=Debug
	Facility       int       `json:"facility"`
	AppName        string    `json:"app_name"`        // first seen app name
	MessagePattern string    `json:"message_pattern"` // normalized message template
	Count          int64     `json:"count"`           // number of messages in this bucket
	SampleMessage  string    `json:"sample_message"`  // one example message for debugging
}

func (SyslogSummary) TableName() string { return "syslog_summaries" }

type FlowSample struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp" gorm:"index;index:idx_flow_device_ts,priority:2"`
	DeviceID       uint      `json:"device_id" gorm:"index;index:idx_flow_device_ts,priority:1"`
	ProbeID        uint      `json:"probe_id" gorm:"index"`
	SamplerAddress string    `json:"sampler_address"`
	SequenceNumber uint32    `json:"sequence_number"`
	SamplingRate   uint32    `json:"sampling_rate"`
	// AUDIT-034: idx_flow_src_addr / idx_flow_dst_addr back the connection
	// flow-stats queries, which filter with `src_addr LIKE ? OR dst_addr LIKE ?`
	// (cidrToLikePattern builds `192.168.1.%`-style prefixes). Without these
	// btree indexes every connection stats click was a full scan of
	// flow_samples. A prefix `LIKE 'x%'` is sargable on a btree, so these help
	// on both Postgres and SQLite.
	SrcAddr       string `json:"src_addr" gorm:"index:idx_flow_src_addr"`
	DstAddr       string `json:"dst_addr" gorm:"index:idx_flow_dst_addr"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	Protocol      uint8  `json:"protocol"`
	Bytes         uint64 `json:"bytes"`
	Packets       uint64 `json:"packets"`
	InputIfIndex  uint32 `json:"input_if_index"`
	OutputIfIndex uint32 `json:"output_if_index"`
	TCPFlags      uint8  `json:"tcp_flags"`
	// Drops is the sFlow v5 §3.1.1 sample-pool drops counter for this
	// individual sample (RFC 3176). Non-zero values indicate the agent
	// had to drop packets between this sample and the previous one
	// because it couldn't keep up. The CTO-loop audit (2026-06-22,
	// taocp [MEDIUM] #5 + consolidated C-3) found this field was being
	// read by the collector parser and discarded; the server now
	// persists it so aggregate `drops_last_5m` per agent can drive
	// alerts and NOC widgets. omitempty keeps the wire contract
	// forward-compatible: pre-adopting collectors that don't send the
	// field see no JSON key and continue to function unchanged.
	Drops     uint64    `json:"drops,omitempty" gorm:"column:drops;default:0;not null"`
	CreatedAt time.Time `json:"created_at"`
}

func (FlowSample) TableName() string { return "flow_samples" }

// AgentDrops is a rolling-window aggregate of sFlow agent drops, the
// running counter of packets the agent had to discard because it
// couldn't keep up with the sampled rate (sFlow v5 §3.1.1).
//
// One row per (agent, sampling_rate) tuple per minute-window (the
// caller buckets). The CTO-loop audit (2026-06-22, taocp [MEDIUM] #5
// + consolidated C-3) found this data was previously invisible —
// agent-side congestion was undetectable. Storing it here lets alert
// policies fire on `drops_last_5m` and surfaces it in the NOC strip.
//
// The flow_agent_drops table is intentionally NOT partitioned (see
// docs/SFLOW-NOC-REDESIGN-PLAN.md §6.2). Per-(agent, sampling_rate)
// row count is bounded by the number of monitored agents (typical
// deployments: tens to low hundreds); no monthly rollup needed.
type AgentDrops struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	AgentAddress string    `json:"agent_address" gorm:"size:64;index:idx_agent_drops_lookup,priority:1"`
	SamplingRate uint32    `json:"sampling_rate" gorm:"index:idx_agent_drops_lookup,priority:2"`
	WindowStart  time.Time `json:"window_start" gorm:"index:idx_agent_drops_lookup,priority:3;index:idx_agent_drops_window"`
	DropsCount   uint64    `json:"drops_count"`
	CreatedAt    time.Time `json:"created_at"`
}

func (AgentDrops) TableName() string { return "flow_agent_drops" }

type FlowRollup struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Timestamp       time.Time `json:"timestamp" gorm:"index:idx_rollup_lookup,priority:3;index:idx_rollup_interval_ts,priority:2"`
	DeviceID        uint      `json:"device_id" gorm:"index:idx_rollup_lookup,priority:1"`
	IntervalType    string    `json:"interval_type" gorm:"size:4;index:idx_rollup_lookup,priority:2;index:idx_rollup_interval_ts,priority:1"` // "5m","1h","1d"
	SrcAddr         string    `json:"src_addr"`
	DstAddr         string    `json:"dst_addr"`
	DstPort         uint16    `json:"dst_port"`
	Protocol        uint8     `json:"protocol"`
	BytesSum        uint64    `json:"bytes_sum"`
	PacketsSum      uint64    `json:"packets_sum"`
	FlowCount       int64     `json:"flow_count"`
	SamplingRateAvg float64   `json:"sampling_rate_avg"`
}

func (FlowRollup) TableName() string { return "flow_rollups" }

type SiteDatabase struct {
	ID           uint       `json:"id" gorm:"primaryKey"`
	SiteID       uint       `json:"site_id" gorm:"uniqueIndex;not null"`
	Site         *Site      `json:"site,omitempty" gorm:"foreignKey:SiteID"`
	DatabasePath string     `json:"database_path" gorm:"not null"`
	IsRemote     bool       `json:"is_remote" gorm:"default:false"`
	LastSync     *time.Time `json:"last_sync"`
	Status       string     `json:"status" gorm:"default:active"` // active, syncing, error
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (SiteDatabase) TableName() string { return "site_databases" }

type SiteDevice struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	LocalID        uint      `json:"local_id"` // ID from the site-specific database
	Name           string    `json:"name" gorm:"not null"`
	Hostname       string    `json:"hostname"`
	IPAddress      string    `json:"ip_address" gorm:"not null"`
	SNMPPort       int       `json:"snmp_port" gorm:"default:161"`
	SNMPCommunity  string    `json:"snmp_community"`
	SNMPVersion    string    `json:"snmp_version" gorm:"default:2c"`
	Enabled        bool      `json:"enabled" gorm:"default:true"`
	Location       string    `json:"location"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (SiteDevice) TableName() string { return "site_devices" }

type SiteSystemStatus struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	Timestamp      time.Time `json:"timestamp" gorm:"index"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	Hostname       string    `json:"hostname"`
	Version        string    `json:"version"`
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	MemoryTotal    uint64    `json:"memory_total"`
	DiskUsage      float64   `json:"disk_usage"`
	DiskTotal      uint64    `json:"disk_total"`
	SessionCount   int       `json:"session_count"`
	Uptime         uint64    `json:"uptime"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SiteSystemStatus) TableName() string { return "site_system_status" }

type SiteInterfaceStats struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	Timestamp      time.Time `json:"timestamp" gorm:"index"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	Name           string    `json:"name"`
	Index          int       `json:"index"`
	Type           int       `json:"type"`
	Speed          uint64    `json:"speed"`
	Status         string    `json:"status"`
	InBytes        uint64    `json:"in_bytes"`
	InPackets      uint64    `json:"in_packets"`
	InErrors       uint64    `json:"in_errors"`
	InDiscards     uint64    `json:"in_discards"`
	OutBytes       uint64    `json:"out_bytes"`
	OutPackets     uint64    `json:"out_packets"`
	OutErrors      uint64    `json:"out_errors"`
	OutDiscards    uint64    `json:"out_discards"`
	AdminStatus    string    `json:"admin_status"`
	Description    string    `json:"description"`
	Alias          string    `json:"alias"`
	MTU            int       `json:"mtu"`
	MACAddress     string    `json:"mac_address"`
	TypeName       string    `json:"type_name"`
	HighSpeed      uint64    `json:"high_speed"`
	VLANID         int       `json:"vlan_id"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SiteInterfaceStats) TableName() string { return "site_interface_stats" }

type SiteTrapEvent struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	Timestamp      time.Time `json:"timestamp" gorm:"index"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	SourceIP       string    `json:"source_ip"`
	TrapOID        string    `json:"trap_oid"`
	TrapType       string    `json:"trap_type"`
	Severity       string    `json:"severity"`
	Message        string    `json:"message"`
	Processed      bool      `json:"processed"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SiteTrapEvent) TableName() string { return "site_trap_events" }

type SiteAlert struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	Timestamp      time.Time `json:"timestamp" gorm:"index"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	AlertType      string    `json:"alert_type"`
	Severity       string    `json:"severity"`
	Message        string    `json:"message"`
	MetricName     string    `json:"metric_name"`
	Threshold      float64   `json:"threshold"`
	CurrentValue   float64   `json:"current_value"`
	Notified       bool      `json:"notified"`
	Acknowledged   bool      `json:"acknowledged"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SiteAlert) TableName() string { return "site_alerts" }

type SitePingResult struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	Timestamp      time.Time `json:"timestamp" gorm:"index"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	ProbeID        uint      `json:"probe_id" gorm:"index"`
	TargetIP       string    `json:"target_ip"`
	Success        bool      `json:"success"`
	Latency        float64   `json:"latency"`
	PacketLoss     float64   `json:"packet_loss"`
	TTL            int       `json:"ttl"`
	ErrorMessage   string    `json:"error_message"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SitePingResult) TableName() string { return "site_ping_results" }

type SitePingStats struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	ProbeID        uint      `json:"probe_id" gorm:"index"`
	TargetIP       string    `json:"target_ip"`
	MinLatency     float64   `json:"min_latency"`
	MaxLatency     float64   `json:"max_latency"`
	AvgLatency     float64   `json:"avg_latency"`
	PacketLoss     float64   `json:"packet_loss"`
	Samples        int       `json:"samples"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SitePingStats) TableName() string { return "site_ping_stats" }

type IRCServer struct {
	ID               uint         `json:"id" gorm:"primaryKey"`
	Name             string       `json:"name" gorm:"column:name;not null"`
	ServerHost       string       `json:"server_host" gorm:"column:server_host;not null"`
	ServerPort       int          `json:"server_port" gorm:"column:server_port;default:6667"`
	UseTLS           bool         `json:"use_tls" gorm:"column:use_tls;default:false"`
	Nick             string       `json:"nick" gorm:"column:nick;not null"`
	NickServPassword string       `json:"nickserv_password" gorm:"column:nickserv_password"`
	NickServIdentify bool         `json:"nickserv_identify" gorm:"column:nickserv_identify;default:false"`
	Username         string       `json:"username" gorm:"column:username"`
	RealName         string       `json:"real_name" gorm:"column:real_name"`
	ServerPassword   string       `json:"server_password" gorm:"column:server_password"`
	SASLEnabled      bool         `json:"sasl_enabled" gorm:"column:sasl_enabled;default:false"`
	SASLUsername     string       `json:"sasl_username" gorm:"column:sasl_username"`
	SASLPassword     string       `json:"sasl_password" gorm:"column:sasl_password"`
	Channels         []IRCChannel `json:"channels,omitempty" gorm:"foreignKey:ServerID"`
	Enabled          bool         `json:"enabled" gorm:"column:enabled;default:true"`
	Status           string       `json:"status" gorm:"column:status;default:disconnected"`
	LastConnected    *time.Time   `json:"last_connected" gorm:"column:last_connected"`
	LastError        string       `json:"last_error" gorm:"column:last_error"`
	AutoReconnect    bool         `json:"auto_reconnect" gorm:"column:auto_reconnect;default:true"`
	ReconnectDelay   int          `json:"reconnect_delay" gorm:"column:reconnect_delay;default:30"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

func (IRCServer) TableName() string { return "irc_servers" }

type IRCChannel struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	ServerID       uint       `json:"server_id" gorm:"column:server_id;not null;index"`
	Server         *IRCServer `json:"server,omitempty" gorm:"foreignKey:ServerID"`
	ChannelName    string     `json:"channel_name" gorm:"column:channel_name;not null"`
	ChannelKey     string     `json:"channel_key" gorm:"column:channel_key"`
	ChanServName   string     `json:"chanserv_name" gorm:"column:chanserv_name"`
	ChanServPass   string     `json:"chanserv_password" gorm:"column:chanserv_password"`
	ChanOperPass   string     `json:"chan_oper_pass" gorm:"column:chan_oper_pass"`
	AutoJoin       bool       `json:"auto_join" gorm:"column:auto_join;default:true"`
	SendAlerts     bool       `json:"send_alerts" gorm:"column:send_alerts;default:false"`
	SendStatus     bool       `json:"send_status" gorm:"column:send_status;default:false"`
	StatusInterval int        `json:"status_interval" gorm:"column:status_interval;default:300"`
	Enabled        bool       `json:"enabled" gorm:"column:enabled;default:true"`
	Status         string     `json:"status" gorm:"column:status;default:pending"`
	JoinedAt       *time.Time `json:"joined_at" gorm:"column:joined_at"`
	// AdminNicks is a semicolon-separated list of IRC nicks authorized to
	// execute commands with `AdminOnly: true` in this channel. AUDIT-019:
	// comparison is case-insensitive; an empty value means NO ONE (not even
	// the bot itself) can execute admin-only commands in the channel.
	// Examples: "alice;bob" or "ChanOp". Stored as a single text column
	// because the list is bounded (typically 1-5 entries per channel) and
	// a join table would be overkill for a feature most deployments
	// either don't use or use with 1-2 admins.
	AdminNicks string    `json:"admin_nicks" gorm:"column:admin_nicks;default:''"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (IRCChannel) TableName() string { return "irc_channels" }

type IRCCommand struct {
	ID          uint        `json:"id" gorm:"primaryKey"`
	Command     string      `json:"command" gorm:"not null;uniqueIndex"` // e.g., "!status", "!help", "!stats"
	Description string      `json:"description"`
	Response    string      `json:"response"`                           // Response template or command to execute
	CommandType CommandType `json:"command_type" gorm:"default:static"` // static, status, stats, custom
	Enabled     bool        `json:"enabled" gorm:"default:true"`
	AdminOnly   bool        `json:"admin_only" gorm:"default:false"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func (IRCCommand) TableName() string { return "irc_commands" }

type IRCMessageLog struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	ServerID    uint      `json:"server_id" gorm:"index"`
	Channel     string    `json:"channel"`
	Nick        string    `json:"nick"`
	Message     string    `json:"message"`
	MessageType string    `json:"message_type"` // message, action, notice, join, part, quit
	Timestamp   time.Time `json:"timestamp" gorm:"index"`
}

func (IRCMessageLog) TableName() string { return "irc_message_logs" }

type SiteSyslogMessage struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	SiteDatabaseID uint      `json:"site_database_id" gorm:"index;not null"`
	Timestamp      time.Time `json:"timestamp" gorm:"index"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	ProbeID        uint      `json:"probe_id" gorm:"index"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"app_name"`
	ProcessID      string    `json:"process_id"`
	MessageID      string    `json:"message_id"`
	StructuredData string    `json:"structured_data"`
	Message        string    `json:"message"`
	Priority       int       `json:"priority"`
	Facility       int       `json:"facility"`
	Severity       int       `json:"severity"`
	SourceIP       string    `json:"source_ip"`
	CreatedAt      time.Time `json:"created_at"`
}

func (SiteSyslogMessage) TableName() string { return "site_syslog_messages" }

func (s *SystemStatus) ToJSON() string {
	jsonBytes, err := json.Marshal(s)
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}

type DashboardData struct {
	Devices         []Device           `json:"devices"`
	SystemStatus    SystemStatus       `json:"system_status"`
	Interfaces      []InterfaceStats   `json:"interfaces"`
	VPNStatus       []VPNStatus        `json:"vpn_status"`
	HAStatus        *HAStatus          `json:"ha_status"`
	HardwareSensors []HardwareSensor   `json:"hardware_sensors"`
	RecentAlerts    []Alert            `json:"recent_alerts"`
	UptimeData      *UptimeRecord      `json:"uptime_data"`
	Connections     []DeviceConnection `json:"connections"`
}

// APIResponse and its constructors moved to internal/api/response (AUDIT-073) —
// HTTP transport types don't belong in the GORM model package.

type DeviceConfigRevision struct {
	ID                 uint      `json:"id" gorm:"primaryKey"`
	DeviceID           uint      `json:"device_id" gorm:"not null;index"`
	Timestamp          time.Time `json:"timestamp" gorm:"not null"`
	Checksum           string    `json:"checksum"`
	NormalizedChecksum string    `json:"normalized_checksum" gorm:"index"`
	ConfigText         string    `json:"config_text"`
	Length             int       `json:"length"`
	BackupQuality      string    `json:"backup_quality"`              // full | masked | suspect | unknown
	TriggerSource      string    `json:"trigger_source" gorm:"index"` // syslog | poll | manual

	// Merge-into-latest model (v0.10.198+): one row per logical config state.
	// FirstSeenAt is when this state was first observed; LastVerifiedAt is the
	// most recent backup that confirmed the state still holds; VerifyCount is
	// how many refreshes have confirmed it. Operators see "this state has been
	// current for X, last verified Y, confirmed Z times."
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
	VerifyCount    int       `json:"verify_count"`

	// Change attribution (v0.10.440+): who made the change, from where, and how,
	// correlated from FortiGate config-change syslog events at insert time.
	//
	// AttributionChecked records whether correlation was actually attempted for
	// this row — only true for a real insert-change. It disambiguates the two
	// reasons ChangedBy can be empty: a first-seen/merged row that was never
	// correlated (AttributionChecked=false → "unknown"), versus a real change
	// with no matching authenticated session (AttributionChecked=true,
	// Attributed=false → a possible out-of-band/unauthorized change).
	ChangedBy          string `json:"changed_by"`
	ChangedFrom        string `json:"changed_from"`  // source IP
	ChangeMethod       string `json:"change_method"` // GUI | CLI(ssh) | jsconsole | API
	Attributed         bool   `json:"attributed"`
	AttributionChecked bool   `json:"attribution_checked"`
}

type ProcessStats struct {
	ID        uint          `json:"id" gorm:"primaryKey"`
	Timestamp time.Time     `json:"timestamp" gorm:"index:idx_procstats_device_ts,priority:2"`
	DeviceID  uint          `json:"device_id" gorm:"index;index:idx_procstats_device_ts,priority:1"`
	Processes []ProcessInfo `json:"processes" gorm:"serializer:json"`
}

type ProcessInfo struct {
	Name    string  `json:"name"`
	PID     int     `json:"pid"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"mem"`
	Command string  `json:"command"`
}

type InterfaceErrors struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp" gorm:"index:idx_ifaceerr_device_ts,priority:2"`
	DeviceID    uint      `json:"device_id" gorm:"index;index:idx_ifaceerr_device_ts,priority:1"`
	Interface   string    `json:"interface"`
	InErrors    uint64    `json:"in_errors"`
	InDiscards  uint64    `json:"in_discards"`
	OutErrors   uint64    `json:"out_errors"`
	OutDiscards uint64    `json:"out_discards"`
}
