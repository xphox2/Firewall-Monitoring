package models

import (
	"encoding/json"
	"time"
)

type SystemStatus struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id" gorm:"index"`
	Hostname     string    `json:"hostname"`
	Version      string    `json:"version"`
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  float64   `json:"memory_usage"`
	MemoryTotal  uint64    `json:"memory_total"`
	DiskUsage    float64   `json:"disk_usage"`
	DiskTotal    uint64    `json:"disk_total"`
	SessionCount int       `json:"session_count"`
	Uptime       uint64    `json:"uptime"`
}

type InterfaceStats struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id" gorm:"index"`
	Name        string    `json:"name"`
	Index       int       `json:"index"`
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
}

type VPNStatus struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id" gorm:"index"`
	TunnelName  string    `json:"tunnel_name"`
	RemoteIP    string    `json:"remote_ip"`
	Status      string    `json:"status"`
	BytesIn     uint64    `json:"bytes_in"`
	BytesOut    uint64    `json:"bytes_out"`
	PacketsIn   uint64    `json:"packets_in"`
	PacketsOut  uint64    `json:"packets_out"`
	State       string    `json:"state"`
}

type HAStatus struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Timestamp       time.Time `json:"timestamp"`
	DeviceID        uint      `json:"device_id" gorm:"index"`
	ClusterName     string    `json:"cluster_name"`
	Mode            string    `json:"mode"`
	MasterIP        string    `json:"master_ip"`
	SlaveIP         string    `json:"slave_ip"`
	MasterPriority  int       `json:"master_priority"`
	SlavePriority   int       `json:"slave_priority"`
	HeartbeatStatus string    `json:"heartbeat_status"`
	SyncStatus      string    `json:"sync_status"`
}

type HardwareSensor struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id" gorm:"index"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Value       float64   `json:"value"`
	Status      string    `json:"status"`
	Unit        string    `json:"unit"`
}

type TrapEvent struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id" gorm:"index"`
	ProbeID     uint      `json:"probe_id" gorm:"index"`
	SourceIP    string    `json:"source_ip"`
	TrapOID     string    `json:"trap_oid"`
	TrapType    string    `json:"trap_type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Processed   bool      `json:"processed"`
}

type Alert struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id" gorm:"index"`
	AlertType    string    `json:"alert_type"`
	Severity     string    `json:"severity"`
	Message      string    `json:"message"`
	MetricName   string    `json:"metric_name"`
	Threshold    float64   `json:"threshold"`
	CurrentValue float64   `json:"current_value"`
	Notified     bool      `json:"notified"`
	Acknowledged bool      `json:"acknowledged"`
}

type UptimeRecord struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id" gorm:"index"`
	DeviceUptime   uint64    `json:"device_uptime"`
	TotalDowntime  float64   `json:"total_downtime_seconds"`
	UptimePercent  float64   `json:"uptime_percent"`
	DowntimeEvents int       `json:"downtime_events"`
}

type LoginAttempt struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	IPAddress string    `json:"ip_address"`
	Success   bool      `json:"success"`
	UserAgent string    `json:"user_agent"`
}

type Device struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	Name          string    `json:"name" gorm:"uniqueIndex;not null"`
	Hostname      string    `json:"hostname"`
	IPAddress     string    `json:"ip_address" gorm:"not null"`
	SNMPPort      int       `json:"snmp_port" gorm:"default:161"`
	SNMPCommunity string    `json:"snmp_community" gorm:"default:public"`
	SNMPVersion   string    `json:"snmp_version" gorm:"default:2c"`
	Enabled       bool      `json:"enabled" gorm:"default:true"`
	SiteID        *uint     `json:"site_id" gorm:"index"`
	Site          *Site     `json:"site,omitempty" gorm:"foreignKey:SiteID"`
	ProbeID       *uint     `json:"probe_id" gorm:"index"`
	Probe         *Probe    `json:"probe,omitempty" gorm:"foreignKey:ProbeID"`
	Location      string    `json:"location"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastPolled    time.Time `json:"last_polled"`
	Status        string    `json:"status" gorm:"default:unknown"`
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
	ID             uint       `json:"id" gorm:"primaryKey"`
	Name           string     `json:"name" gorm:"not null"`
	SourceDeviceID uint       `json:"source_device_id" gorm:"not null;index"`
	SourceDevice   *Device    `json:"source_device,omitempty" gorm:"foreignKey:SourceDeviceID"`
	SourceTunnelID uint       `json:"source_tunnel_id"`
	DestDeviceID   uint       `json:"dest_device_id" gorm:"not null;index"`
	DestDevice     *Device    `json:"dest_device,omitempty" gorm:"foreignKey:DestDeviceID"`
	DestTunnelID   uint       `json:"dest_tunnel_id"`
	ConnectionType string     `json:"connection_type" gorm:"default:ipsec"`
	Status         string     `json:"status" gorm:"default:unknown"`
	Latency        float64    `json:"latency"`
	LastCheck      time.Time  `json:"last_check"`
	Notes          string     `json:"notes"`
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
	ID        uint      `json:"id" gorm:"primaryKey"`
	Username  string    `json:"username" gorm:"uniqueIndex;not null"`
	Password  string    `json:"-" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	ID              uint       `json:"id" gorm:"primaryKey"`
	Name            string     `json:"name" gorm:"uniqueIndex;not null"`
	SiteID          uint       `json:"site_id" gorm:"index"`
	Site            *Site      `json:"site,omitempty" gorm:"foreignKey:SiteID"`
	RegistrationKey string     `json:"registration_key" gorm:"uniqueIndex"`
	Enabled         bool       `json:"enabled" gorm:"default:true"`
	Status          string     `json:"status" gorm:"default:pending"`
	ApprovalStatus  string     `json:"approval_status" gorm:"default:pending"`
	ApprovedAt      *time.Time `json:"approved_at"`
	ApprovedBy      *uint      `json:"approved_by"`
	RejectedAt      *time.Time `json:"rejected_at"`
	RejectedReason  string     `json:"rejected_reason"`
	LastSeen        time.Time  `json:"last_seen"`
	ListenAddress   string     `json:"listen_address"`
	ListenPort      int        `json:"listen_port" gorm:"default:8089"`
	TLSCertPath     string     `json:"tls_cert_path"`
	TLSKeyPath      string     `json:"tls_key_path"`
	ServerURL       string     `json:"server_url"`
	ServerTLSCert   string     `json:"server_tls_cert"`
	Description     string     `json:"description"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
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
	ProbeID   uint      `json:"probe_id" gorm:"index;not null"`
	Probe     *Probe    `json:"probe,omitempty" gorm:"foreignKey:ProbeID"`
	Status    string    `json:"status"` // online, offline
	IPAddress string    `json:"ip_address"`
	Version   string    `json:"version"`
	Uptime    uint64    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
}

type PingResult struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Timestamp    time.Time `json:"timestamp" gorm:"index"`
	DeviceID     uint      `json:"device_id" gorm:"index"`
	ProbeID      uint      `json:"probe_id" gorm:"index"`
	TargetIP     string    `json:"target_ip"`
	Success      bool      `json:"success"`
	Latency      float64   `json:"latency"`
	PacketLoss   float64   `json:"packet_loss"`
	TTL          int       `json:"ttl"`
	ErrorMessage string    `json:"error_message"`
}

type PingStats struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	DeviceID    uint      `json:"device_id" gorm:"index"`
	ProbeID     uint      `json:"probe_id" gorm:"index"`
	TargetIP    string    `json:"target_ip"`
	MinLatency  float64   `json:"min_latency"`
	MaxLatency  float64   `json:"max_latency"`
	AvgLatency  float64   `json:"avg_latency"`
	PacketLoss  float64   `json:"packet_loss"`
	Samples     int       `json:"samples"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (SystemStatus) TableName() string        { return "system_status" }
func (InterfaceStats) TableName() string      { return "interface_stats" }
func (VPNStatus) TableName() string           { return "vpn_status" }
func (HAStatus) TableName() string            { return "ha_status" }
func (HardwareSensor) TableName() string      { return "hardware_sensors" }
func (TrapEvent) TableName() string           { return "trap_events" }
func (Alert) TableName() string               { return "alerts" }
func (UptimeRecord) TableName() string        { return "uptime_records" }
func (LoginAttempt) TableName() string        { return "login_attempts" }
func (Device) TableName() string              { return "devices" }
func (DeviceTunnel) TableName() string        { return "device_tunnels" }
func (DeviceConnection) TableName() string    { return "device_connections" }
func (SystemSetting) TableName() string       { return "system_settings" }
func (Admin) TableName() string               { return "admins" }
func (Site) TableName() string                { return "sites" }
func (Probe) TableName() string               { return "probes" }
func (ProbeApproval) TableName() string       { return "probe_approvals" }
func (ProbeHeartbeat) TableName() string      { return "probe_heartbeats" }
func (PingResult) TableName() string          { return "ping_results" }
func (PingStats) TableName() string           { return "ping_stats" }

type SyslogMessage struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
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

func (SyslogMessage) TableName() string { return "syslog_messages" }

type FlowSample struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Timestamp       time.Time `json:"timestamp" gorm:"index"`
	DeviceID        uint      `json:"device_id" gorm:"index"`
	ProbeID         uint      `json:"probe_id" gorm:"index"`
	SamplerAddress  string    `json:"sampler_address"`
	SequenceNumber  uint32    `json:"sequence_number"`
	SamplingRate    uint32    `json:"sampling_rate"`
	SrcAddr         string    `json:"src_addr"`
	DstAddr         string    `json:"dst_addr"`
	SrcPort         uint16    `json:"src_port"`
	DstPort         uint16    `json:"dst_port"`
	Protocol        uint8     `json:"protocol"`
	Bytes           uint64    `json:"bytes"`
	Packets         uint64    `json:"packets"`
	InputIfIndex    uint32    `json:"input_if_index"`
	OutputIfIndex   uint32    `json:"output_if_index"`
	TCPFlags        uint8     `json:"tcp_flags"`
	CreatedAt       time.Time `json:"created_at"`
}

func (FlowSample) TableName() string { return "flow_samples" }

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
	SNMPCommunity  string    `json:"snmp_community" gorm:"default:public"`
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
	Devices         []Device              `json:"devices"`
	SystemStatus    SystemStatus          `json:"system_status"`
	Interfaces      []InterfaceStats      `json:"interfaces"`
	VPNStatus       []VPNStatus           `json:"vpn_status"`
	HAStatus        *HAStatus             `json:"ha_status"`
	HardwareSensors []HardwareSensor      `json:"hardware_sensors"`
	RecentAlerts    []Alert               `json:"recent_alerts"`
	UptimeData      *UptimeRecord         `json:"uptime_data"`
	Connections     []DeviceConnection    `json:"connections"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

func SuccessResponse(data interface{}) APIResponse {
	return APIResponse{
		Success: true,
		Data:    data,
	}
}

func ErrorResponse(err string) APIResponse {
	return APIResponse{
		Success: false,
		Error:   err,
	}
}

func MessageResponse(msg string) APIResponse {
	return APIResponse{
		Success: true,
		Message: msg,
	}
}
