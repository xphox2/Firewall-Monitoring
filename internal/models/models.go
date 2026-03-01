package models

import (
	"encoding/json"
	"time"
)

type SystemStatus struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Timestamp    time.Time `json:"timestamp"`
	FortiGateID  uint      `json:"fortigate_id" gorm:"index"`
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
	FortiGateID uint      `json:"fortigate_id" gorm:"index"`
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
	FortiGateID uint      `json:"fortigate_id" gorm:"index"`
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
	FortiGateID     uint      `json:"fortigate_id" gorm:"index"`
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
	FortiGateID uint      `json:"fortigate_id" gorm:"index"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Value       float64   `json:"value"`
	Status      string    `json:"status"`
	Unit        string    `json:"unit"`
}

type TrapEvent struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Timestamp   time.Time `json:"timestamp"`
	FortiGateID uint      `json:"fortigate_id" gorm:"index"`
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
	FortiGateID  uint      `json:"fortigate_id" gorm:"index"`
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
	FortiGateID    uint      `json:"fortigate_id" gorm:"index"`
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

type FortiGate struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	Name          string    `json:"name" gorm:"uniqueIndex;not null"`
	Hostname      string    `json:"hostname"`
	IPAddress     string    `json:"ip_address" gorm:"not null"`
	SNMPPort      int       `json:"snmp_port" gorm:"default:161"`
	SNMPCommunity string    `json:"snmp_community" gorm:"default:public"`
	SNMPVersion   string    `json:"snmp_version" gorm:"default:2c"`
	Enabled       bool      `json:"enabled" gorm:"default:true"`
	Location      string    `json:"location"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastPolled    time.Time `json:"last_polled"`
	Status        string    `json:"status" gorm:"default:unknown"`
}

type FortiGateTunnel struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	FortiGateID   uint      `json:"fortigate_id" gorm:"not null;index"`
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

type FortiGateConnection struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	Name           string     `json:"name" gorm:"not null"`
	SourceFGID     uint       `json:"source_fg_id" gorm:"not null;index"`
	SourceFG       *FortiGate `json:"source_fg,omitempty" gorm:"foreignKey:SourceFGID"`
	SourceTunnelID uint       `json:"source_tunnel_id"`
	DestFGID       uint       `json:"dest_fg_id" gorm:"not null;index"`
	DestFG         *FortiGate `json:"dest_fg,omitempty" gorm:"foreignKey:DestFGID"`
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

func (SystemStatus) TableName() string        { return "system_status" }
func (InterfaceStats) TableName() string      { return "interface_stats" }
func (VPNStatus) TableName() string           { return "vpn_status" }
func (HAStatus) TableName() string            { return "ha_status" }
func (HardwareSensor) TableName() string      { return "hardware_sensors" }
func (TrapEvent) TableName() string           { return "trap_events" }
func (Alert) TableName() string               { return "alerts" }
func (UptimeRecord) TableName() string        { return "uptime_records" }
func (LoginAttempt) TableName() string        { return "login_attempts" }
func (FortiGate) TableName() string           { return "fortigates" }
func (FortiGateTunnel) TableName() string     { return "fortigate_tunnels" }
func (FortiGateConnection) TableName() string { return "fortigate_connections" }
func (SystemSetting) TableName() string       { return "system_settings" }
func (Admin) TableName() string               { return "admins" }

func (s *SystemStatus) ToJSON() string {
	jsonBytes, _ := json.Marshal(s)
	return string(jsonBytes)
}

type DashboardData struct {
	FortiGates      []FortiGate           `json:"fortigates"`
	SystemStatus    SystemStatus          `json:"system_status"`
	Interfaces      []InterfaceStats      `json:"interfaces"`
	VPNStatus       []VPNStatus           `json:"vpn_status"`
	HAStatus        *HAStatus             `json:"ha_status"`
	HardwareSensors []HardwareSensor      `json:"hardware_sensors"`
	RecentAlerts    []Alert               `json:"recent_alerts"`
	UptimeData      *UptimeRecord         `json:"uptime_data"`
	Connections     []FortiGateConnection `json:"connections"`
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
