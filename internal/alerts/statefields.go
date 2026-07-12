package alerts

import "fmt"

// State-event field extraction for source="state" Event Rules. These are the
// fields a rule's match expression can scope/suppress on (interface_name,
// tunnel_name, event_type, vendor, …) — NOT the fire decision, which the
// state evaluator owns. Mirrors internal/alerts/logfields for syslog.

// State event types.
const (
	StateEventInterfaceDown = "interface_down"
	StateEventVPNDown       = "vpn_tunnel_down"
	StateEventDeviceOffline = "device_offline" // Phase 3
)

// Metric event types (source="metric"). Phase 2 ships these as the scoping
// vocabulary for the seeded CPU/mem/disk/session templates + validation; the
// metric evaluator that matches on them lands in Phase 4 (until then the legacy
// CheckSystemStatus path drives these alerts). One event_type per system metric,
// mirroring the AlertType.
const (
	MetricEventCPU      = "cpu_high"
	MetricEventMemory   = "memory_high"
	MetricEventDisk     = "disk_high"
	MetricEventSessions = "sessions_high"
)

// interfaceStateFields builds the matchable field set for a down interface.
func interfaceStateFields(deviceID uint, ifaceName, adminStatus, vendor string) map[string]string {
	return map[string]string{
		"event_type":     StateEventInterfaceDown,
		"interface_name": ifaceName,
		"admin_status":   adminStatus,
		"vendor":         vendor,
		"device_id":      fmt.Sprintf("%d", deviceID),
	}
}

// vpnStateFields builds the matchable field set for a down VPN tunnel.
func vpnStateFields(deviceID uint, tunnelName, vendor string) map[string]string {
	return map[string]string{
		"event_type":  StateEventVPNDown,
		"tunnel_name": tunnelName,
		"vendor":      vendor,
		"device_id":   fmt.Sprintf("%d", deviceID),
	}
}
