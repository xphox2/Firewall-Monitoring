package snmp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// FortiGate-specific SNMP OIDs (Fortinet enterprise MIB 1.3.6.1.4.1.12356)
var (
	fgOIDSystemCPU       = ".1.3.6.1.4.1.12356.101.4.1.3.0"
	fgOIDSystemMemory    = ".1.3.6.1.4.1.12356.101.4.1.4.0"
	fgOIDSystemMemoryCap = ".1.3.6.1.4.1.12356.101.4.1.5.0"
	fgOIDSystemDisk      = ".1.3.6.1.4.1.12356.101.4.1.6.0"
	fgOIDSystemDiskCap   = ".1.3.6.1.4.1.12356.101.4.1.7.0"
	fgOIDSystemSessions  = ".1.3.6.1.4.1.12356.101.4.1.8.0"
	fgOIDSystemUptime    = ".1.3.6.1.4.1.12356.101.4.1.20.0"
	fgOIDSystemVersion   = ".1.3.6.1.4.1.12356.101.4.1.1.0"
	fgOIDSystemHostname  = ".1.3.6.1.4.1.12356.101.4.1.2.0"

	fgBaseOIDVPNTunnel       = ".1.3.6.1.4.1.12356.101.12.2.2.1"
	fgOIDVPNTunnelPhase1Name = ".1.3.6.1.4.1.12356.101.12.2.2.1.2"
	fgOIDVPNTunnelName       = ".1.3.6.1.4.1.12356.101.12.2.2.1.3"
	fgOIDVPNTunnelRemoteGW   = ".1.3.6.1.4.1.12356.101.12.2.2.1.4"
	// Phase 2 selectors - source (local) subnet
	fgOIDVPNTunnelSrcBeginIP = ".1.3.6.1.4.1.12356.101.12.2.2.1.8"  // Source selector begin IP
	fgOIDVPNTunnelSrcEndIP   = ".1.3.6.1.4.1.12356.101.12.2.2.1.9"  // Source selector end IP
	fgOIDVPNTunnelSrcMask    = ".1.3.6.1.4.1.12356.101.12.2.2.1.10" // Source subnet mask
	// Phase 2 selectors - destination (remote) subnet
	fgOIDVPNTunnelDstBeginIP = ".1.3.6.1.4.1.12356.101.12.2.2.1.11" // Destination selector begin IP
	fgOIDVPNTunnelDstEndIP   = ".1.3.6.1.4.1.12356.101.12.2.2.1.12" // Destination selector end IP
	fgOIDVPNTunnelDstMask    = ".1.3.6.1.4.1.12356.101.12.2.2.1.13" // Destination subnet mask
	fgOIDVPNTunnelInOctets   = ".1.3.6.1.4.1.12356.101.12.2.2.1.18"
	fgOIDVPNTunnelOutOctets  = ".1.3.6.1.4.1.12356.101.12.2.2.1.19"
	fgOIDVPNTunnelStatus     = ".1.3.6.1.4.1.12356.101.12.2.2.1.20"
	fgOIDVPNTunnelUpTime     = ".1.3.6.1.4.1.12356.101.12.2.2.1.21"

	fgOIDHWSensorEntry = ".1.3.6.1.4.1.12356.101.4.3.2.1"
	fgOIDHWSensorName  = ".1.3.6.1.4.1.12356.101.4.3.2.1.2"
	fgOIDHWSensorValue = ".1.3.6.1.4.1.12356.101.4.3.2.1.3"
	fgOIDHWSensorAlarm = ".1.3.6.1.4.1.12356.101.4.3.2.1.4"

	fgBaseOIDProcessor  = ".1.3.6.1.4.1.12356.101.4.4.2.1"
	fgOIDProcessorUsage = ".1.3.6.1.4.1.12356.101.4.4.2.1.2"

	fgOIDHaTable = ".1.3.6.1.4.1.12356.101.13.2.1"

	fgTrapVPNTunnelUp   = ".1.3.6.1.4.1.12356.101.2.0.301"
	fgTrapVPNTunnelDown = ".1.3.6.1.4.1.12356.101.2.0.302"
	fgTrapHASwitch      = ".1.3.6.1.4.1.12356.101.2.0.401"
	fgTrapHAStateChange = ".1.3.6.1.4.1.12356.101.2.0.402"
	fgTrapHAHBFail      = ".1.3.6.1.4.1.12356.101.2.0.403"
	fgTrapHAMemberDown  = ".1.3.6.1.4.1.12356.101.2.0.404"
	fgTrapHAMemberUp    = ".1.3.6.1.4.1.12356.101.2.0.405"
	fgTrapIPSSignature  = ".1.3.6.1.4.1.12356.101.2.0.503"
	fgTrapIPSAnomaly    = ".1.3.6.1.4.1.12356.101.2.0.504"
	fgTrapAVVirus       = ".1.3.6.1.4.1.12356.101.2.0.601"
	fgTrapAVOversize    = ".1.3.6.1.4.1.12356.101.2.0.602"
)

// FortiGateProfile implements VendorProfile for FortiGate devices.
type FortiGateProfile struct{}

func init() {
	RegisterVendor(&FortiGateProfile{})
}

func (f *FortiGateProfile) Name() string { return "fortigate" }

func (f *FortiGateProfile) SystemOIDs() []string {
	return []string{
		fgOIDSystemHostname,
		fgOIDSystemVersion,
		fgOIDSystemCPU,
		fgOIDSystemMemory,
		fgOIDSystemMemoryCap,
		fgOIDSystemDisk,
		fgOIDSystemDiskCap,
		fgOIDSystemSessions,
		fgOIDSystemUptime,
	}
}

func (f *FortiGateProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *models.SystemStatus {
	status := &models.SystemStatus{Timestamp: time.Now()}
	var rawDiskMB, rawDiskCapMB int64
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case fgOIDSystemHostname:
			status.Hostname = safeString(pdu.Value)
		case fgOIDSystemVersion:
			status.Version = safeString(pdu.Value)
		case fgOIDSystemCPU:
			status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemMemory:
			status.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemMemoryCap:
			status.MemoryTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case fgOIDSystemDisk:
			rawDiskMB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fgOIDSystemDiskCap:
			rawDiskCapMB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fgOIDSystemSessions:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemUptime:
			status.Uptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}
	// fgSysDiskUsage/fgSysDiskCapacity are in MB — compute percentage
	if rawDiskCapMB > 0 {
		status.DiskUsage = float64(rawDiskMB) / float64(rawDiskCapMB) * 100
	}
	status.DiskTotal = uint64(rawDiskCapMB)
	return status
}

func (f *FortiGateProfile) VPNBaseOID() string { return fgBaseOIDVPNTunnel }

func (f *FortiGateProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	tunnelMap := make(map[int]*models.VPNStatus)
	// Temporary storage for Phase 2 subnet selectors (source=destination=local, dest=remote)
	srcBeginIPs := make(map[int]string)
	srcEndIPs := make(map[int]string)
	srcMasks := make(map[int]string)
	dstBeginIPs := make(map[int]string)
	dstEndIPs := make(map[int]string)
	dstMasks := make(map[int]string)

	for _, pdu := range pdus {
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDVPNTunnelPhase1Name+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelPhase1Name)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.Phase1Name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNTunnelName+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelName)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelName = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNTunnelRemoteGW+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelRemoteGW)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.RemoteIP = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNTunnelSrcBeginIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelSrcBeginIP)
			if idx >= 0 {
				srcBeginIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelSrcEndIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelSrcEndIP)
			if idx >= 0 {
				srcEndIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelSrcMask+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelSrcMask)
			if idx >= 0 {
				srcMasks[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelDstBeginIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelDstBeginIP)
			if idx >= 0 {
				dstBeginIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelDstEndIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelDstEndIP)
			if idx >= 0 {
				dstEndIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelDstMask+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelDstMask)
			if idx >= 0 {
				dstMasks[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelInOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelInOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNTunnelOutOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelOutOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNTunnelStatus+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelStatus)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			statusVal := gosnmp.ToBigInt(pdu.Value).Int64()
			if statusVal == 2 {
				t.Status = "up"
				t.State = "active"
			} else {
				t.Status = "down"
				t.State = "inactive"
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelUpTime+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelUpTime)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelUptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	result := make([]models.VPNStatus, 0, len(tunnelMap))
	for idx, t := range tunnelMap {
		t.Timestamp = now
		// Build Local Subnet (Phase 2 source selector) — CIDR if mask available
		srcBegin := srcBeginIPs[idx]
		srcMask := srcMasks[idx]
		if cidr := buildCIDR(srcBegin, srcMask); cidr != "" {
			t.LocalSubnet = cidr
		} else if srcBegin != "" {
			srcEnd := srcEndIPs[idx]
			if srcEnd != "" && srcEnd != srcBegin {
				t.LocalSubnet = srcBegin + " - " + srcEnd
			} else {
				t.LocalSubnet = srcBegin
			}
		}
		// Build Remote Subnet (Phase 2 destination selector) — CIDR if mask available
		dstBegin := dstBeginIPs[idx]
		dstMask := dstMasks[idx]
		if cidr := buildCIDR(dstBegin, dstMask); cidr != "" {
			t.RemoteSubnet = cidr
		} else if dstBegin != "" {
			dstEnd := dstEndIPs[idx]
			if dstEnd != "" && dstEnd != dstBegin {
				t.RemoteSubnet = dstBegin + " - " + dstEnd
			} else {
				t.RemoteSubnet = dstBegin
			}
		}
		result = append(result, *t)
	}
	return result
}

// buildCIDR combines an IP address and subnet mask into CIDR notation (e.g., "10.0.0.0/24").
func buildCIDR(addr, mask string) string {
	if addr == "" {
		return ""
	}
	// Wildcard selector: 0.0.0.0/0.0.0.0 → "0.0.0.0/0" (Phase 2 "any" selector)
	if addr == "0.0.0.0" {
		if mask == "" || mask == "0.0.0.0" {
			return "0.0.0.0/0"
		}
		return ""
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if mask == "" || mask == "0.0.0.0" {
		return addr
	}
	m := net.ParseIP(mask)
	if m == nil {
		return addr
	}
	ones, _ := net.IPMask(m.To4()).Size()
	return fmt.Sprintf("%s/%d", addr, ones)
}

func (f *FortiGateProfile) HWSensorBaseOID() string { return fgOIDHWSensorEntry }

func (f *FortiGateProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []models.HardwareSensor {
	sensorMap := make(map[int]*models.HardwareSensor)
	for _, pdu := range pdus {
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDHWSensorName+".") {
			idx := getIndexFromOID(name, fgOIDHWSensorName)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			sensor.Name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDHWSensorValue+".") {
			idx := getIndexFromOID(name, fgOIDHWSensorValue)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			// fgHwSensorEntValue is a DisplayString ("52.500000"); parse it as
			// a float — gosnmp.ToBigInt would return 0 for the []byte/decimal.
			sensor.Value = safeFloat(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDHWSensorAlarm+".") {
			idx := getIndexFromOID(name, fgOIDHWSensorAlarm)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			alarm := gosnmp.ToBigInt(pdu.Value).Int64()
			if alarm == 0 {
				sensor.Status = "normal"
			} else {
				sensor.Status = "alarm"
			}
		}
	}

	now := time.Now()
	sensors := make([]models.HardwareSensor, 0, len(sensorMap))
	for _, sensor := range sensorMap {
		sensor.Timestamp = now
		inferSensorUnit(sensor)
		sensors = append(sensors, *sensor)
	}
	return sensors
}

// inferSensorUnit sets Type and Unit based on FortiGate sensor name patterns.
// FortiGate's fgHwSensorTable carries no unit/type column, so we derive them
// from the sensor name. Kept in sync with the collector's identical helper
// (Firewall-Collector internal/snmp/vendor_fortigate.go) so directly-polled and
// probe-collected FortiGates render the same Unit/Type on the device page.
func inferSensorUnit(s *models.HardwareSensor) {
	lower := strings.ToLower(s.Name)
	switch {
	case strings.Contains(lower, "temp") || strings.Contains(lower, "dts") || strings.Contains(lower, "lm75"):
		s.Type = "temperature"
		s.Unit = "°C"
	case strings.Contains(lower, "fan"):
		s.Type = "fan"
		s.Unit = "RPM"
	case strings.Contains(lower, "vcc") || strings.Contains(lower, "vdd") ||
		strings.Contains(lower, "+1.") || strings.Contains(lower, "+2.") ||
		strings.Contains(lower, "+3.") || strings.Contains(lower, "+5.") ||
		strings.Contains(lower, "+12") || strings.Contains(lower, "volt"):
		s.Type = "voltage"
		// fgHwSensorEntValue is a DisplayString in VOLTS (e.g. "12.07"), not
		// millivolts. Twin of the collector's inferSensorUnit (AUDIT-301).
		s.Unit = "V"
	case strings.Contains(lower, "ps") && strings.Contains(lower, "status"):
		s.Type = "power"
		s.Unit = ""
	}
}

func (f *FortiGateProfile) ProcessorBaseOID() string { return fgBaseOIDProcessor }

func (f *FortiGateProfile) ParseProcessors(pdus []gosnmp.SnmpPDU) []models.ProcessorStats {
	now := time.Now()
	var result []models.ProcessorStats
	for _, pdu := range pdus {
		if strings.HasPrefix(pdu.Name, fgOIDProcessorUsage+".") {
			idx := getIndexFromOID(pdu.Name, fgOIDProcessorUsage)
			if idx < 0 {
				continue
			}
			result = append(result, models.ProcessorStats{
				Timestamp: now,
				Index:     idx,
				Usage:     float64(gosnmp.ToBigInt(pdu.Value).Int64()),
			})
		}
	}
	return result
}

func (f *FortiGateProfile) HABaseOID() string { return fgOIDHaTable }

func (f *FortiGateProfile) ParseHAStatus(pdus []gosnmp.SnmpPDU) []models.HAStatus {
	// HA parsing uses scalar OIDs, not walk data — return empty for now
	// The current codebase doesn't actively poll HA via walk
	return nil
}

func (f *FortiGateProfile) TrapOIDs() map[string]TrapDef {
	return map[string]TrapDef{
		fgTrapVPNTunnelUp:   {Type: "VPN_TUNNEL_UP", Severity: "info"},
		fgTrapVPNTunnelDown: {Type: "VPN_TUNNEL_DOWN", Severity: "critical"},
		fgTrapHASwitch:      {Type: "HA_SWITCH", Severity: "warning"},
		fgTrapHAStateChange: {Type: "HA_STATE_CHANGE", Severity: "warning"},
		fgTrapHAHBFail:      {Type: "HA_HEARTBEAT_FAIL", Severity: "critical"},
		fgTrapHAMemberDown:  {Type: "HA_MEMBER_DOWN", Severity: "critical"},
		fgTrapHAMemberUp:    {Type: "HA_MEMBER_UP", Severity: "info"},
		fgTrapIPSSignature:  {Type: "IPS_SIGNATURE", Severity: "critical"},
		fgTrapIPSAnomaly:    {Type: "IPS_ANOMALY", Severity: "critical"},
		fgTrapAVVirus:       {Type: "AV_VIRUS", Severity: "critical"},
		fgTrapAVOversize:    {Type: "AV_OVERSIZE", Severity: "info"},
	}
}

type FortiGateVxlan struct {
	Name            string
	Interface       string
	VXLANID         int
	DestinationPort int
	RemoteIPs       []string // VTEP peer IPs (set remote-ip "a" "b" ...)
}

func ParseFortiGateVxlanConfig(configText string) []FortiGateVxlan {
	var vxlans []FortiGateVxlan
	if configText == "" {
		return vxlans
	}

	var currentEdit string
	var currentVxlan FortiGateVxlan
	inVxlanBlock := false
	inVxlanEdit := false

	lines := strings.Split(configText, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "config system vxlan") {
			inVxlanBlock = true
			continue
		}

		if inVxlanBlock && strings.HasPrefix(line, "end") {
			if inVxlanEdit && currentEdit != "" {
				vxlans = append(vxlans, currentVxlan)
			}
			break
		}

		if inVxlanBlock {
			if strings.HasPrefix(line, "edit ") {
				if inVxlanEdit && currentEdit != "" {
					vxlans = append(vxlans, currentVxlan)
				}
				currentEdit = strings.Trim(strings.TrimPrefix(line, "edit "), "\"")
				currentVxlan = FortiGateVxlan{Name: currentEdit}
				inVxlanEdit = true
				continue
			}

			if inVxlanEdit {
				if strings.HasPrefix(line, "set interface ") {
					currentVxlan.Interface = strings.Trim(strings.TrimPrefix(line, "set interface "), "\"")
					continue
				}
				if strings.HasPrefix(line, "set vxlan-id ") {
					if vxlanID, err := strconv.Atoi(strings.TrimPrefix(line, "set vxlan-id ")); err == nil {
						currentVxlan.VXLANID = vxlanID
					}
					continue
				}
				if strings.HasPrefix(line, "set destination-port ") {
					if port, err := strconv.Atoi(strings.TrimPrefix(line, "set destination-port ")); err == nil {
						currentVxlan.DestinationPort = port
					}
					continue
				}
				// FortiOS spells the UDP port "dstport" (4789 default).
				if strings.HasPrefix(line, "set dstport ") {
					if port, err := strconv.Atoi(strings.TrimPrefix(line, "set dstport ")); err == nil {
						currentVxlan.DestinationPort = port
					}
					continue
				}
				// VTEP peers: set remote-ip "10.1.1.2" "10.1.1.3"
				if strings.HasPrefix(line, "set remote-ip ") {
					for _, tok := range strings.Fields(strings.TrimPrefix(line, "set remote-ip ")) {
						if ip := strings.Trim(tok, "\""); ip != "" {
							currentVxlan.RemoteIPs = append(currentVxlan.RemoteIPs, ip)
						}
					}
					continue
				}
				if strings.HasPrefix(line, "next") {
					vxlans = append(vxlans, currentVxlan)
					currentEdit = ""
					currentVxlan = FortiGateVxlan{}
					inVxlanEdit = false
					continue
				}
			}
		}
	}

	return vxlans
}

// FortiGateInterface captures the relationship-relevant fields of one
// `config system interface` entry: its parent interface (the interface it is
// bound to — set for VLAN sub-interfaces), its VLAN id, and its FortiGate type
// (vlan, hard-switch, aggregate, …). Lets the connection detail recognize that
// a VLAN sub-interface and its parent bridge are the same logical segment.
type FortiGateInterface struct {
	Name   string
	Parent string // set interface "X" — the underlying interface this rides on
	VLANID int    // set vlanid N
	Type   string // set type vlan|hard-switch|aggregate|...
}

// ParseFortiGateInterfaceConfig extracts every `config system interface` entry's
// name, parent, vlanid and type. Nested blocks (config ipv6, secondaryip,
// member, …) inside an edit are skipped via depth tracking so their `end` does
// not terminate the section early.
func ParseFortiGateInterfaceConfig(configText string) []FortiGateInterface {
	if configText == "" {
		return nil
	}
	var out []FortiGateInterface
	inBlock := false
	inEdit := false
	depth := 0 // nested-config depth within the current edit
	var cur FortiGateInterface

	for _, raw := range strings.Split(configText, "\n") {
		line := strings.TrimSpace(raw)
		if !inBlock {
			if line == "config system interface" {
				inBlock = true
			}
			continue
		}
		if !inEdit {
			if strings.HasPrefix(line, "edit ") {
				cur = FortiGateInterface{Name: strings.Trim(strings.TrimPrefix(line, "edit "), "\"")}
				inEdit = true
				depth = 0
			} else if line == "end" {
				break // end of the section
			}
			continue
		}
		// inside an edit
		switch {
		case strings.HasPrefix(line, "config "):
			depth++
		case line == "end":
			if depth > 0 {
				depth--
			}
		case depth > 0:
			// inside a nested block (ipv6/secondaryip/member) — ignore
		case strings.HasPrefix(line, "set interface "):
			cur.Parent = strings.Trim(strings.TrimPrefix(line, "set interface "), "\"")
		case strings.HasPrefix(line, "set vlanid "):
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "set vlanid "))); err == nil {
				cur.VLANID = v
			}
		case strings.HasPrefix(line, "set type "):
			cur.Type = strings.Trim(strings.TrimPrefix(line, "set type "), "\"")
		case line == "next":
			out = append(out, cur)
			cur = FortiGateInterface{}
			inEdit = false
		}
	}
	return out
}

func IsFortiGateVxlanInterface(configText string, ifaceName string) bool {
	vxlans := ParseFortiGateVxlanConfig(configText)
	for _, v := range vxlans {
		if v.Name == ifaceName {
			return true
		}
	}
	return false
}
