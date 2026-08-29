package snmp

import (
	"fmt"
	"net"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// SonicWall SNMP OIDs — SNWL-COMMON-MIB + SONICWALL-FIREWALL-IP-STATISTICS-MIB.
// Enterprise OID: .1.3.6.1.4.1.8741
var (
	// --- SNMPv2-MIB system scalars ---
	swOIDSysName   = ".1.3.6.1.2.1.1.5.0"
	swOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"

	// --- SNWL-COMMON-MIB (.1.3.6.1.4.1.8741.2.1.1) ---
	swOIDModel           = ".1.3.6.1.4.1.8741.2.1.1.1.0"
	swOIDSerialNumber    = ".1.3.6.1.4.1.8741.2.1.1.2.0"
	swOIDFirmwareVersion = ".1.3.6.1.4.1.8741.2.1.1.3.0"

	// --- SONICWALL-FIREWALL-IP-STATISTICS-MIB ---
	swOIDMaxConn     = ".1.3.6.1.4.1.8741.1.3.1.1.0" // sonicMaxConnCacheEntries
	swOIDCurrentConn = ".1.3.6.1.4.1.8741.1.3.1.2.0" // sonicCurrentConnCacheEntries
	swOIDCpuUtil     = ".1.3.6.1.4.1.8741.1.3.1.3.0" // sonicCurrentCPUUtil (%)
	swOIDRamUtil     = ".1.3.6.1.4.1.8741.1.3.1.4.0" // sonicCurrentRAMUtil (%)

	// --- VPN SA Statistics Table ---
	swBaseOIDVPNSA      = ".1.3.6.1.4.1.8741.1.3.2.1.1.1"
	swOIDSAPeerGateway  = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.2"
	swOIDSASrcAddrBegin = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.3"
	swOIDSASrcAddrEnd   = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.4"
	swOIDSADstAddrBegin = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.5"
	swOIDSADstAddrEnd   = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.6"
	swOIDSAEncryptBytes = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.9"
	swOIDSADecryptBytes = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.11"
	swOIDSAUserName     = ".1.3.6.1.4.1.8741.1.3.2.1.1.1.14"

	// --- Hardware Sensors Table ---
	swBaseOIDSensors  = ".1.3.6.1.4.1.8741.1.3.3.3.1.1"
	swOIDSensorDevice = ".1.3.6.1.4.1.8741.1.3.3.3.1.1.3"
	swOIDSensorValue  = ".1.3.6.1.4.1.8741.1.3.3.3.1.1.4"
	swOIDSensorUnit   = ".1.3.6.1.4.1.8741.1.3.3.3.1.1.5"
)

// SonicWallProfile implements VendorProfile for SonicWall firewalls.
type SonicWallProfile struct{}

func init() {
	RegisterVendor(&SonicWallProfile{})
}

func (sw *SonicWallProfile) Name() string { return "sonicwall" }

func (sw *SonicWallProfile) SystemOIDs() []string {
	return []string{
		swOIDSysName,
		swOIDSysUpTime,
		swOIDModel,
		swOIDSerialNumber,
		swOIDFirmwareVersion,
		swOIDCpuUtil,
		swOIDRamUtil,
		swOIDCurrentConn,
		swOIDMaxConn,
	}
}

func (sw *SonicWallProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *models.SystemStatus {
	status := &models.SystemStatus{Timestamp: time.Now()}

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case swOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case swOIDFirmwareVersion:
			status.Version = "SonicOS " + safeString(pdu.Value)
		case swOIDSysUpTime:
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks // AUDIT-220: store RAW hundredths (the consumer FormatUptime divides by 100 once; pre-dividing here was a latent 100x error should this legacy single-device path ever select a non-FortiGate profile — same fix as the collector profiles).
		case swOIDCpuUtil:
			status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case swOIDRamUtil:
			status.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case swOIDCurrentConn:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		}
	}

	return status
}

// VPN: SonicWall exposes active IPSec SA entries in sonicSAStatTable.

func (sw *SonicWallProfile) VPNBaseOID() string { return swBaseOIDVPNSA }

func (sw *SonicWallProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	return parseSonicWallVPNFromSATable(pdus)
}

func (sw *SonicWallProfile) GetAllVPNTunnels(s *SNMPClient) ([]models.VPNStatus, error) {
	pdus, err := s.Walk(swBaseOIDVPNSA)
	if err != nil {
		return nil, err
	}
	tunnels := parseSonicWallVPNFromSATable(pdus)
	return tunnels, nil
}

// sonicSAData holds per-SA data from the sonicSAStatTable.
type sonicSAData struct {
	peerGateway  string
	srcAddrBegin string
	srcAddrEnd   string
	dstAddrBegin string
	dstAddrEnd   string
	encryptBytes uint64
	decryptBytes uint64
	userName     string
}

func parseSonicWallVPNFromSATable(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	saMap := make(map[int]*sonicSAData)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		if strings.HasPrefix(name, swOIDSAPeerGateway+".") {
			idx := getIndexFromOID(name, swOIDSAPeerGateway)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.peerGateway = swFormatIPAddress(pdu.Value)
		} else if strings.HasPrefix(name, swOIDSASrcAddrBegin+".") {
			idx := getIndexFromOID(name, swOIDSASrcAddrBegin)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.srcAddrBegin = swFormatIPAddress(pdu.Value)
		} else if strings.HasPrefix(name, swOIDSASrcAddrEnd+".") {
			idx := getIndexFromOID(name, swOIDSASrcAddrEnd)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.srcAddrEnd = swFormatIPAddress(pdu.Value)
		} else if strings.HasPrefix(name, swOIDSADstAddrBegin+".") {
			idx := getIndexFromOID(name, swOIDSADstAddrBegin)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.dstAddrBegin = swFormatIPAddress(pdu.Value)
		} else if strings.HasPrefix(name, swOIDSADstAddrEnd+".") {
			idx := getIndexFromOID(name, swOIDSADstAddrEnd)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.dstAddrEnd = swFormatIPAddress(pdu.Value)
		} else if strings.HasPrefix(name, swOIDSAEncryptBytes+".") {
			idx := getIndexFromOID(name, swOIDSAEncryptBytes)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.encryptBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, swOIDSADecryptBytes+".") {
			idx := getIndexFromOID(name, swOIDSADecryptBytes)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.decryptBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, swOIDSAUserName+".") {
			idx := getIndexFromOID(name, swOIDSAUserName)
			if idx < 0 {
				continue
			}
			sa := getOrCreateSWSA(saMap, idx)
			sa.userName = safeString(pdu.Value)
		}
	}

	now := time.Now()
	var result []models.VPNStatus

	for _, sa := range saMap {
		tunnelName := sa.userName
		if tunnelName == "" {
			tunnelName = fmt.Sprintf("SA-%s", sa.peerGateway)
		}

		localSubnet := swFormatSubnetRange(sa.srcAddrBegin, sa.srcAddrEnd)
		remoteSubnet := swFormatSubnetRange(sa.dstAddrBegin, sa.dstAddrEnd)

		result = append(result, models.VPNStatus{
			Timestamp:    now,
			TunnelName:   tunnelName,
			TunnelType:   "ipsec",
			RemoteIP:     sa.peerGateway,
			Status:       "up",
			State:        "active",
			BytesIn:      sa.decryptBytes,
			BytesOut:     sa.encryptBytes,
			LocalSubnet:  localSubnet,
			RemoteSubnet: remoteSubnet,
		})
	}

	return result
}

func getOrCreateSWSA(m map[int]*sonicSAData, idx int) *sonicSAData {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &sonicSAData{}
	m[idx] = v
	return v
}

func swFormatIPAddress(v interface{}) string {
	switch val := v.(type) {
	case string:
		if ip := net.ParseIP(val); ip != nil {
			return ip.String()
		}
		if len(val) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", val[0], val[1], val[2], val[3])
		}
		return val
	case []byte:
		if len(val) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", val[0], val[1], val[2], val[3])
		}
		return string(val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func swFormatSubnetRange(begin, end string) string {
	if begin == "" {
		return ""
	}
	if begin == end || end == "" {
		return begin + "/32"
	}
	return begin + "-" + end
}

// swSensor holds per-sensor data from the sonicwallSensorsTable.
type swSensor struct {
	name  string
	value float64
	unit  string
}

// Hardware sensors: sonicwallSensorsTable (temperature, fan, voltage).

func (sw *SonicWallProfile) HWSensorBaseOID() string { return swBaseOIDSensors }

func (sw *SonicWallProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []models.HardwareSensor {
	sensorMap := make(map[int]*swSensor)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		if strings.HasPrefix(name, swOIDSensorDevice+".") {
			idx := getIndexFromOID(name, swOIDSensorDevice)
			if idx < 0 {
				continue
			}
			sd := getOrCreateSWSensor(sensorMap, idx)
			sd.name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, swOIDSensorValue+".") {
			idx := getIndexFromOID(name, swOIDSensorValue)
			if idx < 0 {
				continue
			}
			sd := getOrCreateSWSensor(sensorMap, idx)
			sd.value = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, swOIDSensorUnit+".") {
			idx := getIndexFromOID(name, swOIDSensorUnit)
			if idx < 0 {
				continue
			}
			sd := getOrCreateSWSensor(sensorMap, idx)
			sd.unit = safeString(pdu.Value)
		}
	}

	now := time.Now()
	var result []models.HardwareSensor

	for _, sd := range sensorMap {
		if sd.name == "" {
			continue
		}

		sensorType := swClassifySensorType(sd.name, sd.unit)

		result = append(result, models.HardwareSensor{
			Timestamp: now,
			Name:      sd.name,
			Type:      sensorType,
			Value:     sd.value,
			Status:    "normal",
			Unit:      sd.unit,
		})
	}

	return result
}

func getOrCreateSWSensor(m map[int]*swSensor, idx int) *swSensor {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &swSensor{}
	m[idx] = v
	return v
}

func swClassifySensorType(name, unit string) string {
	lower := strings.ToLower(name + " " + unit)
	switch {
	case strings.Contains(lower, "temp") || strings.Contains(lower, "celsius"):
		return "temperature"
	case strings.Contains(lower, "fan") || strings.Contains(lower, "rpm"):
		return "fan"
	case strings.Contains(lower, "volt") || strings.Contains(lower, "vcc") || strings.Contains(lower, "vdd"):
		return "voltage"
	case strings.Contains(lower, "power") || strings.Contains(lower, "watt"):
		return "power"
	default:
		return "other"
	}
}

// Processors: SonicWall has no per-core SNMP table.

func (sw *SonicWallProfile) ProcessorBaseOID() string { return "" }

func (sw *SonicWallProfile) ParseProcessors(_ []gosnmp.SnmpPDU) []models.ProcessorStats {
	return nil
}

// HA: SonicWall has no pollable HA state OIDs — only trap-based.

func (sw *SonicWallProfile) HABaseOID() string { return "" }

func (sw *SonicWallProfile) ParseHAStatus(_ []gosnmp.SnmpPDU) []models.HAStatus {
	return nil
}

// Traps: SONICWALL-FIREWALL-TRAP-MIB notifications.

func (sw *SonicWallProfile) TrapOIDs() map[string]TrapDef {
	return map[string]TrapDef{
		".1.3.6.1.4.1.8741.1.1.2.0.1":   {Type: "attack-detected", Severity: "critical"},
		".1.3.6.1.4.1.8741.1.1.2.0.2":   {Type: "system-error", Severity: "critical"},
		".1.3.6.1.4.1.8741.1.1.2.0.4":   {Type: "ipsec-tunnel", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.6":   {Type: "system-environment", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.122": {Type: "hw-error", Severity: "critical"},
		".1.3.6.1.4.1.8741.1.1.2.0.126": {Type: "ha-state-change", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.127": {Type: "ips-detection", Severity: "critical"},
		".1.3.6.1.4.1.8741.1.1.2.0.138": {Type: "security-services", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.140": {Type: "vpn-event", Severity: "info"},
		".1.3.6.1.4.1.8741.1.1.2.0.142": {Type: "vpn-ike", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.143": {Type: "vpn-ipsec", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.145": {Type: "wan-failover", Severity: "warning"},
		".1.3.6.1.4.1.8741.1.1.2.0.162": {Type: "sslvpn-event", Severity: "info"},
	}
}
