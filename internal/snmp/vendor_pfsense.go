package snmp

import (
	"strings"
	"time"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// pfSense SNMP OIDs — FreeBSD-based, uses bsnmpd with standard + BEGEMOT-PF-MIB.
// UCD-SNMP-MIB available when the UCD module is enabled in Services > SNMP.
var (
	// --- SNMPv2-MIB system scalars ---
	pfOIDSysDescr  = ".1.3.6.1.2.1.1.1.0"
	pfOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"
	pfOIDSysName   = ".1.3.6.1.2.1.1.5.0"

	// --- UCD-SNMP-MIB CPU (requires UCD module) ---
	pfOIDCpuUser   = ".1.3.6.1.4.1.2021.11.9.0"
	pfOIDCpuSystem = ".1.3.6.1.4.1.2021.11.10.0"
	pfOIDCpuIdle   = ".1.3.6.1.4.1.2021.11.11.0"

	// --- UCD-SNMP-MIB Memory ---
	pfOIDMemTotalReal = ".1.3.6.1.4.1.2021.4.5.0"
	pfOIDMemAvailReal = ".1.3.6.1.4.1.2021.4.6.0"
	pfOIDMemBuffer    = ".1.3.6.1.4.1.2021.4.14.0"
	pfOIDMemCached    = ".1.3.6.1.4.1.2021.4.15.0"

	// --- BEGEMOT-PF-MIB (enterprise 12325 = FreeBSD/Begemot) ---
	pfOIDStateCount = ".1.3.6.1.4.1.12325.1.200.1.3.1.0" // pfStateTableCount
	pfOIDPfRunning  = ".1.3.6.1.4.1.12325.1.200.1.1.1.0" // PF enabled

	// --- HOST-RESOURCES-MIB Processor ---
	pfBaseOIDProcessor = ".1.3.6.1.2.1.25.3.3.1"
	pfOIDProcessorLoad = ".1.3.6.1.2.1.25.3.3.1.2"
)

// PfSenseProfile implements VendorProfile for pfSense firewalls.
type PfSenseProfile struct{}

func init() {
	RegisterVendor(&PfSenseProfile{})
}

func (p *PfSenseProfile) Name() string { return "pfsense" }

func (p *PfSenseProfile) SystemOIDs() []string {
	return []string{
		pfOIDSysName,
		pfOIDSysDescr,
		pfOIDSysUpTime,
		pfOIDCpuUser,
		pfOIDCpuSystem,
		pfOIDCpuIdle,
		pfOIDMemTotalReal,
		pfOIDMemAvailReal,
		pfOIDMemBuffer,
		pfOIDMemCached,
		pfOIDStateCount,
		pfOIDPfRunning,
	}
}

func (p *PfSenseProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *models.SystemStatus {
	status := &models.SystemStatus{Timestamp: time.Now()}
	var cpuUser, cpuSystem, cpuIdle int64
	var memTotalKB, memAvailKB, memBufferKB, memCachedKB int64

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case pfOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case pfOIDSysDescr:
			status.Version = extractPfSenseVersion(safeString(pdu.Value))
		case pfOIDSysUpTime:
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks / 100
		case pfOIDCpuUser:
			cpuUser = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDCpuSystem:
			cpuSystem = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDCpuIdle:
			cpuIdle = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemTotalReal:
			memTotalKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemAvailReal:
			memAvailKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemBuffer:
			memBufferKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemCached:
			memCachedKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDStateCount:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		}
	}

	total := cpuUser + cpuSystem + cpuIdle
	if total > 0 {
		status.CPUUsage = float64(cpuUser+cpuSystem) / float64(total) * 100
	} else if cpuIdle > 0 {
		status.CPUUsage = float64(100 - cpuIdle)
	}

	if memTotalKB > 0 {
		status.MemoryTotal = uint64(memTotalKB / 1024)
		usedKB := memTotalKB - memAvailKB - memBufferKB - memCachedKB
		if usedKB < 0 {
			usedKB = memTotalKB - memAvailKB
		}
		status.MemoryUsage = float64(usedKB) / float64(memTotalKB) * 100
	}

	return status
}

// extractPfSenseVersion parses the pfSense version from sysDescr.
func extractPfSenseVersion(sysDescr string) string {
	if sysDescr == "" {
		return ""
	}
	lower := strings.ToLower(sysDescr)
	if idx := strings.Index(lower, "pfsense"); idx >= 0 {
		parts := strings.Fields(sysDescr[idx:])
		for _, part := range parts {
			if strings.Contains(part, "-CE-") || strings.Contains(part, "-RELEASE") ||
				strings.Contains(part, "2.") || strings.Contains(part, "24.") {
				return "pfSense " + part
			}
		}
		if len(parts) >= 2 {
			return "pfSense " + parts[1]
		}
	}
	parts := strings.Fields(sysDescr)
	if len(parts) >= 3 {
		return parts[0] + " " + parts[2]
	}
	if len(sysDescr) > 80 {
		return sysDescr[:80]
	}
	return sysDescr
}

// VPN: not exposed via SNMP on pfSense.

func (p *PfSenseProfile) VPNBaseOID() string { return "" }

func (p *PfSenseProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	return nil
}

func (p *PfSenseProfile) SSLVPNBaseOID() string { return "" }

func (p *PfSenseProfile) ParseSSLVPNStatus(pdus []gosnmp.SnmpPDU) (int, int) {
	return 0, 0
}

func (p *PfSenseProfile) ParseSSLVPNTunnels(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	return nil
}

func (p *PfSenseProfile) GetAllVPNTunnels(s *SNMPClient) ([]models.VPNStatus, int, int, error) {
	return nil, 0, 0, nil
}

// Hardware sensors: not available via bsnmpd.

func (p *PfSenseProfile) HWSensorBaseOID() string { return "" }

func (p *PfSenseProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []models.HardwareSensor {
	return nil
}

// Processors: HOST-RESOURCES-MIB hrProcessorTable.

func (p *PfSenseProfile) ProcessorBaseOID() string { return pfBaseOIDProcessor }

func (p *PfSenseProfile) ParseProcessors(pdus []gosnmp.SnmpPDU) []models.ProcessorStats {
	now := time.Now()
	var result []models.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, pfOIDProcessorLoad+".") {
			idx := getIndexFromOID(pdu.Name, pfOIDProcessorLoad)
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

// HA: pfSense CARP HA is not exposed via SNMP.

func (p *PfSenseProfile) HABaseOID() string { return "" }

func (p *PfSenseProfile) ParseHAStatus(pdus []gosnmp.SnmpPDU) []models.HAStatus {
	return nil
}

// Traps: standard linkUp/linkDown only.

func (p *PfSenseProfile) TrapOIDs() map[string]TrapDef {
	return nil
}
