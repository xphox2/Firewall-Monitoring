package snmp

import (
	"fmt"
	"net"
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
	fgOIDVPNTunnelRemoteAddr = ".1.3.6.1.4.1.12356.101.12.2.2.1.5"
	fgOIDVPNTunnelRemoteMask = ".1.3.6.1.4.1.12356.101.12.2.2.1.6"
	fgOIDVPNTunnelLocalAddr  = ".1.3.6.1.4.1.12356.101.12.2.2.1.7"
	fgOIDVPNTunnelLocalMask  = ".1.3.6.1.4.1.12356.101.12.2.2.1.8"
	fgOIDVPNTunnelInOctets   = ".1.3.6.1.4.1.12356.101.12.2.2.1.18"
	fgOIDVPNTunnelOutOctets  = ".1.3.6.1.4.1.12356.101.12.2.2.1.19"
	fgOIDVPNTunnelStatus     = ".1.3.6.1.4.1.12356.101.12.2.2.1.20"
	fgOIDVPNTunnelUpTime     = ".1.3.6.1.4.1.12356.101.12.2.2.1.21"

	fgBaseOIDVPNDialup       = ".1.3.6.1.4.1.12356.101.12.2.1.1"
	fgOIDVPNDialupPhase1Name = ".1.3.6.1.4.1.12356.101.12.2.1.1.2"
	fgOIDVPNDialupName       = ".1.3.6.1.4.1.12356.101.12.2.1.1.3"
	fgOIDVPNDialupRemoteGW   = ".1.3.6.1.4.1.12356.101.12.2.1.1.4"
	fgOIDVPNDialupInOctets   = ".1.3.6.1.4.1.12356.101.12.2.1.1.7"
	fgOIDVPNDialupOutOctets  = ".1.3.6.1.4.1.12356.101.12.2.1.1.8"
	fgOIDVPNDialupStatus     = ".1.3.6.1.4.1.12356.101.12.2.1.1.9"
	fgOIDVPNDialupUpTime     = ".1.3.6.1.4.1.12356.101.12.2.1.1.10"

	fgBaseOIDSSLVPN          = ".1.3.6.1.4.1.12356.101.12.3.1.1"
	fgOIDSSLVPNLoginName     = ".1.3.6.1.4.1.12356.101.12.3.1.1.3"
	fgOIDSSLVPNLoginState    = ".1.3.6.1.4.1.12356.101.12.3.1.1.6"
	fgOIDSSLVPNLoginDuration = ".1.3.6.1.4.1.12356.101.12.3.1.1.7"

	fgOIDHWSensorEntry = ".1.3.6.1.4.1.12356.101.4.3.2.1"
	fgOIDHWSensorName  = ".1.3.6.1.4.1.12356.101.4.3.2.1.2"
	fgOIDHWSensorValue = ".1.3.6.1.4.1.12356.101.4.3.2.1.3"
	fgOIDHWSensorAlarm = ".1.3.6.1.4.1.12356.101.4.3.2.1.4"

	fgBaseOIDProcessor  = ".1.3.6.1.4.1.12356.101.4.4.2.1"
	fgOIDProcessorUsage = ".1.3.6.1.4.1.12356.101.4.4.2.1.2"

	fgOIDHaMode      = ".1.3.6.1.4.1.12356.101.13.1.1"
	fgOIDHaGroupName = ".1.3.6.1.4.1.12356.101.13.1.2"
	fgOIDHaMasterIP  = ".1.3.6.1.4.1.12356.101.13.1.3"
	fgOIDHaSlaveIP   = ".1.3.6.1.4.1.12356.101.13.1.4"
	fgOIDHaTable     = ".1.3.6.1.4.1.12356.101.13.2.1"

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

func (f *FortiGateProfile) SSLVPNBaseOID() string { return fgBaseOIDSSLVPN }

func (f *FortiGateProfile) GetAllVPNTunnels(s *SNMPClient) ([]models.VPNStatus, int, int, error) {
	var allTunnels []models.VPNStatus
	var sslvpnUsers, sslvpnSessions int

	// Walk IPSec site-to-site tunnels
	ipsecPdus, err := s.Walk(fgBaseOIDVPNTunnel)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to walk IPSec tunnel table: %w", err)
	}
	ipsecTunnels := f.ParseVPNStatus(ipsecPdus)
	// Mark as ipsec type
	for i := range ipsecTunnels {
		ipsecTunnels[i].TunnelType = "ipsec"
	}
	allTunnels = append(allTunnels, ipsecTunnels...)

	// Walk IPSec dialup tunnels
	dialupPdus, err := s.Walk(fgBaseOIDVPNDialup)
	if err == nil && len(dialupPdus) > 0 {
		dialupTunnels := f.ParseVPNDialupStatus(dialupPdus)
		// Mark as ipsec-dialup type
		for i := range dialupTunnels {
			dialupTunnels[i].TunnelType = "ipsec-dialup"
		}
		allTunnels = append(allTunnels, dialupTunnels...)
	}

	// Walk SSL-VPN tunnels
	sslvpnPdus, err := s.Walk(fgBaseOIDSSLVPN)
	if err != nil {
		// SSL-VPN may not be available on all devices
		sslErr := err.Error()
		if !strings.Contains(sslErr, "noSuchName") && !strings.Contains(sslErr, "NoSuchObject") {
			// Log but don't fail - SSL-VPN is optional
		}
	} else {
		sslvpnTunnels := f.ParseSSLVPNTunnels(sslvpnPdus)
		allTunnels = append(allTunnels, sslvpnTunnels...)
		sslvpnUsers, sslvpnSessions = f.ParseSSLVPNStatus(sslvpnPdus)
	}

	// Walk GRE tunnels from interface table (ifType=47)
	grePdus, err := s.Walk(BaseOIDInterface)
	if err == nil {
		greTunnels := f.ParseGRETunnels(grePdus)
		allTunnels = append(allTunnels, greTunnels...)
	}

	return allTunnels, sslvpnUsers, sslvpnSessions, nil
}

func (f *FortiGateProfile) ParseGRETunnels(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	interfaces := make(map[int]map[string]interface{})
	
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		
		if strings.HasPrefix(name, OIDIfDescr+".") {
			idx := getIndexFromOID(name, OIDIfDescr)
			if idx < 0 {
				continue
			}
			if interfaces[idx] == nil {
				interfaces[idx] = make(map[string]interface{})
			}
			interfaces[idx]["name"] = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDIfType+".") {
			idx := getIndexFromOID(name, OIDIfType)
			if idx < 0 {
				continue
			}
			if interfaces[idx] == nil {
				interfaces[idx] = make(map[string]interface{})
			}
			interfaces[idx]["type"] = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
			idx := getIndexFromOID(name, OIDIfOperStatus)
			if idx < 0 {
				continue
			}
			if interfaces[idx] == nil {
				interfaces[idx] = make(map[string]interface{})
			}
			status := gosnmp.ToBigInt(pdu.Value).Int64()
			if status == 1 {
				interfaces[idx]["status"] = "up"
			} else if status == 2 {
				interfaces[idx]["status"] = "down"
			} else {
				interfaces[idx]["status"] = "unknown"
			}
		} else if strings.HasPrefix(name, OIDIfAdminStatus+".") {
			idx := getIndexFromOID(name, OIDIfAdminStatus)
			if idx < 0 {
				continue
			}
			if interfaces[idx] == nil {
				interfaces[idx] = make(map[string]interface{})
			}
			adminStatus := gosnmp.ToBigInt(pdu.Value).Int64()
			if adminStatus == 1 {
				interfaces[idx]["admin_status"] = "up"
			} else {
				interfaces[idx]["admin_status"] = "down"
			}
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			idx := getIndexFromOID(name, OIDIfInOctets)
			if idx < 0 {
				continue
			}
			if interfaces[idx] == nil {
				interfaces[idx] = make(map[string]interface{})
			}
			interfaces[idx]["bytes_in"] = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfOutOctets)
			if idx < 0 {
				continue
			}
			if interfaces[idx] == nil {
				interfaces[idx] = make(map[string]interface{})
			}
			interfaces[idx]["bytes_out"] = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	// Filter for GRE interfaces (ifType = 47)
	var result []models.VPNStatus
	now := time.Now()
	for idx, iface := range interfaces {
		ifType, _ := iface["type"].(int)
		if ifType == 47 { // GRE tunnel
			name, _ := iface["name"].(string)
			if name == "" {
				name = fmt.Sprintf("gre.%d", idx)
			}
			status, _ := iface["status"].(string)
			state := "inactive"
			if status == "up" {
				state = "active"
			}
			
			var bytesIn, bytesOut uint64
			if b, ok := iface["bytes_in"].(uint64); ok {
				bytesIn = b
			}
			if b, ok := iface["bytes_out"].(uint64); ok {
				bytesOut = b
			}
			
			vpn := models.VPNStatus{
				Timestamp:  now,
				TunnelName: name,
				TunnelType: "gre",
				Status:     status,
				State:      state,
				BytesIn:    bytesIn,
				BytesOut:   bytesOut,
			}
			// For GRE, we don't have remote/local subnet in interface stats
			// Could add additional OID walks for GRE-specific data if available
			result = append(result, vpn)
		}
	}
	return result
}

func (f *FortiGateProfile) ParseVPNDialupStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	tunnelMap := make(map[int]*models.VPNStatus)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		if strings.HasPrefix(name, fgOIDVPNDialupPhase1Name+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupPhase1Name)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.Phase1Name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNDialupName+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupName)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelName = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNDialupRemoteGW+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupRemoteGW)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.RemoteIP = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNDialupInOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupInOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNDialupOutOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupOutOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNDialupStatus+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupStatus)
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
		} else if strings.HasPrefix(name, fgOIDVPNDialupUpTime+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupUpTime)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelUptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	result := make([]models.VPNStatus, 0, len(tunnelMap))
	for _, t := range tunnelMap {
		t.Timestamp = now
		result = append(result, *t)
	}
	return result
}

func (f *FortiGateProfile) ParseSSLVPNTunnels(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	tunnelMap := make(map[int]*models.VPNStatus)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		// fgVpnSslTableEntry indexes
		if strings.HasPrefix(name, fgOIDSSLVPNLoginName+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNLoginName)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelName = safeString(pdu.Value)
			t.TunnelType = "sslvpn"
		} else if strings.HasPrefix(name, fgOIDSSLVPNLoginState+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNLoginState)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			state := gosnmp.ToBigInt(pdu.Value).Int64()
			if state == 1 {
				t.Status = "up"
				t.State = "active"
			} else {
				t.Status = "down"
				t.State = "inactive"
			}
		} else if strings.HasPrefix(name, fgOIDSSLVPNLoginDuration+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNLoginDuration)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelUptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	result := make([]models.VPNStatus, 0, len(tunnelMap))
	for _, t := range tunnelMap {
		t.Timestamp = now
		result = append(result, *t)
	}
	return result
}

func (f *FortiGateProfile) ParseSSLVPNStatus(pdus []gosnmp.SnmpPDU) (int, int) {
	var users, sessions int
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDSSLVPNLoginName+".") {
			users++
		} else if strings.HasPrefix(name, fgOIDSSLVPNLoginState+".") {
			state := gosnmp.ToBigInt(pdu.Value).Int64()
			if state == 1 { // up/active
				sessions++
			}
		}
	}
	return users, sessions
}

func (f *FortiGateProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	tunnelMap := make(map[int]*models.VPNStatus)
	// Temporary storage for subnet addr/mask to combine into CIDR
	localAddrs := make(map[int]string)
	localMasks := make(map[int]string)
	remoteAddrs := make(map[int]string)
	remoteMasks := make(map[int]string)

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
		} else if strings.HasPrefix(name, fgOIDVPNTunnelRemoteAddr+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelRemoteAddr)
			if idx >= 0 {
				remoteAddrs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelRemoteMask+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelRemoteMask)
			if idx >= 0 {
				remoteMasks[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelLocalAddr+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelLocalAddr)
			if idx >= 0 {
				localAddrs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelLocalMask+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelLocalMask)
			if idx >= 0 {
				localMasks[idx] = safeString(pdu.Value)
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
		t.LocalSubnet = buildCIDR(localAddrs[idx], localMasks[idx])
		t.RemoteSubnet = buildCIDR(remoteAddrs[idx], remoteMasks[idx])
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
			sensor.Value = float64(gosnmp.ToBigInt(pdu.Value).Int64())
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
		sensors = append(sensors, *sensor)
	}
	return sensors
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
