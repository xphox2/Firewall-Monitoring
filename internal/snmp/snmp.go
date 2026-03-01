package snmp

import (
	"fmt"
	"strings"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

var (
	OIDSystemCPU       = ".1.3.6.1.4.1.12356.101.4.1.3"
	OIDSystemMemory    = ".1.3.6.1.4.1.12356.101.4.1.4"
	OIDSystemMemoryCap = ".1.3.6.1.4.1.12356.101.4.1.5"
	OIDSystemDisk      = ".1.3.6.1.4.1.12356.101.4.1.6"
	OIDSystemDiskCap   = ".1.3.6.1.4.1.12356.101.4.1.7"
	OIDSystemSessions  = ".1.3.6.1.4.1.12356.101.4.1.8"
	OIDSystemUptime    = ".1.3.6.1.4.1.12356.101.4.1.20"
	OIDSystemVersion   = ".1.3.6.1.4.1.12356.101.4.1.1"
	OIDSystemHostname  = ".1.3.6.1.4.1.12356.101.4.1.2"

	BaseOIDInterface   = ".1.3.6.1.2.1.2.2.1"
	OIDIfDescr         = ".1.3.6.1.2.1.2.2.1.2"
	OIDIfType          = ".1.3.6.1.2.1.2.2.1.3"
	OIDIfSpeed         = ".1.3.6.1.2.1.2.2.1.5"
	OIDIfPhysAddress   = ".1.3.6.1.2.1.2.2.1.6"
	OIDIfAdminStatus   = ".1.3.6.1.2.1.2.2.1.7"
	OIDIfOperStatus    = ".1.3.6.1.2.1.2.2.1.8"
	OIDIfInOctets      = ".1.3.6.1.2.1.2.2.1.10"
	OIDIfInUcastPkts   = ".1.3.6.1.2.1.2.2.1.11"
	OIDIfInNUcastPkts  = ".1.3.6.1.2.1.2.2.1.12"
	OIDIfInDiscards    = ".1.3.6.1.2.1.2.2.1.13"
	OIDIfInErrors      = ".1.3.6.1.2.1.2.2.1.14"
	OIDIfOutOctets     = ".1.3.6.1.2.1.2.2.1.16"
	OIDIfOutUcastPkts  = ".1.3.6.1.2.1.2.2.1.18"
	OIDIfOutNUcastPkts = ".1.3.6.1.2.1.2.2.1.19"
	OIDIfOutDiscards   = ".1.3.6.1.2.1.2.2.1.20"
	OIDIfOutErrors     = ".1.3.6.1.2.1.2.2.1.21"

	OIDHWSensorTable = ".1.3.6.1.4.1.12356.101.4.3.2"
	OIDHWSensorCount = ".1.3.6.1.4.1.12356.101.4.3.1"

	OIDHaTable     = ".1.3.6.1.4.1.12356.101.13.2.1"
	OIDHaMode      = ".1.3.6.1.4.1.12356.101.13.1.1"
	OIDHaGroupName = ".1.3.6.1.4.1.12356.101.13.1.2"
	OIDHaMasterIP  = ".1.3.6.1.4.1.12356.101.13.1.3"
	OIDHaSlaveIP   = ".1.3.6.1.4.1.12356.101.13.1.4"

	TrapVPNTunnelUp   = ".1.3.6.1.4.1.12356.101.2.0.301"
	TrapVPNTunnelDown = ".1.3.6.1.4.1.12356.101.2.0.302"
	TrapHASwitch      = ".1.3.6.1.4.1.12356.101.2.0.401"
	TrapHAStateChange = ".1.3.6.1.4.1.12356.101.2.0.402"
	TrapHAHBFail      = ".1.3.6.1.4.1.12356.101.2.0.403"
	TrapHAMemberDown  = ".1.3.6.1.4.1.12356.101.2.0.404"
	TrapHAMemberUp    = ".1.3.6.1.4.1.12356.101.2.0.405"
	TrapIPSSignature  = ".1.3.6.1.4.1.12356.101.2.0.503"
	TrapIPSanomaly    = ".1.3.6.1.4.1.12356.101.2.0.504"
	TrapAVVirus       = ".1.3.6.1.4.1.12356.101.2.0.601"
	TrapAVOversize    = ".1.3.6.1.4.1.12356.101.2.0.602"
)

func safeString(v interface{}) string {
	if s, ok := v.([]byte); ok {
		return string(s)
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

type SNMPClient struct {
	config *config.Config
	client *gosnmp.GoSNMP
}

func NewSNMPClient(cfg *config.Config) (*SNMPClient, error) {
	version := gosnmp.Version2c
	if cfg.SNMP.Version == "3" {
		version = gosnmp.Version3
	} else if cfg.SNMP.Version == "1" {
		version = gosnmp.Version1
	}

	client := &gosnmp.GoSNMP{
		Target:    cfg.SNMP.FortiGateHost,
		Port:      uint16(cfg.SNMP.FortiGatePort),
		Community: cfg.SNMP.Community,
		Version:   version,
		Timeout:   cfg.SNMP.Timeout,
		Retries:   cfg.SNMP.Retries,
	}

	err := client.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SNMP: %w", err)
	}

	return &SNMPClient{
		config: cfg,
		client: client,
	}, nil
}

func (s *SNMPClient) Close() error {
	if s.client != nil && s.client.Conn != nil {
		return s.client.Conn.Close()
	}
	return nil
}

func (s *SNMPClient) Get(oid string) (*gosnmp.SnmpPDU, error) {
	result, err := s.client.Get([]string{oid})
	if err != nil {
		return nil, err
	}
	if len(result.Variables) == 0 {
		return nil, fmt.Errorf("no results for OID: %s", oid)
	}
	return &result.Variables[0], nil
}

func (s *SNMPClient) Walk(oid string) ([]gosnmp.SnmpPDU, error) {
	result, err := s.client.WalkAll(oid)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SNMPClient) GetSystemStatus() (*models.SystemStatus, error) {
	status := &models.SystemStatus{
		Timestamp: time.Now(),
	}

	oids := []string{
		OIDSystemHostname,
		OIDSystemVersion,
		OIDSystemCPU,
		OIDSystemMemory,
		OIDSystemMemoryCap,
		OIDSystemDisk,
		OIDSystemDiskCap,
		OIDSystemSessions,
		OIDSystemUptime,
	}

	result, err := s.client.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("failed to get system status: %w", err)
	}

	for _, pdu := range result.Variables {
		switch pdu.Name {
		case OIDSystemHostname:
			status.Hostname = safeString(pdu.Value)
		case OIDSystemVersion:
			status.Version = safeString(pdu.Value)
		case OIDSystemCPU:
			status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemMemory:
			status.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemMemoryCap:
			status.MemoryTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case OIDSystemDisk:
			status.DiskUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemDiskCap:
			status.DiskTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case OIDSystemSessions:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemUptime:
			status.Uptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	return status, nil
}

func (s *SNMPClient) GetInterfaceStats() ([]models.InterfaceStats, error) {
	pdus, err := s.Walk(BaseOIDInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to walk interface stats: %w", err)
	}

	interfaces := make(map[int]models.InterfaceStats)

	for _, pdu := range pdus {
		name := pdu.Name
		var ifIndex int

		if strings.HasPrefix(name, OIDIfDescr) {
			ifIndex = getIndexFromOID(name, OIDIfDescr)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.Name = safeString(pdu.Value)
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfType) {
			ifIndex = getIndexFromOID(name, OIDIfType)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.Type = int(gosnmp.ToBigInt(pdu.Value).Int64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfSpeed) {
			ifIndex = getIndexFromOID(name, OIDIfSpeed)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.Speed = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOperStatus) {
			ifIndex = getIndexFromOID(name, OIDIfOperStatus)
			iface := getOrCreateInterface(interfaces, ifIndex)
			status := gosnmp.ToBigInt(pdu.Value).Int64()
			if status == 1 {
				iface.Status = "up"
			} else if status == 2 {
				iface.Status = "down"
			} else {
				iface.Status = "unknown"
			}
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfAdminStatus) {
			ifIndex = getIndexFromOID(name, OIDIfAdminStatus)
			iface := getOrCreateInterface(interfaces, ifIndex)
			status := gosnmp.ToBigInt(pdu.Value).Int64()
			if status == 1 {
				iface.AdminStatus = "up"
			} else {
				iface.AdminStatus = "down"
			}
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInOctets) {
			ifIndex = getIndexFromOID(name, OIDIfInOctets)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInUcastPkts) {
			ifIndex = getIndexFromOID(name, OIDIfInUcastPkts)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InPackets = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInErrors) {
			ifIndex = getIndexFromOID(name, OIDIfInErrors)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InErrors = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInDiscards) {
			ifIndex = getIndexFromOID(name, OIDIfInDiscards)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InDiscards = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutOctets) {
			ifIndex = getIndexFromOID(name, OIDIfOutOctets)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutUcastPkts) {
			ifIndex = getIndexFromOID(name, OIDIfOutUcastPkts)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutPackets = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutErrors) {
			ifIndex = getIndexFromOID(name, OIDIfOutErrors)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutErrors = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutDiscards) {
			ifIndex = getIndexFromOID(name, OIDIfOutDiscards)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutDiscards = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		}
	}

	result := make([]models.InterfaceStats, 0, len(interfaces))
	for _, iface := range interfaces {
		iface.Timestamp = time.Now()
		result = append(result, iface)
	}

	return result, nil
}

func (s *SNMPClient) GetHardwareSensors() ([]models.HardwareSensor, error) {
	pdus, err := s.Walk(OIDHWSensorTable)
	if err != nil {
		return nil, err
	}

	var sensors []models.HardwareSensor
	for range pdus {
		sensor := models.HardwareSensor{
			Timestamp: time.Now(),
		}
		sensors = append(sensors, sensor)
	}

	return sensors, nil
}

func getIndexFromOID(oid, base string) int {
	partial := strings.TrimPrefix(oid, base+".")
	parts := strings.Split(partial, ".")
	if len(parts) > 0 {
		var index int
		fmt.Sscanf(parts[0], "%d", &index)
		return index
	}
	return 0
}

func getOrCreateInterface(interfaces map[int]models.InterfaceStats, index int) models.InterfaceStats {
	if iface, exists := interfaces[index]; exists {
		return iface
	}
	return models.InterfaceStats{Index: index}
}
