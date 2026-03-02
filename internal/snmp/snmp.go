package snmp

import (
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// Standard MIB OIDs (vendor-neutral)
var (
	BaseOIDInterface   = ".1.3.6.1.2.1.2.2.1"
	OIDIfDescr         = ".1.3.6.1.2.1.2.2.1.2"
	OIDIfType          = ".1.3.6.1.2.1.2.2.1.3"
	OIDIfMtu           = ".1.3.6.1.2.1.2.2.1.4"
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
	OIDIfOutUcastPkts  = ".1.3.6.1.2.1.2.2.1.17"
	OIDIfOutNUcastPkts = ".1.3.6.1.2.1.2.2.1.18"
	OIDIfOutDiscards   = ".1.3.6.1.2.1.2.2.1.19"
	OIDIfOutErrors     = ".1.3.6.1.2.1.2.2.1.20"

	// ifXTable (RFC 2863)
	BaseOIDIfXTable  = ".1.3.6.1.2.1.31.1.1.1"
	OIDIfName        = ".1.3.6.1.2.1.31.1.1.1.1"
	OIDIfHCInOctets  = ".1.3.6.1.2.1.31.1.1.1.6"
	OIDIfHCOutOctets = ".1.3.6.1.2.1.31.1.1.1.10"
	OIDIfHighSpeed   = ".1.3.6.1.2.1.31.1.1.1.15"
	OIDIfAlias       = ".1.3.6.1.2.1.31.1.1.1.18"

	// Q-BRIDGE-MIB (native VLAN)
	OIDdot1qPvid = ".1.3.6.1.2.1.17.7.1.4.5.1.1"
)

// IfTypeNames maps IANA ifType values to human-readable names
var IfTypeNames = map[int]string{
	1:   "other",
	6:   "ethernet",
	24:  "loopback",
	53:  "propVirtual",
	131: "tunnel",
	135: "l2vlan",
	136: "l3ipvlan",
	150: "mplsTunnel",
	161: "lag",
	351: "vxlan",
}

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
	if cfg.SNMP.SNMPPort < 1 || cfg.SNMP.SNMPPort > 65535 {
		return nil, fmt.Errorf("invalid SNMP port: %d", cfg.SNMP.SNMPPort)
	}

	version := gosnmp.Version2c
	if cfg.SNMP.Version == "3" {
		version = gosnmp.Version3
	} else if cfg.SNMP.Version == "1" {
		version = gosnmp.Version1
	}

	client := &gosnmp.GoSNMP{
		Target:    cfg.SNMP.SNMPHost,
		Port:      uint16(cfg.SNMP.SNMPPort),
		Community: cfg.SNMP.Community,
		Version:   version,
		Timeout:   cfg.SNMP.Timeout,
		Retries:   cfg.SNMP.Retries,
	}

	// Configure SNMPv3 security parameters
	if version == gosnmp.Version3 {
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = cfg.SNMP.V3MsgFlags()
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.SNMP.V3Username,
			AuthenticationProtocol:   cfg.SNMP.V3AuthProto(),
			AuthenticationPassphrase: cfg.SNMP.V3AuthPass,
			PrivacyProtocol:          cfg.SNMP.V3PrivProto(),
			PrivacyPassphrase:        cfg.SNMP.V3PrivPass,
		}
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

func (s *SNMPClient) resolveVendor(vendor string) VendorProfile {
	if vendor == "" {
		vendor = "fortigate"
	}
	profile := GetVendorProfile(vendor)
	if profile == nil {
		profile = DefaultVendor()
	}
	return profile
}

func (s *SNMPClient) GetSystemStatus(vendor ...string) (*models.SystemStatus, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	oids := profile.SystemOIDs()
	if len(oids) == 0 {
		return nil, fmt.Errorf("vendor %s does not support system status polling", v)
	}

	result, err := s.client.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("failed to get system status: %w", err)
	}

	return profile.ParseSystemStatus(result.Variables), nil
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

		// Use OID+"." prefix to prevent collisions (e.g., .2 matching .20)
		if strings.HasPrefix(name, OIDIfDescr+".") {
			ifIndex = getIndexFromOID(name, OIDIfDescr)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.Name = safeString(pdu.Value)
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfType+".") {
			ifIndex = getIndexFromOID(name, OIDIfType)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.Type = int(gosnmp.ToBigInt(pdu.Value).Int64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfMtu+".") {
			ifIndex = getIndexFromOID(name, OIDIfMtu)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.MTU = int(gosnmp.ToBigInt(pdu.Value).Int64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfSpeed+".") {
			ifIndex = getIndexFromOID(name, OIDIfSpeed)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.Speed = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfPhysAddress+".") {
			ifIndex = getIndexFromOID(name, OIDIfPhysAddress)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.MACAddress = formatMAC(pdu.Value)
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
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
		} else if strings.HasPrefix(name, OIDIfAdminStatus+".") {
			ifIndex = getIndexFromOID(name, OIDIfAdminStatus)
			iface := getOrCreateInterface(interfaces, ifIndex)
			status := gosnmp.ToBigInt(pdu.Value).Int64()
			if status == 1 {
				iface.AdminStatus = "up"
			} else {
				iface.AdminStatus = "down"
			}
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			ifIndex = getIndexFromOID(name, OIDIfInOctets)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInUcastPkts+".") {
			ifIndex = getIndexFromOID(name, OIDIfInUcastPkts)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InPackets = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInErrors+".") {
			ifIndex = getIndexFromOID(name, OIDIfInErrors)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InErrors = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfInDiscards+".") {
			ifIndex = getIndexFromOID(name, OIDIfInDiscards)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.InDiscards = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			ifIndex = getIndexFromOID(name, OIDIfOutOctets)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutUcastPkts+".") {
			ifIndex = getIndexFromOID(name, OIDIfOutUcastPkts)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutPackets = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutErrors+".") {
			ifIndex = getIndexFromOID(name, OIDIfOutErrors)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutErrors = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		} else if strings.HasPrefix(name, OIDIfOutDiscards+".") {
			ifIndex = getIndexFromOID(name, OIDIfOutDiscards)
			iface := getOrCreateInterface(interfaces, ifIndex)
			iface.OutDiscards = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[ifIndex] = iface
		}
	}

	// Walk ifXTable for extended counters and metadata
	if xPdus, err := s.Walk(BaseOIDIfXTable); err == nil {
		for _, pdu := range xPdus {
			name := pdu.Name
			if strings.HasPrefix(name, OIDIfName+".") {
				idx := getIndexFromOID(name, OIDIfName)
				if iface, ok := interfaces[idx]; ok {
					ifName := safeString(pdu.Value)
					if ifName != "" {
						iface.Name = ifName
					}
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfAlias+".") {
				idx := getIndexFromOID(name, OIDIfAlias)
				if iface, ok := interfaces[idx]; ok {
					iface.Alias = safeString(pdu.Value)
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfHighSpeed+".") {
				idx := getIndexFromOID(name, OIDIfHighSpeed)
				if iface, ok := interfaces[idx]; ok {
					iface.HighSpeed = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfHCInOctets+".") {
				idx := getIndexFromOID(name, OIDIfHCInOctets)
				if iface, ok := interfaces[idx]; ok {
					iface.InBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfHCOutOctets+".") {
				idx := getIndexFromOID(name, OIDIfHCOutOctets)
				if iface, ok := interfaces[idx]; ok {
					iface.OutBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
					interfaces[idx] = iface
				}
			}
		}
	}

	// Walk Q-BRIDGE-MIB for VLAN IDs (not all devices support this)
	if vlanPdus, err := s.Walk(OIDdot1qPvid); err == nil {
		for _, pdu := range vlanPdus {
			idx := getIndexFromOID(pdu.Name, OIDdot1qPvid)
			if iface, ok := interfaces[idx]; ok {
				iface.VLANID = int(gosnmp.ToBigInt(pdu.Value).Int64())
				interfaces[idx] = iface
			}
		}
	}

	// Resolve type names
	now := time.Now()
	result := make([]models.InterfaceStats, 0, len(interfaces))
	for idx, iface := range interfaces {
		if idx < 0 {
			continue // skip entries with invalid OID index
		}
		if typeName, ok := IfTypeNames[iface.Type]; ok {
			iface.TypeName = typeName
		}
		iface.Timestamp = now
		result = append(result, iface)
	}

	return result, nil
}

func formatMAC(v interface{}) string {
	var bytes []byte
	switch val := v.(type) {
	case []byte:
		bytes = val
	case string:
		bytes = []byte(val)
	default:
		return ""
	}
	if len(bytes) != 6 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}

func (s *SNMPClient) GetVPNStatus(vendor ...string) ([]models.VPNStatus, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	baseOID := profile.VPNBaseOID()
	if baseOID == "" {
		return nil, nil // vendor doesn't support VPN polling
	}

	pdus, err := s.Walk(baseOID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk VPN tunnel table: %w", err)
	}

	return profile.ParseVPNStatus(pdus), nil
}

func getOrCreateVPN(m map[int]*models.VPNStatus, index int) *models.VPNStatus {
	if v, exists := m[index]; exists {
		return v
	}
	v := &models.VPNStatus{}
	m[index] = v
	return v
}

func (s *SNMPClient) GetHardwareSensors(vendor ...string) ([]models.HardwareSensor, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	baseOID := profile.HWSensorBaseOID()
	if baseOID == "" {
		return nil, nil // vendor doesn't support hardware sensor polling
	}

	pdus, err := s.Walk(baseOID)
	if err != nil {
		return nil, err
	}

	return profile.ParseHardwareSensors(pdus), nil
}

func getOrCreateSensor(sensors map[int]*models.HardwareSensor, index int) *models.HardwareSensor {
	if s, exists := sensors[index]; exists {
		return s
	}
	s := &models.HardwareSensor{}
	sensors[index] = s
	return s
}

func getIndexFromOID(oid, base string) int {
	partial := strings.TrimPrefix(oid, base+".")
	parts := strings.Split(partial, ".")
	if len(parts) > 0 {
		var index int
		if n, _ := fmt.Sscanf(parts[0], "%d", &index); n == 1 {
			return index
		}
	}
	return -1
}

func getOrCreateInterface(interfaces map[int]models.InterfaceStats, index int) models.InterfaceStats {
	if iface, exists := interfaces[index]; exists {
		return iface
	}
	return models.InterfaceStats{Index: index}
}
