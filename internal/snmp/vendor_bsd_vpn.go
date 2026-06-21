package snmp

import (
	"strings"
	"time"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// bsdIfData holds interface data extracted from IF-MIB for VPN detection.
type bsdIfData struct {
	name     string
	operUp   bool
	bytesIn  uint64
	bytesOut uint64
}

// parseBSDVPNFromInterfacePDUs extracts VPN tunnel status from IF-MIB PDUs by
// matching interface name patterns used by pfSense and OPNsense:
//
//   - ovpns*  → OpenVPN server instances
//   - ovpnc*  → OpenVPN client instances
//   - wg*     → WireGuard interfaces
//   - tun_wg* → WireGuard interfaces (pfSense naming)
//   - ipsec*  → IPSec VTI (route-based) interfaces
//
// This works with pure SNMP — no firewall-side configuration required.
func parseBSDVPNFromInterfacePDUs(pdus []gosnmp.SnmpPDU) []models.VPNStatus {
	interfaces := make(map[int]*bsdIfData)

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
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
			idx := getIndexFromOID(name, OIDIfOperStatus)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.operUp = gosnmp.ToBigInt(pdu.Value).Int64() == 1
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			idx := getIndexFromOID(name, OIDIfInOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.bytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfOutOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.bytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
		// Also pick up 64-bit counters from ifXTable if present in the walk
		if strings.HasPrefix(name, OIDIfHCInOctets+".") {
			idx := getIndexFromOID(name, OIDIfHCInOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.bytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfHCOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfHCOutOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.bytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	var result []models.VPNStatus

	for _, ifd := range interfaces {
		tunnelType, tunnelName := classifyBSDVPNInterface(ifd.name)
		if tunnelType == "" {
			continue
		}

		status := "down"
		state := "inactive"
		if ifd.operUp {
			status = "up"
			state = "active"
		}

		result = append(result, models.VPNStatus{
			Timestamp:  now,
			TunnelName: tunnelName,
			TunnelType: tunnelType,
			Status:     status,
			State:      state,
			BytesIn:    ifd.bytesIn,
			BytesOut:   ifd.bytesOut,
		})
	}

	return result
}

// classifyBSDVPNInterface returns (tunnelType, tunnelName) if the interface
// name matches a known VPN pattern, or ("", "") if not a VPN interface.
func classifyBSDVPNInterface(ifName string) (string, string) {
	lower := strings.ToLower(ifName)

	if strings.HasPrefix(lower, "ovpns") {
		return "openvpn-server", ifName
	}
	if strings.HasPrefix(lower, "ovpnc") {
		return "openvpn-client", ifName
	}
	if strings.HasPrefix(lower, "wg") || strings.HasPrefix(lower, "tun_wg") {
		return "wireguard", ifName
	}
	if strings.HasPrefix(lower, "ipsec") {
		return "ipsec", ifName
	}

	return "", ""
}

func getOrCreateBSDIf(m map[int]*bsdIfData, idx int) *bsdIfData {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &bsdIfData{}
	m[idx] = v
	return v
}

// bsdGetAllVPNTunnels walks IF-MIB to discover VPN interfaces.
// Used by both pfSense and OPNsense GetAllVPNTunnels implementations.
func bsdGetAllVPNTunnels(s *SNMPClient) ([]models.VPNStatus, error) {
	pdus, err := s.Walk(BaseOIDInterface)
	if err != nil {
		return nil, err
	}

	// Also walk ifXTable for 64-bit counters and interface names
	xPdus, err := s.Walk(BaseOIDIfXTable)
	if err == nil {
		pdus = append(pdus, xPdus...)
	}

	tunnels := parseBSDVPNFromInterfacePDUs(pdus)
	return tunnels, nil
}
