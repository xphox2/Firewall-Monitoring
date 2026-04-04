package snmp

import (
	"fmt"
	"net"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// Standard IETF trap OIDs (RFC 3418)
const (
	oidSnmpTrapOID  = ".1.3.6.1.6.3.1.1.4.1.0"
	oidLinkDown     = ".1.3.6.1.6.3.1.1.5.3"
	oidLinkUp       = ".1.3.6.1.6.3.1.1.5.4"
	oidIfIndex      = ".1.3.6.1.2.1.2.2.1.1"
	oidIfDescr      = ".1.3.6.1.2.1.2.2.1.2"
	oidIfOperStatus = ".1.3.6.1.2.1.2.2.1.8"
	oidIfAdminStat  = ".1.3.6.1.2.1.2.2.1.7"
)

type TrapReceiver struct {
	config  *config.Config
	server  *gosnmp.TrapListener
	handler func(*models.TrapEvent)
}

func NewTrapReceiver(cfg *config.Config) (*TrapReceiver, error) {
	trapListener := gosnmp.NewTrapListener()

	return &TrapReceiver{
		config: cfg,
		server: trapListener,
	}, nil
}

func (t *TrapReceiver) Start(handler func(*models.TrapEvent)) error {
	t.handler = handler

	t.server.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		// Validate community string if configured
		if t.config.SNMP.TrapCommunity != "" && packet.Community != t.config.SNMP.TrapCommunity {
			return
		}
		trap := t.parseTrap(packet, addr)
		if trap != nil && t.handler != nil {
			t.handler(trap)
		}
	}

	err := t.server.Listen(t.config.SNMP.TrapListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start trap listener: %w", err)
	}

	return nil
}

func (t *TrapReceiver) Stop() {
	t.server.Close()
}

func (t *TrapReceiver) parseTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) *models.TrapEvent {
	if len(packet.Variables) == 0 {
		return nil
	}

	trap := &models.TrapEvent{
		Timestamp: time.Now(),
		SourceIP:  addr.IP.String(),
	}

	// Phase 1: Check for standard linkUp/linkDown traps
	if linkTrap := t.parseLinkTrap(packet); linkTrap != nil {
		linkTrap.SourceIP = trap.SourceIP
		return linkTrap
	}

	// Phase 2: Vendor-specific trap lookup
	for _, v := range packet.Variables {
		oid := v.Name

		trapType, severity := lookupTrapOID(oid)
		if trapType != "" {
			trap.TrapOID = oid
			trap.TrapType = trapType
			trap.Severity = severity
			trap.Message = t.formatTrapMessage(v, oid)
			break
		}
	}

	if trap.TrapOID == "" {
		return nil
	}

	return trap
}

// parseLinkTrap detects standard IETF linkUp/linkDown traps from both
// SNMPv1 (generic trap types 2/3) and SNMPv2c/v3 (snmpTrapOID varbind).
func (t *TrapReceiver) parseLinkTrap(packet *gosnmp.SnmpPacket) *models.TrapEvent {
	var isLinkDown, isLinkUp bool

	// SNMPv1: check GenericTrap field (2=linkDown, 3=linkUp)
	if packet.PDUType == gosnmp.Trap {
		switch packet.GenericTrap {
		case 2:
			isLinkDown = true
		case 3:
			isLinkUp = true
		}
	}

	// SNMPv2c/v3: scan for snmpTrapOID.0 varbind
	if !isLinkDown && !isLinkUp {
		for _, v := range packet.Variables {
			if v.Name == oidSnmpTrapOID {
				if oidVal, ok := v.Value.(string); ok {
					switch oidVal {
					case oidLinkDown:
						isLinkDown = true
					case oidLinkUp:
						isLinkUp = true
					}
				}
				break
			}
		}
	}

	if !isLinkDown && !isLinkUp {
		return nil
	}

	// Extract interface details from varbinds
	var ifIndex string
	var ifDescr string
	var ifOperStatus string

	for _, v := range packet.Variables {
		oid := v.Name
		switch {
		case strings.HasPrefix(oid, oidIfIndex):
			ifIndex = fmt.Sprintf("%v", v.Value)
		case strings.HasPrefix(oid, oidIfDescr):
			if val, ok := v.Value.([]byte); ok {
				ifDescr = string(val)
			} else {
				ifDescr = fmt.Sprintf("%v", v.Value)
			}
		case strings.HasPrefix(oid, oidIfOperStatus):
			switch val := v.Value.(type) {
			case int:
				if val == 1 {
					ifOperStatus = "up"
				} else {
					ifOperStatus = "down"
				}
			default:
				ifOperStatus = fmt.Sprintf("%v", v.Value)
			}
		case strings.HasPrefix(oid, oidIfAdminStat):
			// Captured but not used in message — available for future use
		}
	}

	trap := &models.TrapEvent{
		Timestamp: time.Now(),
	}

	if isLinkDown {
		trap.TrapOID = oidLinkDown
		trap.TrapType = "LINK_DOWN"
		trap.Severity = "warning"
		trap.Message = formatLinkMessage("LINK_DOWN", ifIndex, ifDescr, ifOperStatus)
	} else {
		trap.TrapOID = oidLinkUp
		trap.TrapType = "LINK_UP"
		trap.Severity = "info"
		trap.Message = formatLinkMessage("LINK_UP", ifIndex, ifDescr, ifOperStatus)
	}

	return trap
}

func formatLinkMessage(trapType, ifIndex, ifDescr, ifOperStatus string) string {
	var parts []string
	parts = append(parts, trapType)
	if ifDescr != "" {
		parts = append(parts, fmt.Sprintf("interface=%s", ifDescr))
	}
	if ifIndex != "" {
		parts = append(parts, fmt.Sprintf("ifIndex=%s", ifIndex))
	}
	if ifOperStatus != "" {
		parts = append(parts, fmt.Sprintf("status=%s", ifOperStatus))
	}
	return strings.Join(parts, " ")
}

// lookupTrapOID searches all registered vendor profiles for the given trap OID.
func lookupTrapOID(oid string) (trapType string, severity string) {
	vendorMu.RLock()
	defer vendorMu.RUnlock()
	for _, profile := range vendorRegistry {
		if def, ok := profile.TrapOIDs()[oid]; ok {
			return def.Type, def.Severity
		}
	}
	return "", ""
}

func (t *TrapReceiver) formatTrapMessage(v gosnmp.SnmpPDU, oid string) string {
	var sb strings.Builder
	trapType, _ := lookupTrapOID(oid)
	if trapType == "" {
		trapType = "UNKNOWN"
	}
	sb.WriteString(trapType)

	switch v.Type {
	case gosnmp.OctetString:
		sb.WriteString(": ")
		if val, ok := v.Value.([]byte); ok {
			sb.WriteString(string(val))
		}
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks:
		sb.WriteString(": ")
		sb.WriteString(fmt.Sprintf("%d", v.Value))
	}

	return sb.String()
}
