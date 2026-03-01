package snmp

import (
	"fmt"
	"net"
	"strings"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"

	"github.com/gosnmp/gosnmp"
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

	for _, v := range packet.Variables {
		oid := v.Name

		if strings.HasPrefix(oid, "1.3.6.1.4.1.12356.101.2.0") {
			trap.TrapOID = oid
			trap.TrapType = t.getTrapType(oid)
			trap.Severity = t.getTrapSeverity(oid)
			trap.Message = t.formatTrapMessage(v, oid)
		}
	}

	return trap
}

func (t *TrapReceiver) getTrapType(oid string) string {
	switch oid {
	case TrapVPNTunnelUp:
		return "VPN_TUNNEL_UP"
	case TrapVPNTunnelDown:
		return "VPN_TUNNEL_DOWN"
	case TrapHASwitch:
		return "HA_SWITCH"
	case TrapHAStateChange:
		return "HA_STATE_CHANGE"
	case TrapHAHBFail:
		return "HA_HEARTBEAT_FAIL"
	case TrapHAMemberDown:
		return "HA_MEMBER_DOWN"
	case TrapHAMemberUp:
		return "HA_MEMBER_UP"
	case TrapIPSSignature:
		return "IPS_SIGNATURE"
	case TrapIPSanomaly:
		return "IPS_ANOMALY"
	case TrapAVVirus:
		return "AV_VIRUS"
	case TrapAVOversize:
		return "AV_OVERSIZE"
	default:
		return "UNKNOWN"
	}
}

func (t *TrapReceiver) getTrapSeverity(oid string) string {
	switch oid {
	case TrapVPNTunnelDown, TrapHAHBFail, TrapHAMemberDown, TrapIPSSignature,
		TrapIPSanomaly, TrapAVVirus:
		return "critical"
	case TrapHASwitch, TrapHAStateChange:
		return "warning"
	default:
		return "info"
	}
}

func (t *TrapReceiver) formatTrapMessage(v gosnmp.SnmpPDU, oid string) string {
	var sb strings.Builder
	sb.WriteString(t.getTrapType(oid))

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
