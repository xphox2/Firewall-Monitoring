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

		// Look up trap OID across all registered vendor profiles
		trapType, severity := lookupTrapOID(oid)
		if trapType != "" {
			trap.TrapOID = oid
			trap.TrapType = trapType
			trap.Severity = severity
			trap.Message = t.formatTrapMessage(v, oid)
			break
		}
	}

	// Return nil if no recognized trap OID was found
	if trap.TrapOID == "" {
		return nil
	}

	return trap
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
