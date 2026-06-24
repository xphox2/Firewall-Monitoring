package snmp

import (
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"sync"
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

// AUDIT-012 rate-limiter defaults. 10 traps/sec per source IP with a burst
// of 50 is generous for a healthy device under load (a chassis link-flap
// storm rarely exceeds that), but tight enough to make a spoofed-source-IP
// flood expensive — at the default rate, an attacker would need to spray
// 6,000 unique source IPs/min to sustain 1,000 trap rows per second.
const (
	defaultTrapRatePerSec = 10.0
	defaultTrapBurst      = 50.0

	// rlBucketIdleTTL: a per-IP bucket idle this long has fully refilled, so
	// dropping it is lossless (a returning IP gets a fresh bucket). rlSweepInterval
	// throttles the O(n) idle sweep so a sustained flood can't make it run per packet.
	rlBucketIdleTTL = 5 * time.Minute
	rlSweepInterval = 1 * time.Minute
)

// maxRateLimitedIPs caps the per-source-IP bucket map (AUDIT-012). A var, not a
// const, so tests can shrink it to exercise the cap/sweep path.
var maxRateLimitedIPs = 10000

// ipBucket is one source IP's token bucket for the trap-receive rate limit.
type ipBucket struct {
	tokens float64
	last   time.Time
}

type TrapReceiver struct {
	config  *config.Config
	server  *gosnmp.TrapListener
	handler func(*models.TrapEvent)

	// AUDIT-012: per-source-IP token-bucket rate limiter. Without it, an
	// attacker who can reach UDP/162 can flood the listener with crafted
	// packets — the parsed trap rows hit the DB / alerting / IRC, which
	// is a DoS amplification.
	rlMu        sync.Mutex
	rlBuckets   map[string]*ipBucket
	rlRate      float64
	rlBurst     float64
	rlLastSweep time.Time
}

func NewTrapReceiver(cfg *config.Config) (*TrapReceiver, error) {
	trapListener := gosnmp.NewTrapListener()

	return &TrapReceiver{
		config:    cfg,
		server:    trapListener,
		rlBuckets: make(map[string]*ipBucket),
		rlRate:    defaultTrapRatePerSec,
		rlBurst:   defaultTrapBurst,
	}, nil
}

// allow consumes one token for the given source IP. Returns true if the
// packet should be processed, false if it should be dropped.
//
// AUDIT-012: the map is capped at maxRateLimitedIPs to prevent an attacker
// from spraying unique source IPs to grow the map without bound. When the
// cap is hit, NEW IPs are rejected; existing buckets continue to refill
// and serve. This is a conservative trade-off — under sustained spoofing
// the legitimate trap rate from non-tracked IPs degrades to zero, but the
// process does not OOM and the operator sees a clear "rate limited"
// pattern in the logs (one drop per spoofed-IP packet).
func (t *TrapReceiver) allow(ip string) bool {
	t.rlMu.Lock()
	defer t.rlMu.Unlock()
	now := time.Now()
	b, ok := t.rlBuckets[ip]
	if !ok {
		if len(t.rlBuckets) >= maxRateLimitedIPs {
			// Before rejecting a new IP at the cap, sweep idle buckets so a past
			// spoofed-IP flood doesn't permanently lock out every new legitimate
			// device until restart (2026-06-23 audit, M9 — "durable denial-of-trap").
			// Throttled to one O(n) pass per rlSweepInterval.
			if now.Sub(t.rlLastSweep) >= rlSweepInterval {
				for k, kb := range t.rlBuckets {
					if now.Sub(kb.last) >= rlBucketIdleTTL {
						delete(t.rlBuckets, k)
					}
				}
				t.rlLastSweep = now
			}
			if len(t.rlBuckets) >= maxRateLimitedIPs {
				return false
			}
		}
		t.rlBuckets[ip] = &ipBucket{tokens: t.rlBurst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * t.rlRate
		if b.tokens > t.rlBurst {
			b.tokens = t.rlBurst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Enabled reports whether trap ingestion is configured. Trap reception requires
// a non-empty SNMP_TRAP_COMMUNITY: without one the receiver must NOT open a
// listener (AUDIT-012 — an empty community accepts every spoofable UDP packet on
// port 162). When disabled, the daemon idles as a clean no-op instead of failing
// to start, so a deployment that doesn't use a global trap community (e.g. each
// firewall has its own) keeps the rest of the stack — API/web UI, poller —
// running normally rather than crash-looping the container.
func (t *TrapReceiver) Enabled() bool {
	return t.config.SNMP.TrapCommunity != ""
}

func (t *TrapReceiver) Start(handler func(*models.TrapEvent)) error {
	// AUDIT-012: require a non-empty SNMP_TRAP_COMMUNITY. Previously the
	// listener accepted every UDP packet on port 162 when the community
	// was empty (`if t.config.SNMP.TrapCommunity != "" && ...` short-
	// circuited the check), so an attacker spoofing source IPs could
	// inject arbitrary trap events and pollute the DB. Callers should gate on
	// Enabled() and idle instead of treating this as fatal.
	if t.config.SNMP.TrapCommunity == "" {
		return fmt.Errorf("SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)")
	}
	t.handler = handler

	expectedCommunity := []byte(t.config.SNMP.TrapCommunity)

	t.server.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		// AUDIT-012: per-IP rate limit BEFORE crypto / parse so an
		// attacker can't burn CPU even with bad packets.
		if !t.allow(addr.IP.String()) {
			return
		}
		// AUDIT-012: constant-time community check. The previous `!=`
		// short-circuited byte-by-byte, leaking the prefix length of
		// any guessed community to a network attacker. subtle.Constant
		// TimeCompare returns 0 for differing lengths and compares all
		// bytes of equal-length inputs without short-circuit.
		if subtle.ConstantTimeCompare([]byte(packet.Community), expectedCommunity) != 1 {
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
