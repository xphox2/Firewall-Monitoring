package snmp

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
)

// minTrapCommunityLen is the minimum SNMP_TRAP_COMMUNITY length (H-5). A short
// community is trivially guessable ("public" is 6 chars), which defeats the
// constant-time community check entirely: an attacker who guesses it can forge
// traps from any spoofable UDP source IP. Require enough entropy that guessing
// is infeasible.
const minTrapCommunityLen = 16

// trapRateLimitDrops counts trap datagrams the AUDIT-012 limiter dropped, by
// reason: "rate" = a tracked source exhausted its token bucket, "cap" = the
// source map was full so a NEW source was rejected. M29 of the 2026-07-01
// audit: drops were previously completely silent — no log line, no metric —
// despite code comments and the CHANGELOG claiming visibility, so legitimate
// traps lost during flap storms or spoof-flood lockouts left zero trace.
// Registered on the default registry, which the trap-receiver's /metrics
// serves; the metric simply stays 0 in the other binaries that link this
// package.
var trapRateLimitDrops = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "fwmon",
		Subsystem: "trap",
		Name:      "ratelimit_drops_total",
		Help:      "Trap datagrams dropped by the rate limiters, by reason (rate = per-source token exhaustion, cap = source-map full, global = receiver-wide cap).",
	},
	[]string{"reason"},
)

// trapCommunityDrops counts datagrams dropped by the D-18 header pre-check
// (wrong community, malformed header, SNMPv3). They are deliberately kept out
// of the rate limiters, so this is the only signal that a forged flood is
// arriving.
var trapCommunityDrops = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "fwmon",
	Subsystem: "trap",
	Name:      "community_drops_total",
	Help:      "Trap datagrams dropped before decoding because the header was malformed, SNMPv3, or carried the wrong community.",
})

func init() {
	prometheus.MustRegister(trapRateLimitDrops, trapCommunityDrops)
}

// Standard IETF trap OIDs (RFC 3418)
const (
	oidSnmpTrapOID  = ".1.3.6.1.6.3.1.1.4.1.0"
	oidSysUpTime    = ".1.3.6.1.2.1.1.3.0"
	oidLinkDown     = ".1.3.6.1.6.3.1.1.5.3"
	oidLinkUp       = ".1.3.6.1.6.3.1.1.5.4"
	oidIfIndex      = ".1.3.6.1.2.1.2.2.1.1"
	oidIfDescr      = ".1.3.6.1.2.1.2.2.1.2"
	oidIfOperStatus = ".1.3.6.1.2.1.2.2.1.8"
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
	handler func(*models.TrapEvent)

	// D-18: the receiver owns its UDP socket so it can drop unauthenticated
	// and over-rate datagrams before gosnmp's full BER decode. done is closed
	// when the read loop exits.
	conn     *net.UDPConn
	done     chan struct{}
	stopOnce sync.Once

	// AUDIT-012: per-source-IP token-bucket rate limiter. Without it, an
	// attacker who can reach UDP/162 can flood the listener with crafted
	// packets — the parsed trap rows hit the DB / alerting / IRC, which
	// is a DoS amplification.
	rlMu        sync.Mutex
	rlBuckets   map[string]*ipBucket
	rlRate      float64
	rlBurst     float64
	rlLastSweep time.Time
	// M29: drop tallies since the last summary log line, so drops are
	// operator-visible without one log write per flooded packet. Guarded by rlMu.
	rlDropsRate   uint64
	rlDropsCap    uint64
	rlDropsGlobal uint64
	rlLastDropLog time.Time

	// D-18: receiver-wide token bucket, guarded by rlMu.
	globalTokens float64
	globalLast   time.Time
	globalRate   float64
	globalBurst  float64
}

func NewTrapReceiver(cfg *config.Config) (*TrapReceiver, error) {
	return &TrapReceiver{
		config:       cfg,
		rlBuckets:    make(map[string]*ipBucket),
		rlRate:       defaultTrapRatePerSec,
		rlBurst:      defaultTrapBurst,
		globalTokens: defaultTrapGlobalBurst,
		globalRate:   defaultTrapGlobalRatePerSec,
		globalBurst:  defaultTrapGlobalBurst,
	}, nil
}

// allowGlobal consumes one token from the receiver-wide bucket (D-18).
func (t *TrapReceiver) allowGlobal() bool {
	t.rlMu.Lock()
	defer t.rlMu.Unlock()
	now := time.Now()
	if !t.globalLast.IsZero() {
		if elapsed := now.Sub(t.globalLast).Seconds(); elapsed > 0 {
			t.globalTokens += elapsed * t.globalRate
			if t.globalTokens > t.globalBurst {
				t.globalTokens = t.globalBurst
			}
		}
	}
	t.globalLast = now
	if t.globalTokens < 1 {
		t.recordDropLocked("global", now)
		return false
	}
	t.globalTokens--
	return true
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
				t.recordDropLocked("cap", now)
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
		t.recordDropLocked("rate", now)
		return false
	}
	b.tokens--
	return true
}

// recordDropLocked makes a rate-limiter drop operator-visible (M29 of the
// 2026-07-01 audit): the Prometheus counter increments per drop, and a summary
// log line fires at most once per minute so a flood can't turn the defense
// into a log-volume DoS. Caller holds rlMu.
func (t *TrapReceiver) recordDropLocked(reason string, now time.Time) {
	trapRateLimitDrops.WithLabelValues(reason).Inc()
	switch reason {
	case "cap":
		t.rlDropsCap++
	case "global":
		t.rlDropsGlobal++
	default:
		t.rlDropsRate++
	}
	if now.Sub(t.rlLastDropLog) >= time.Minute {
		log.Printf("trap rate-limiter: dropped %d datagram(s) in the last interval (%d over per-source rate, %d new sources rejected at the %d-source cap, %d over the receiver-wide cap) — legitimate traps may be lost during a flood; see fwmon_trap_ratelimit_drops_total",
			t.rlDropsRate+t.rlDropsCap+t.rlDropsGlobal, t.rlDropsRate, t.rlDropsCap, maxRateLimitedIPs, t.rlDropsGlobal)
		t.rlDropsRate, t.rlDropsCap, t.rlDropsGlobal = 0, 0, 0
		t.rlLastDropLog = now
	}
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
	// H-5: require minimum community entropy. A short/guessable community makes
	// the constant-time compare pointless — an attacker who guesses it can forge
	// traps from any spoofable UDP source IP.
	if len(t.config.SNMP.TrapCommunity) < minTrapCommunityLen {
		return fmt.Errorf("SNMP_TRAP_COMMUNITY must be at least %d characters; refusing to start the trap listener with a weak community (H-5)", minTrapCommunityLen)
	}
	t.handler = handler

	// gosnmp's listener also accepted a "tcp://" prefix; SNMP traps are UDP
	// (RFC 3417) and this receiver only speaks UDP, so say so plainly.
	listen := strings.TrimPrefix(t.config.SNMP.TrapListenAddr, "udp://")
	if strings.Contains(listen, "://") {
		return fmt.Errorf("SNMP_TRAP_LISTEN %q: only UDP is supported (use host:port)", t.config.SNMP.TrapListenAddr)
	}
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("failed to start trap listener: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start trap listener: %w", err)
	}
	t.conn = conn
	t.done = make(chan struct{})

	// The socket is bound above so a bind failure is still a startup error;
	// the read loop runs in the background. (gosnmp's Listen blocked forever,
	// so the caller's post-Start work — the M25 cooldown prune, the LC-9
	// policy refresh and the shutdown path — never ran.)
	go t.readLoop([]byte(t.config.SNMP.TrapCommunity))
	return nil
}

// trapReadBuf is the receive buffer: the largest UDP payload, so no datagram
// is silently truncated into a decode error.
const trapReadBuf = 65535

func (t *TrapReceiver) readLoop(expectedCommunity []byte) {
	defer close(t.done)
	buf := make([]byte, trapReadBuf)
	for {
		n, addr, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("trap receiver: read error: %v", err)
			continue
		}
		if resp := t.handleDatagram(buf[:n], addr, expectedCommunity); resp != nil {
			if _, err := t.conn.WriteToUDP(resp, addr); err != nil {
				log.Printf("trap receiver: inform response to %s: %v", addr.IP, err)
			}
		}
	}
}

// handleDatagram runs one datagram through the D-18 filter order — each
// stage cheaper than the next, so a flood is shed as early as possible:
//
//  1. community pre-check on the raw header (no PDU decode). Unauthenticated
//     datagrams stop here and never touch the rate-limiter state, so a
//     spoofed-source flood cannot fill the per-IP map or drain the global
//     budget that legitimate traps need;
//  2. per-source token bucket (AUDIT-012);
//  3. receiver-wide token bucket;
//  4. full gosnmp decode, classification and the handler.
//
// It returns the response to send for an InformRequest, else nil.
func (t *TrapReceiver) handleDatagram(msg []byte, addr *net.UDPAddr, expectedCommunity []byte) []byte {
	// AUDIT-012: constant-time community check. subtle.ConstantTimeCompare
	// returns 0 for differing lengths and compares all bytes of equal-length
	// inputs without short-circuit, so it leaks no prefix length.
	community, ok := trapCommunity(msg)
	if !ok || subtle.ConstantTimeCompare(community, expectedCommunity) != 1 {
		trapCommunityDrops.Inc()
		return nil
	}
	if !t.allow(addr.IP.String()) || !t.allowGlobal() {
		return nil
	}

	// The decoded packet's OctetString values alias the datagram, and the read
	// loop reuses its buffer for the next one: decode a private copy, so
	// nothing derived from this trap can change under a later read.
	packet, err := decodeTrap(append([]byte(nil), msg...))
	if err != nil {
		return nil
	}
	// The decoder must agree with the pre-check; anything else is a crafted
	// header and is dropped.
	if subtle.ConstantTimeCompare([]byte(packet.Community), expectedCommunity) != 1 {
		return nil
	}
	if trap := t.parseTrap(packet, addr); trap != nil && t.handler != nil {
		t.handler(trap)
	}
	if packet.PDUType == gosnmp.InformRequest {
		// RFC 3416 4.2.7: acknowledge with the same varbinds, noError.
		packet.PDUType = gosnmp.GetResponse
		packet.Error = gosnmp.NoError
		packet.ErrorIndex = 0
		out, err := packet.MarshalMsg()
		if err != nil {
			return nil
		}
		return out
	}
	return nil
}

// decodeTrap runs gosnmp's full decoder on an authenticated datagram. The
// recover covers only the decoder — a crafted body must not kill the
// receiver — so a panic in the alert handler still surfaces as a crash
// instead of being mislabelled as a malformed packet.
func decodeTrap(msg []byte) (packet *gosnmp.SnmpPacket, err error) {
	defer func() {
		if r := recover(); r != nil {
			packet, err = nil, fmt.Errorf("trap decode panic: %v", r)
		}
	}()
	return gosnmp.Default.UnmarshalTrap(msg, false)
}

func (t *TrapReceiver) Stop() {
	t.stopOnce.Do(func() {
		if t.conn == nil {
			return
		}
		t.conn.Close()
		select {
		case <-t.done:
		case <-time.After(3 * time.Second):
		}
	})
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

	// Phase 2: Vendor-specific trap lookup. Per RFC 3418 the notification OID
	// that identifies the trap arrives as the VALUE of the snmpTrapOID.0
	// varbind, NOT as a varbind name — so classify by that value first, the way
	// the collector's parseTrap does (Firewall-Collector internal/snmp/trap.go).
	// Without this, vendor VPN/HA/IPS traps never classified and parseTrap
	// silently discarded them (AUDIT-296).
	var trapOIDValue string
	for _, v := range packet.Variables {
		if v.Name == oidSnmpTrapOID {
			if oid, ok := v.Value.(string); ok {
				trapOIDValue = oid
			}
			break
		}
	}
	if trapOIDValue != "" {
		if trapType, severity := lookupTrapOID(trapOIDValue); trapType != "" {
			trap.TrapOID = trapOIDValue
			trap.TrapType = trapType
			trap.Severity = severity
			trap.Message = t.formatTrapMessage(firstDataVarbind(packet), trapOIDValue)
		}
	}

	// Fallback: some devices send the notification OID as a varbind NAME rather
	// than as the snmpTrapOID.0 value. The collector keeps both paths.
	if trap.TrapOID == "" {
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
	}

	if trap.TrapOID == "" {
		return nil
	}

	return trap
}

// firstDataVarbind returns the first varbind that is not the snmpTrapOID.0 or
// sysUpTime.0 wrapper — a representative payload varbind for the trap message.
// It shares the collector's wrapper-skip set (those two OIDs) but not its full
// message body: the collector's buildTrapMessage joins ALL data varbinds,
// whereas this uses just the first (full parity is a later cross-repo batch).
// Returns a zero PDU when the packet carries only wrappers, in which case
// formatTrapMessage emits just the trap-type label.
func firstDataVarbind(packet *gosnmp.SnmpPacket) gosnmp.SnmpPDU {
	for _, v := range packet.Variables {
		if v.Name == oidSnmpTrapOID || v.Name == oidSysUpTime {
			continue
		}
		return v
	}
	return gosnmp.SnmpPDU{}
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
		case strings.HasPrefix(oid, oidIfIndex+"."):
			ifIndex = fmt.Sprintf("%v", v.Value)
		case strings.HasPrefix(oid, oidIfDescr+"."):
			if val, ok := v.Value.([]byte); ok {
				ifDescr = string(val)
			} else {
				ifDescr = fmt.Sprintf("%v", v.Value)
			}
		case strings.HasPrefix(oid, oidIfOperStatus+"."):
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
	// AUDIT-239: ifDescr is a raw attacker-controlled OctetString, so this is the
	// second trap-message producer (besides formatTrapMessage). Sanitize and cap
	// at the single return so the linkUp/linkDown path can't forge log lines or
	// bloat a row either.
	return sanitizeTrapField(strings.Join(parts, " "))
}

// NormalizeTrapType puts a trap type name in the canonical form the alert
// types (models.AlertType), the seeded trap rules (`trap_type eq
// HA_STATE_CHANGE`) and the FortiGate profile use: upper-case, `-` to `_`.
// The Palo Alto and SonicWall profiles name their traps in lower-kebab form
// (`ha-state-change`), so a PAN HA transition never matched the HA_STATE_CHANGE
// seed; applying this at the one lookup (and at the relay ingest for a
// collector that still sends the raw profile name) makes the casing a
// non-issue everywhere downstream.
func NormalizeTrapType(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
}

// lookupTrapOID searches all registered vendor profiles for the given trap OID.
// The returned type is normalized (NormalizeTrapType), whatever the profile's
// own spelling.
func lookupTrapOID(oid string) (trapType string, severity string) {
	vendorMu.RLock()
	defer vendorMu.RUnlock()
	for _, profile := range vendorRegistry {
		if def, ok := profile.TrapOIDs()[oid]; ok {
			return NormalizeTrapType(def.Type), def.Severity
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

	// AUDIT-239: the OctetString value above is raw attacker-controlled bytes.
	// Strip control characters (embedded CR/LF forge extra log lines — CWE-117 —
	// once this reaches log.Printf in the trap-receiver, and pollute the alerts
	// table + notifier payloads via ProcessTrap) and cap the total length so a
	// crafted trap can't bloat a row. Applied to the whole message so ANY
	// varbind type is cleaned.
	return sanitizeTrapField(sb.String())
}

// maxTrapMessageLen caps a formatted trap message before it reaches the log and
// the DB (Alert.Message → alerts table + notifier payloads).
const maxTrapMessageLen = 256

// sanitizeTrapField strips CR/LF and other ASCII control characters from an
// attacker-controlled trap value (so it can't forge extra log lines) and caps
// its length to maxTrapMessageLen runes. Mirrors handlers.sanitizeLogField /
// truncateField, reimplemented here because that helper lives in the handlers
// package and is not importable from internal/snmp (AUDIT-239).
func sanitizeTrapField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxTrapMessageLen {
		s = string(r[:maxTrapMessageLen])
	}
	return s
}
