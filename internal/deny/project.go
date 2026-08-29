// Package deny projects FortiGate syslog action="deny" log lines into the
// compact, indexed models.DeniedEvent rows the Tranche 4 Phase 2 deny detectors
// aggregate over. Projection runs at syslog ingest (the HTTP collector-relay
// handler): it reuses the logfields KV parser and the threat-intel matcher —
// neither of which the leaf detect package may import — so detectors only ever
// see clean typed columns.
//
// Phase 0 proved FortiOS does not export blocked sessions via NetFlow, so
// syslog action="deny" is the only FortiGate deny source. Local-in denies
// (traffic to the firewall's own IPs) and, once `logtraffic all` is enabled on
// the deny policies, forward/transit denies both land here.
package deny

import (
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/logfields"
	"firewall-mon/internal/models"
	"firewall-mon/internal/threatintel"
)

// PatternConfig carries the operator-configurable block-policy-name pattern.
// A FortiGate "block" policy that logs a session as action="start" (the
// accept-log-drop convention, e.g. IP_BLOCK-1) is a denial in intent; when its
// policyname matches Pattern we project it with Signal=2. Empty Pattern = off
// (only literal action="deny" projects).
type PatternConfig struct {
	Pattern string // case-insensitive glob, '*' wildcard; "" disables
}

// literal returns the fixed leading segment of the glob (before the first '*'),
// used as a cheap substring pre-filter so an action="start" line only pays the
// full KV parse when the block-policy name plausibly appears in it. "" when the
// pattern starts with a wildcard (then every start line must be parsed).
func (c PatternConfig) literal() string {
	if i := strings.IndexByte(c.Pattern, '*'); i >= 0 {
		return c.Pattern[:i]
	}
	return c.Pattern
}

// matches reports whether a policyname matches the block-policy glob. Only '*'
// is special (prefix/suffix/substring). Case-insensitive. Not a regexp — no
// ReDoS surface on the ingest hot path.
func (c PatternConfig) matches(policyName string) bool {
	if c.Pattern == "" || policyName == "" {
		return false
	}
	return globMatch(strings.ToLower(c.Pattern), strings.ToLower(policyName))
}

// globMatch is a minimal '*'-only glob (the pattern language operators expect
// from firewall policy naming). Anchored at both ends.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s // no wildcard: exact
	}
	// Leading segment must be a prefix.
	if parts[0] != "" && !strings.HasPrefix(s, parts[0]) {
		return false
	}
	// Trailing segment must be a suffix.
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(s, last) {
		return false
	}
	// Middle segments must appear in order.
	pos := 0
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		i := strings.Index(s[pos:], seg)
		if i < 0 {
			return false
		}
		pos += i + len(seg)
	}
	return true
}

// hasDenySignal is the cheap pre-parse gate: only messages that could be a deny
// pay the KV-parse cost, so the majority non-deny syslog stream is untouched on
// the hot path. For the block-policy action="start" case we ALSO require the
// pattern's literal prefix (e.g. "IP_BLOCK") to appear in the raw line, so a
// device logging every session start (logtraffic-start) doesn't parse them all
// — only the block-named ones. A wildcard-leading pattern has no literal, so it
// falls back to parsing every start line (rare config).
func hasDenySignal(message string, cfg PatternConfig) bool {
	if strings.Contains(message, `action="deny"`) {
		return true
	}
	if cfg.Pattern != "" && strings.Contains(message, `action="start"`) {
		if lit := cfg.literal(); lit == "" || containsFold(message, lit) {
			return true
		}
	}
	return false
}

// containsFold is a case-insensitive strings.Contains. It only runs on the
// action="start" subset that already passed the literal Contains, so the
// lowercase allocation is off the bulk hot path.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// Project derives a DeniedEvent from a FortiGate syslog message, or ok=false if
// the message is not a denial (the common case — those never touch the table).
// tm may be nil (Match is nil-safe → ThreatFlag 0, no escalation). Back-compat
// entry point; new callers should use ProjectVendor with the device vendor.
func Project(msg *models.SyslogMessage, tm *threatintel.Holder, cfg PatternConfig) (models.DeniedEvent, bool) {
	return ProjectVendor("fortigate", msg, tm, cfg)
}

// ProjectVendor derives a DeniedEvent from a syslog message under the device's
// vendor (AUDIT-280). FortiGate uses the action="deny"/block-policy heuristics;
// OPNsense/pfSense parse the pf `filterlog` block/reject verdict. Unknown
// vendors fall through to the FortiGate parser (the historical default) so no
// existing FortiGate deny stops projecting.
func ProjectVendor(vendor string, msg *models.SyslogMessage, tm *threatintel.Holder, cfg PatternConfig) (models.DeniedEvent, bool) {
	if msg == nil {
		return models.DeniedEvent{}, false
	}
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "opnsense", "pfsense":
		return projectFilterlog(vendor, msg, tm)
	default:
		return projectFortiGate(msg, tm, cfg)
	}
}

// projectFilterlog projects an OPNsense/pfSense pf `filterlog` block/reject
// verdict into a DeniedEvent. Cheap-gated on the action word before any parse so
// the pass/accept majority of the filterlog stream is untouched on the hot path.
func projectFilterlog(vendor string, msg *models.SyslogMessage, tm *threatintel.Holder) (models.DeniedEvent, bool) {
	if !strings.Contains(msg.Message, "block") && !strings.Contains(msg.Message, "reject") {
		return models.DeniedEvent{}, false
	}
	f := logfields.Fields(vendor, msg)
	switch strings.ToLower(f["action"]) {
	case "block", "reject":
	default:
		return models.DeniedEvent{}, false
	}
	src, dst := f["srcip"], f["dstip"]
	if src == "" || dst == "" {
		return models.DeniedEvent{}, false
	}
	// Mirror the FortiGate path's structural IP validation (AUDIT-272) and
	// scope-local noise drop.
	srcIP, dstIP := net.ParseIP(src), net.ParseIP(dst)
	if srcIP == nil || dstIP == nil {
		return models.DeniedEvent{}, false
	}
	if classify.ScopeLocalIP(srcIP) || classify.ScopeLocalIP(dstIP) {
		return models.DeniedEvent{}, false
	}
	ev := models.DeniedEvent{
		Timestamp: msg.Timestamp,
		DeviceID:  msg.DeviceID,
		ProbeID:   msg.ProbeID,
		SrcAddr:   src,
		DstAddr:   dst,
		SrcPort:   atoiU16(f["srcport"]),
		DstPort:   atoiU16(f["dstport"]),
		Protocol:  atoiU8(f["proto"]),
		// filterlog names the interface, not a wan/lan/dmz role, and carries no
		// forward/local subtype — leave both Unknown rather than guess.
		SrcIntfRole: models.IntfRoleUnknown,
		Subtype:     models.DenySubtypeUnknown,
		Signal:      models.DenySignalAction,
	}
	if tm != nil {
		if _, ok := tm.Match(src); ok {
			ev.ThreatFlag |= 1
		}
		if _, ok := tm.Match(dst); ok {
			ev.ThreatFlag |= 2
		}
	}
	return ev, true
}

// projectFortiGate is the original FortiOS action="deny" / block-policy
// projection.
func projectFortiGate(msg *models.SyslogMessage, tm *threatintel.Holder, cfg PatternConfig) (models.DeniedEvent, bool) {
	if !hasDenySignal(msg.Message, cfg) {
		return models.DeniedEvent{}, false
	}
	f := logfields.Fields("fortigate", msg)

	action := f["action"]
	var signal uint8
	switch {
	case action == "deny":
		signal = models.DenySignalAction
	case action == "start" && cfg.matches(f["policyname"]):
		signal = models.DenySignalPattern
	default:
		return models.DeniedEvent{}, false
	}

	src, dst := f["srcip"], f["dstip"]
	if src == "" || dst == "" {
		return models.DeniedEvent{}, false
	}
	// AUDIT-272: require both endpoints to parse as real IPs. SrcAddr/DstAddr
	// land in INDEXED text columns; a crafted syslog line with a multi-KB
	// "srcip" would otherwise be stored verbatim (a >2704-byte value even
	// overflows the PG btree row limit and fails the batch INSERT). Parsing
	// structurally caps both at valid textual IP length — stronger than an
	// arbitrary byte cap. ScopeLocal's parse-failure semantics ("don't hide
	// unknowns") are for flow CHARTS; at ingest, garbage is rejected.
	srcIP, dstIP := net.ParseIP(src), net.ParseIP(dst)
	if srcIP == nil || dstIP == nil {
		return models.DeniedEvent{}, false
	}
	// Drop scope-local noise (multicast / link-local / limited broadcast) at the
	// source — a burst of internal SSDP/mDNS/broadcast denies would otherwise
	// manufacture a fake victim. The scope-local test does not catch subnet-
	// directed broadcast (no netmask here), which the deny_storm_victim
	// distinct-source threshold tolerates.
	if classify.ScopeLocalIP(srcIP) || classify.ScopeLocalIP(dstIP) {
		return models.DeniedEvent{}, false
	}

	ev := models.DeniedEvent{
		Timestamp:   msg.Timestamp,
		DeviceID:    msg.DeviceID,
		ProbeID:     msg.ProbeID,
		SrcAddr:     src,
		DstAddr:     dst,
		SrcPort:     atoiU16(f["srcport"]),
		DstPort:     atoiU16(f["dstport"]),
		Protocol:    atoiU8(f["proto"]),
		SrcIntfRole: intfRole(f["srcintfrole"]),
		Subtype:     subtype(f["subtype"]),
		SrcCountry:  capStr(f["srccountry"], 48),
		DstCountry:  capStr(f["dstcountry"], 48),
		PolicyID:    atoiU32(f["policyid"]),
		// AUDIT-312: cap the remaining free-text fields at 64 BYTES (capStr
		// cuts rune-safely). FortiOS limits policy names to 35 characters and
		// service names to 63, so 64 bytes is headroom for ASCII names; a
		// multibyte name may keep fewer characters, which is acceptable —
		// the point is bounding what a crafted multi-KB log line can bloat
		// this short-retention, volume-sized table with.
		PolicyName: capStr(f["policyname"], 64),
		Service:    capStr(f["service"], 64),
		Signal:     signal,
	}
	// Threat bitfield — bits 0/1 only (syslog carries no ASN).
	if tm != nil {
		if _, ok := tm.Match(src); ok {
			ev.ThreatFlag |= 1
		}
		if _, ok := tm.Match(dst); ok {
			ev.ThreatFlag |= 2
		}
	}
	return ev, true
}

func intfRole(s string) uint8 {
	switch strings.ToLower(s) {
	case "wan":
		return models.IntfRoleWAN
	case "lan":
		return models.IntfRoleLAN
	case "dmz":
		return models.IntfRoleDMZ
	case "undefined":
		return models.IntfRoleUndefined
	default:
		return models.IntfRoleUnknown
	}
}

func subtype(s string) uint8 {
	switch strings.ToLower(s) {
	case "local":
		return models.DenySubtypeLocal
	case "forward":
		return models.DenySubtypeForward
	default:
		return models.DenySubtypeUnknown
	}
}

// capStr bounds a stored FortiGate field so a crafted log can't bloat a row.
// The cut is rune-safe (AUDIT-272): these fields render in the UI, and a byte
// slice can split a multi-byte UTF-8 sequence mid-rune, storing invalid UTF-8.
// Backing up to the rune boundary keeps the result valid without allocating.
func capStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	// A byte with the top two bits 10xxxxxx is a UTF-8 continuation byte —
	// backing up past them lands on the start of the rune that straddles the
	// cut, which is then dropped whole. utf8.UTFMax bounds the walk.
	for cut > 0 && cut > max-utf8.UTFMax && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func atoiU16(s string) uint16 {
	n, _ := strconv.Atoi(s)
	if n < 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}

func atoiU8(s string) uint8 {
	n, _ := strconv.Atoi(s)
	if n < 0 || n > 255 {
		return 0
	}
	return uint8(n)
}

func atoiU32(s string) uint32 {
	n, _ := strconv.Atoi(s)
	if n < 0 {
		return 0
	}
	return uint32(n)
}
