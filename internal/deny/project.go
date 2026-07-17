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
	"strconv"
	"strings"

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
// the hot path.
func hasDenySignal(message string, cfg PatternConfig) bool {
	if strings.Contains(message, `action="deny"`) {
		return true
	}
	if cfg.Pattern != "" && strings.Contains(message, `action="start"`) {
		return true
	}
	return false
}

// Project derives a DeniedEvent from a FortiGate syslog message, or ok=false if
// the message is not a denial (the common case — those never touch the table).
// tm may be nil (Match is nil-safe → ThreatFlag 0, no escalation).
func Project(msg *models.SyslogMessage, tm *threatintel.Holder, cfg PatternConfig) (models.DeniedEvent, bool) {
	if msg == nil || !hasDenySignal(msg.Message, cfg) {
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
	// Drop scope-local noise (multicast / link-local / limited broadcast) at the
	// source — a burst of internal SSDP/mDNS/broadcast denies would otherwise
	// manufacture a fake victim. classify.ScopeLocal does not catch subnet-
	// directed broadcast (no netmask here), which the deny_storm_victim
	// distinct-source threshold tolerates.
	if classify.ScopeLocal(src, dst) {
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
		PolicyName:  f["policyname"],
		Service:     f["service"],
		Signal:      signal,
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
func capStr(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
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
