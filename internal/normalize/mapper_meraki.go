package normalize

import (
	"regexp"
	"strings"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize/family"
)

func init() { Register(merakiMapper{}) }

// merakiMapper covers the Cisco Meraki MX / MR / MS syslog roles: flows (and
// the firewall / vpn_firewall / cellular_firewall variants), urls,
// ids-alerts / security_event, events and airmarshal_events. Meraki syslog
// carries no bytes, no rule id and no admin audit (those are API-only, Phase
// 2); the rule is identified by its `pattern:` text (tier n). Built from the
// documented samples; UNTESTED ON REAL HARDWARE.
type merakiMapper struct{}

func (merakiMapper) Vendor() string     { return "meraki" }
func (merakiMapper) Families() []Family { return []Family{FamilyMeraki} }

var merakiClientVPN = regexp.MustCompile(`user id '(?P<user>[^']+)' local ip (?P<ip>[0-9a-fA-F.:]+) connected from (?P<peer>[0-9a-fA-F.:]+)`)

func (merakiMapper) Map(tok Tokens, _ *models.SyslogMessage, ev *Event) Outcome {
	mk := tok.MK
	f := mk.Fields
	ev.VendorEventID = mk.Category
	switch mk.Category {
	case "flows", "firewall", "vpn_firewall", "cellular_firewall", "bridge_anyconnect_client_vpn_firewall":
		return merakiFlow(mk, ev)
	case "ip_flow_start", "ip_flow_end":
		ev.Class, ev.Activity, ev.Action = ClassNetwork, ActivityOpen, ActionAllow
		if mk.Category == "ip_flow_end" {
			ev.Activity = ActivityClose
		}
		merakiTuple(f, ev)
		ev.NatSrcIP, ev.NatSrcPort = ev.ip(f["translated_src_ip"]), ev.port(f["translated_port"])
	case "urls":
		ev.Class, ev.Activity = ClassNetwork, ActivityHTTP
		merakiTuple(f, ev)
		if mk.TailKind == "request" {
			method, u, _ := strings.Cut(mk.Tail, " ")
			if u == "" {
				u, method = method, ""
			}
			ev.URLHost, ev.URLPath = splitURL(u)
			ev.extra("method", method)
		}
	case "ids-alerts", "security_event":
		return merakiSecurity(mk, ev)
	case "events":
		return merakiEvent(mk, ev)
	case "airmarshal_events":
		ev.Class, ev.Activity = ClassFinding, ActivityDetect
		ev.SigName, ev.ThreatCat = merakiType(mk), "airmarshal"
		ev.SrcMAC = parseMAC(f["bssid"])
		ev.extra("ssid", f["ssid"])
		ev.extra("channel", f["channel"])
	default:
		return unparsed("meraki: category " + mk.Category + " not mapped")
	}
	return ok()
}

// merakiTuple reads `src=ip[:port] dst=ip[:port] mac= protocol= sport= dport=`.
func merakiTuple(f map[string]string, ev *Event) {
	sh, sp := splitHostPort(f["src"])
	dh, dp := splitHostPort(f["dst"])
	ev.SrcIP, ev.DstIP = ev.ip(sh), ev.ip(dh)
	ev.SrcPort, ev.DstPort = ev.port(firstNonEmpty(f["sport"], sp)), ev.port(firstNonEmpty(f["dport"], dp))
	ev.Proto = ev.protoNum(f["protocol"])
	ev.SrcMAC = parseMAC(firstNonEmpty(f["mac"], f["shost"]))
}

// merakiFlow: the verdict is the first word of `pattern:` (`allow` / `deny`,
// or the numeric form of the inbound rules — the Meraki Syslog Server
// Overview states "for inbound rules, 1 = deny and 0 = allow") or, on newer
// firmware, the word before `src=` (it arrives as the subtype). The rest of
// the pattern is the rule text, which is the rule's only identity in syslog
// (tier n): `allow all` → "all", `0 (tcp||udp) && dst port 443` → the
// expression. A verdict-first line without a pattern reports no rule.
func merakiFlow(mk *family.Meraki, ev *Event) Outcome {
	ev.Class, ev.Activity = ClassNetwork, ActivityTraffic
	merakiTuple(mk.Fields, ev)
	if mk.Category != "flows" && mk.Category != "firewall" {
		ev.Ruleset = mk.Category // vpn_firewall, cellular_firewall, bridge_anyconnect_client_vpn_firewall
	}
	verdict, rule := "", ""
	if mk.TailKind == "pattern" {
		if first, rest, _ := strings.Cut(mk.Tail, " "); merakiVerdict(first) != ActionUnknown {
			verdict, rule = first, rest
		} else {
			rule = mk.Tail
		}
	}
	if mk.Subtype != "" {
		verdict = firstWord(mk.Subtype)
	}
	ev.Action = merakiVerdict(verdict)
	ev.RuleName = strings.TrimSpace(rule)
	return ok()
}

// merakiVerdict maps the pattern / subtype verdict word.
func merakiVerdict(s string) Action {
	switch strings.ToLower(s) {
	case "allow", "0":
		return ActionAllow
	case "deny", "1":
		return ActionDeny
	}
	return ActionUnknown
}

// merakiType returns the `type=` value, also in the documented
// `type= rogue_ssid_detected` spelling (space after `=`), where the value
// arrives as the first subtype word.
func merakiType(mk *family.Meraki) string {
	if t, ok := mk.Fields["type"]; ok && t == "" {
		return firstWord(mk.Subtype)
	}
	return mk.Fields["type"]
}

// merakiSecurity: Snort IDS alerts (`signature=gid:sid:rev priority=
// direction= protocol= src= dst= [decision=blocked] message: <text>`) and
// AMP file dispositions (`security_event security_filtering_file_scanned
// url= src= dst= mac= name='…' sha256= disposition= action=`).
func merakiSecurity(mk *family.Meraki, ev *Event) Outcome {
	f := mk.Fields
	ev.Class, ev.Activity = ClassFinding, ActivityDetect
	merakiTuple(f, ev)
	sub := mk.Subtype
	if mk.Category == "ids-alerts" {
		sub = "ids_alerted"
	}
	ev.VendorEventID = mk.Category + "/" + sub
	switch sub {
	case "ids_alerted":
		ev.SigID, ev.ThreatCat = f["signature"], "ids"
		if mk.TailKind == "message" {
			ev.SigName = mk.Tail
		}
		ev.Severity = ev.merakiPriority(f["priority"])
		switch strings.ToLower(f["direction"]) {
		case "egress":
			ev.Direction = ptrDir(DirectionOutbound)
		case "ingress":
			ev.Direction = ptrDir(DirectionInbound)
		}
		ev.DstMAC = parseMAC(f["dhost"])
		switch {
		case strings.EqualFold(f["decision"], "blocked"), strings.EqualFold(f["action"], "block"), strings.EqualFold(f["action"], "drop"):
			ev.Action = ActionDeny
		case strings.EqualFold(f["action"], "rst"), strings.EqualFold(f["action"], "reset"):
			ev.Action = ActionReject
		default:
			ev.Action = ActionAllow
		}
	case "security_filtering_file_scanned", "security_filtering_disposition_change":
		disposition := strings.ToLower(f["disposition"])
		if u := f["url"]; u != "" {
			ev.URLHost, ev.URLPath = splitURL(u)
		}
		if disposition == "clean" {
			// A clean AMP scan is a file download that passed, not a finding.
			ev.Class, ev.Activity, ev.Action = ClassNetwork, ActivityHTTP, ActionAllow
			ev.extra("disposition", disposition)
			ev.extra("sha256", f["sha256"])
			return ok()
		}
		ev.SigName, ev.FileHash, ev.ThreatCat = f["name"], f["sha256"], disposition
		ev.Action = actionWord(f["action"])
	default:
		return unparsed("meraki: security_event " + sub + " not mapped")
	}
	return ok()
}

// merakiPriority: Snort priority 1 (highest) … 4 → 0-10 scale.
func (ev *Event) merakiPriority(s string) *int16 {
	switch s {
	case "1":
		return ev.p16(9)
	case "2":
		return ev.p16(7)
	case "3":
		return ev.p16(5)
	case "4":
		return ev.p16(3)
	}
	return nil
}

// merakiEvent: the `events` role mixes `type=… key='val'` records with free
// text (`failover to wan1`, `dhcp lease of ip …`).
func merakiEvent(mk *family.Meraki, ev *Event) Outcome {
	f := mk.Fields
	typ := merakiType(mk)
	ev.VendorEventID = "events/" + firstNonEmpty(typ, firstWord(mk.Subtype))
	switch typ {
	case "vpn_connectivity_change":
		ev.Class, ev.Activity = ClassVPNSession, ActivityTunnelDown
		if f["connectivity"] == "true" {
			ev.Activity = ActivityTunnelUp
		}
		ev.TunnelType, ev.TunnelName = f["vpn_type"], f["peer_ident"]
		if h, _ := splitHostPort(f["peer_contact"]); h != "" {
			ev.TunnelPeer = ev.ip(h)
		}
	case "client_vpn_connect", "anyconnect_vpn_connect":
		ev.Class, ev.Activity = ClassVPNSession, ActivityClientConnect
		ev.TunnelType = strings.TrimSuffix(typ, "_connect")
		if m := merakiClientVPN.FindStringSubmatch(mk.Subtype); m != nil {
			ev.User, ev.SrcIP, ev.TunnelPeer = m[1], ev.ip(m[2]), ev.ip(m[3])
		}
	case "8021x_auth", "8021x_eap_success":
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogon, ActionAllow
		ev.User, ev.SrcIf = f["identity"], f["port"]
	case "8021x_eap_failure":
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogon, ActionDeny
		ev.User, ev.SrcIf = f["identity"], f["port"]
	case "8021x_deauth": // the supplicant left; not a failed logon
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogoff, ActionUnknown
		ev.User, ev.SrcIf = f["identity"], f["port"]
	case "association", "disassociation":
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityConnect, ActionAllow
		if typ == "disassociation" {
			ev.Activity = ActivityDisconnect
		}
		ev.SrcMAC = parseMAC(f["client_mac"])
		ev.extra("channel", f["channel"])
		ev.extra("rssi", f["rssi"])
	case "":
		words := strings.Fields(mk.Subtype)
		switch {
		case len(words) >= 3 && words[0] == "failover" && words[1] == "to":
			ev.Class, ev.Activity, ev.WANName = ClassDeviceHealth, ActivityFailover, words[2]
		case len(words) >= 8 && words[0] == "dhcp" && words[1] == "lease":
			// dhcp lease of ip 192.0.2.10 for client mac 00:00:5E:00:53:0A from router …
			ev.Class, ev.Activity, ev.Action = ClassNetwork, ActivityDHCP, ActionAllow
			ev.SrcIP = ev.ip(words[4])
			for i := range words {
				if words[i] == "mac" && i+1 < len(words) {
					ev.SrcMAC = parseMAC(words[i+1])
				}
			}
		default:
			return unparsed("meraki: events text \"" + firstWord(mk.Subtype) + "…\" not mapped")
		}
	default:
		return unparsed("meraki: events type=" + typ + " not mapped")
	}
	ev.Message = mk.Subtype
	return ok()
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}
