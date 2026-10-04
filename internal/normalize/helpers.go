package normalize

import (
	"strings"

	"firewall-mon/internal/normalize/family"
)

// Shared vocabulary translations used by more than one mapper.

// protoNum maps a protocol as vendors spell it (`tcp`, `TCP`, `udp/ip`,
// `icmpv6`, or already numeric `6`) to the IANA number; nil when unknown.
func (ev *Event) protoNum(s string) *int16 {
	if s == "" {
		return nil
	}
	if n := ev.i16(s); n != nil {
		return n
	}
	s = strings.ToLower(s)
	if i := strings.IndexByte(s, '/'); i > 0 { // Meraki `udp/ip`
		s = s[:i]
	}
	switch s {
	case "icmp":
		return ev.p16(1)
	case "igmp":
		return ev.p16(2)
	case "tcp":
		return ev.p16(6)
	case "udp":
		return ev.p16(17)
	case "gre":
		return ev.p16(47)
	case "esp":
		return ev.p16(50)
	case "ah":
		return ev.p16(51)
	case "icmpv6", "icmp6", "ipv6-icmp":
		return ev.p16(58)
	case "ospf":
		return ev.p16(89)
	case "sctp":
		return ev.p16(132)
	}
	return nil
}

// actionWord maps the verdict words the vendors use to Action.
func actionWord(s string) Action {
	switch strings.ToLower(s) {
	case "allow", "allowed", "accept", "accepted", "permit", "pass", "passthrough", "detected", "a":
		return ActionAllow
	case "deny", "denied", "drop", "dropped", "block", "blocked", "d":
		return ActionDeny
	case "reject", "rejected", "reset", "r":
		return ActionReject
	case "timeout":
		return ActionTimeoutClose
	case "":
		return ActionUnknown
	}
	return ActionOther
}

// sevWord maps FortiOS / generic severity words to the 0-10 scale.
func (ev *Event) sevWord(s string) *int16 {
	switch strings.ToLower(s) {
	case "info", "information", "informational", "notice":
		return ev.p16(2)
	case "low":
		return ev.p16(3)
	case "medium", "warning":
		return ev.p16(5)
	case "high", "error":
		return ev.p16(7)
	case "critical", "alert", "emergency":
		return ev.p16(9)
	}
	return ev.i16(s) // CEF already uses 0-10
}

// dnsQType maps a record-type mnemonic to its RR type number.
func (ev *Event) dnsQType(s string) *int16 {
	switch strings.ToUpper(s) {
	case "A":
		return ev.p16(1)
	case "NS":
		return ev.p16(2)
	case "CNAME":
		return ev.p16(5)
	case "SOA":
		return ev.p16(6)
	case "PTR":
		return ev.p16(12)
	case "MX":
		return ev.p16(15)
	case "TXT":
		return ev.p16(16)
	case "AAAA":
		return ev.p16(28)
	case "SRV":
		return ev.p16(33)
	case "HTTPS":
		return ev.p16(65)
	case "ANY":
		return ev.p16(255)
	}
	return ev.i16(s)
}

// splitURL separates `scheme://host[:port]/path` into host and path; a bare
// host comes back with an empty path.
func splitURL(u string) (host, path string) {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexByte(u, '/'); i >= 0 {
		host, path = u[:i], u[i:]
	} else {
		host = u
	}
	if h, _ := splitHostPort(host); h != "" {
		host = h
	}
	return host, path
}

// mapText gives the free-text catalogue entries (family/text.go) their
// meaning; shared by the UniFi and pf mappers.
func mapText(tx *family.Text, ev *Event) Outcome {
	f := tx.Fields
	ev.VendorEventID = tx.Kind
	switch tx.Kind {
	case "dnsmasq_query":
		ev.Class, ev.Activity = ClassNetwork, ActivityDNS
		ev.SrcIP, ev.DNSQName, ev.DNSQType = ev.ip(f["src"]), f["qname"], ev.dnsQType(f["qtype"])
	case "dnsmasq_dhcpack":
		ev.Class, ev.Activity, ev.Action = ClassNetwork, ActivityDHCP, ActionAllow
		ev.SrcIP, ev.SrcMAC, ev.SrcHostname, ev.SrcIf = ev.ip(f["ip"]), parseMAC(f["mac"]), f["host"], f["iface"]
	case "sshd_accepted", "sshd_failed":
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogon, ActionAllow
		if tx.Kind == "sshd_failed" {
			ev.Action = ActionDeny
		}
		ev.AdminUser, ev.AdminSrcIP, ev.AdminMethod = f["user"], f["src"], "ssh"
		ev.SrcIP, ev.SrcPort = ev.ip(f["src"]), ev.port(f["port"])
		ev.extra("auth_method", f["method"])
	case "charon_established", "charon_deleted":
		ev.Class, ev.Activity = ClassVPNSession, ActivityTunnelUp
		if tx.Kind == "charon_deleted" {
			ev.Activity = ActivityTunnelDown
		}
		ev.TunnelName, ev.TunnelType, ev.TunnelPeer = f["tunnel"], "ipsec", ev.ip(f["peer"])
	case "openvpn_connected", "openvpn_disconnected":
		ev.Class, ev.Activity = ClassVPNSession, ActivityClientConnect
		if tx.Kind == "openvpn_disconnected" {
			ev.Activity = ActivityClientDisconnect
		}
		ev.User, ev.TunnelType, ev.TunnelPeer = f["user"], "openvpn", ev.ip(f["peer"])
		ev.SrcIP, ev.SrcPort = ev.ip(f["peer"]), ev.port(f["port"])
	default:
		return unparsed("text: " + tx.Kind + " not mapped")
	}
	return ok()
}

// mapFilterlog is the pf filterlog mapping shared by opnsense, pfsense and
// generic: one per-packet verdict. The tracker is pf's stable per-rule id
// (survives reorder), the rule number its position; both are kept.
func mapFilterlog(fl *family.Filterlog, ev *Event) Outcome {
	ev.Class, ev.Activity = ClassNetwork, ActivityPacket
	ev.VendorEventID = "filterlog"
	// pass / block / reject only: family.FindFilterlog's signature gate does
	// not recognise rdr / nat / binat records, which are translations rather
	// than firewall decisions.
	ev.Action = actionWord(fl.Action)
	ev.RuleUID = fl.Tracker
	ev.RuleID = ev.i64(fl.RuleNr)
	if fl.Dir == "out" {
		ev.DstIf = fl.Interface
	} else {
		ev.SrcIf = fl.Interface
	}
	ev.SrcIP, ev.DstIP = ev.ip(fl.Src), ev.ip(fl.Dst)
	ev.SrcPort, ev.DstPort = ev.port(fl.SrcPort), ev.port(fl.DstPort)
	ev.Proto = ev.protoNum(fl.Proto)
	ev.extra("reason", fl.Reason)
	return ok()
}

// mapCEFGeneric is the vendor-agnostic CEF mapping (generic vendor, or a
// FortiGate / other device switched to CEF output): the header names the
// signature and severity, the standard extension keys name the endpoints and
// the verdict. Anything vendor-prefixed stays in Native only.
func mapCEFGeneric(c *family.CEF, ev *Event) Outcome {
	x := c.Ext
	ev.VendorEventID = c.Vendor + "/" + c.Product + "/" + c.SignatureID
	ev.Severity = ev.sevWord(c.Severity)
	ev.SrcIP, ev.DstIP = ev.ip(x["src"]), ev.ip(x["dst"])
	ev.SrcPort, ev.DstPort = ev.port(x["spt"]), ev.port(x["dpt"])
	ev.Proto = ev.protoNum(x["proto"])
	ev.SrcMAC, ev.DstMAC = parseMAC(x["smac"]), parseMAC(x["dmac"])
	ev.SrcIf, ev.DstIf = x["deviceinboundinterface"], x["deviceoutboundinterface"]
	ev.User, ev.App = x["suser"], x["app"]
	ev.BytesOut, ev.BytesIn = ev.i64(x["out"]), ev.i64(x["in"])
	ev.Action = actionWord(x["act"])
	if r := x["request"]; r != "" {
		ev.URLHost, ev.URLPath = splitURL(r)
	}
	ev.Message = x["msg"]
	if ev.SrcIP != nil || ev.DstIP != nil {
		ev.Class, ev.Activity = ClassNetwork, ActivityTraffic
		ev.RuleName = x["cs1"] // the most common place vendors put a rule name
		return ok()
	}
	ev.Class, ev.Activity = ClassFinding, ActivityDetect
	ev.SigID, ev.SigName = c.SignatureID, c.Name
	return ok()
}
