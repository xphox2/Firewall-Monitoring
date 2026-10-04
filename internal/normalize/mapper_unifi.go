package normalize

import (
	"regexp"
	"strings"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize/family"
)

func init() { Register(unifiMapper{}) }

// unifiMapper covers the two UniFi syslog streams: the SIEM integration (CEF,
// UniFi Network 8.5+; event ids 100 / 112 / 113 / 201 / 400-402 / 512 / 544 /
// 578 and UniFi OS 1005) and the gateway's own syslog (kernel netfilter LOG
// prefixes for logged firewall rules, dnsmasq for DNS / DHCP). Built from the
// vendor documentation and community decoders; UNTESTED ON REAL HARDWARE —
// every key name below is as documented, not as observed by this project.
type unifiMapper struct{}

func (unifiMapper) Vendor() string     { return "unifi" }
func (unifiMapper) Families() []Family { return []Family{FamilyCEF, FamilyNetfilter, FamilyText} }

func (unifiMapper) Map(tok Tokens, _ *models.SyslogMessage, ev *Event) Outcome {
	switch tok.Family {
	case FamilyCEF:
		return unifiCEF(tok.CEF, ev)
	case FamilyNetfilter:
		return unifiNetfilter(tok.NF, ev)
	default:
		return mapText(tok.TX, ev)
	}
}

// unifiConfigMsg is UniFi OS event 1005's free-text body:
// `alice changed Device Name from "old" to "new". Source IP: 192.0.2.10`
// `Alice B. changed Syslog Settings Mode setting from "off" to "external". Source IP: 192.0.2.10`
// — the admin display name may contain spaces, so it runs lazily up to
// ` changed `.
var unifiConfigMsg = regexp.MustCompile(`^(?P<admin>.+?) changed (?P<setting>.+?) from "(?P<old>[^"]*)" to "(?P<new>[^"]*)"\.?(?: Source IP: (?P<ip>[0-9a-fA-F.:]+))?`)

func unifiCEF(c *family.CEF, ev *Event) Outcome {
	x := c.Ext
	ev.VendorEventID = c.Product + "/" + c.SignatureID
	ev.Severity = ev.sevWord(c.Severity)
	ev.Message = x["msg"]
	switch c.SignatureID {
	case "201": // Threat Detected and Blocked (IPS/IDS, blocklists)
		ev.Class, ev.Activity = ClassFinding, ActivityDetect
		// Blocklist / honeypot hits carry no signature keys; the CEF name
		// stands in for the signature name and the id stays NULL.
		ev.SigID, ev.SigName = x["unifiipssignatureid"], firstNonEmpty(x["unifiipssignature"], c.Name)
		ev.ThreatCat = strings.ToLower(firstNonEmpty(x["unifipolicytype"], "ips"))
		ev.Ruleset = ev.ThreatCat // the policy name is unique per policy type (IDS / IPS / …)
		ev.Action = unifiAct(x["act"])
		ev.SrcIP, ev.DstIP = ev.ip(x["src"]), ev.ip(x["dst"])
		ev.SrcPort, ev.DstPort = ev.port(x["spt"]), ev.port(x["dpt"])
		ev.Proto = ev.protoNum(x["proto"])
		ev.App, ev.RuleName = x["app"], x["unifipolicyname"]
		ev.SrcZone, ev.DstZone = x["unifisrczone"], x["unifidstzone"]
		ev.SrcMAC, ev.SrcHostname = parseMAC(x["unifisrcclientmac"]), x["unifisrcclienthostname"]
		ev.BytesOut, ev.BytesIn = ev.i64(x["unifibytessent"]), ev.i64(x["unifibytesreceived"])
		ev.PktsOut, ev.PktsIn = ev.i64(x["unifipacketssent"]), ev.i64(x["unifipacketsreceived"])
		ev.SessionID = x["unifiipssessionid"]
		switch strings.ToLower(x["unifidirection"]) {
		case "inbound", "incoming":
			ev.Direction = ptrDir(DirectionInbound)
		case "outbound", "outgoing":
			ev.Direction = ptrDir(DirectionOutbound)
		}
		ev.extra("risk", x["unifirisk"])
	case "100": // Internet Down
		ev.Class, ev.Activity = ClassDeviceHealth, ActivityWANDown
		ev.WANName = x["unifiwanname"]
	case "112": // High Latency
		ev.Class, ev.Activity = ClassDeviceHealth, ActivityLatency
		ev.WANName, ev.MetricName = x["unifiwanname"], "latency_ms"
		ev.MetricValue = ev.f64(strings.TrimSuffix(strings.TrimSpace(x["unifiwanlatency"]), "ms"))
	case "113": // Packet Loss Detected — the record names the WAN (name / id / ISP / subnet / SLA) but carries no loss figure
		ev.Class, ev.Activity = ClassDeviceHealth, ActivityPacketLoss
		ev.WANName = x["unifiwanname"]
		ev.extra("wan_sla", x["unifiwansla"])
	case "400", "401", "402": // WiFi client connected / disconnected / roamed
		ev.Class, ev.Action = ClassAuth, ActionAllow
		ev.Activity = map[string]Activity{"400": ActivityConnect, "401": ActivityDisconnect, "402": ActivityRoam}[c.SignatureID]
		ev.SrcMAC, ev.SrcIP = parseMAC(x["unificlientmac"]), ev.ip(x["unificlientip"])
		ev.SrcHostname = firstNonEmpty(x["unificlienthostname"], x["unificlientalias"])
		ev.extra("ssid", x["unifissid"])
		ev.extra("ap", x["unifiapname"])
	case "512": // Device Offline
		ev.Class, ev.Activity = ClassDeviceHealth, ActivityDeviceOffline
		ev.SrcHostname = firstNonEmpty(x["unifidevicename"], x["unificonnectedtodevicename"])
		ev.SrcMAC = parseMAC(firstNonEmpty(x["unifidevicemac"], x["unificonnectedtodevicemac"]))
	case "544": // Admin Accessed UniFi Network
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogon, ActionAllow
		ev.AdminUser = firstNonEmpty(x["unifiadmin"], x["suser"])
		ev.AdminSrcIP = x["src"]
		ev.AdminMethod = unifiAccessMethod(x["unifiaccessmethod"])
	case "578": // Network Updated (application version)
		ev.Class, ev.Activity = ClassDeviceHealth, ActivitySoftware
		ev.extra("version", x["unifiapplicationversion"])
		ev.extra("prior_version", x["unifiapplicationpriorversion"])
	case "1005": // UniFi OS: Admin Made Config Changes (free text)
		ev.Class, ev.Activity = ClassConfigChange, ActivityUpdate
		ev.AdminMethod = "gui"
		if m := unifiConfigMsg.FindStringSubmatch(x["msg"]); m != nil {
			ev.AdminUser, ev.ConfigPath, ev.ConfigOld, ev.ConfigNew, ev.AdminSrcIP = m[1], m[2], m[3], m[4], m[5]
		} else {
			ev.AdminUser, ev.AdminSrcIP = x["suser"], x["src"]
		}
	default:
		return unparsed("unifi: cef " + c.SignatureID + " (" + c.Name + ") not mapped")
	}
	return ok()
}

// unifiAccessMethod folds UNIFIaccessMethod (Local / Cloud / Remote …) into
// the admin_method vocabulary: a local controller login is the GUI, a cloud
// SSO one is cloud; anything else keeps its lowercased word.
func unifiAccessMethod(s string) string {
	switch l := strings.ToLower(s); l {
	case "", "local", "gui", "web":
		return "gui"
	case "cloud", "remote", "sso":
		return "cloud"
	default:
		return l
	}
}

func unifiAct(s string) Action {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "block"), strings.Contains(l, "drop"):
		return ActionDeny
	case strings.Contains(l, "reject"), strings.Contains(l, "reset"):
		return ActionReject
	case strings.Contains(l, "detect"), strings.Contains(l, "alert"), strings.Contains(l, "allow"):
		return ActionAllow
	case l == "":
		return ActionUnknown
	}
	return ActionOther
}

// unifiNetfilter maps a logged firewall rule hit: per packet, no bytes, no
// user, no app, no NAT. The chain is the ruleset and the prefix index the
// rule position (tier x) — the API poller resolves names later.
func unifiNetfilter(nf *family.Netfilter, ev *Event) Outcome {
	f := nf.Fields
	ev.Class, ev.Activity = ClassNetwork, ActivityPacket
	ev.VendorEventID = nf.Ruleset
	ev.Ruleset = nf.Ruleset
	ev.Action = actionWord(nf.Verdict)
	if nf.Verdict == "RET" {
		ev.Action = ActionOther
	}
	ev.RuleIndex = ev.i32(nf.Index)
	if d := f["descr"]; d != "" && !strings.EqualFold(d, "no rule description") {
		ev.RuleName = d
	}
	// Tier x (roadmap §1.3): the chain position is the identity; DESCR is a
	// description netfilter truncates at ~28 chars, kept for display only.
	// The API poller resolves the real name through fw_rules later.
	ev.RuleKey = RuleKey("", nil, "", nf.Ruleset, ev.RuleIndex)
	ev.SrcIf, ev.DstIf = f["in"], f["out"]
	ev.SrcIP, ev.DstIP = ev.ip(f["src"]), ev.ip(f["dst"])
	ev.SrcPort, ev.DstPort = ev.port(f["spt"]), ev.port(f["dpt"])
	ev.Proto = ev.protoNum(f["proto"])
	// MAC= is dst(6) + src(6) + ethertype(2) as colon-separated bytes.
	if mac := f["mac"]; len(mac) >= 35 {
		ev.DstMAC, ev.SrcMAC = parseMAC(mac[:17]), parseMAC(mac[18:35])
	}
	ev.extra("len", f["len"])
	return ok()
}
