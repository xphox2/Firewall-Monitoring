package normalize

import (
	"strings"

	"firewall-mon/internal/models"
)

func init() { Register(fortigateMapper{}) }

// fortigateMapper maps FortiOS key=value logs (the FortiOS Log Message
// Reference vocabulary: type / subtype / logid / action …). A FortiGate
// switched to CEF output takes the generic CEF mapping. Country names become
// ISO codes (country.go); `vd=` is the ruleset so policy ids are qualified by
// VDOM.
//
// CEF is tried first: its gate is the exact `CEF:` record marker, while the
// key=value gate (any `k=v`) would also claim a CEF record's extension and
// map nothing useful. The order must not depend on the collector's format
// hint — a row re-read from the database (backfill, rule tester) has none
// and must normalize exactly as it did at ingest.
type fortigateMapper struct{}

func (fortigateMapper) Vendor() string     { return "fortigate" }
func (fortigateMapper) Families() []Family { return []Family{FamilyCEF, FamilyFortiOSKV} }

func (fortigateMapper) Map(tok Tokens, _ *models.SyslogMessage, ev *Event) Outcome {
	if tok.Family == FamilyCEF {
		return mapCEFGeneric(tok.CEF, ev)
	}
	kv := tok.KV
	typ := fgType(kv)
	if typ == "" {
		return unparsed("fortigate: not a FortiOS log (no type/logid)")
	}
	ev.VendorEventID = kv["logid"]
	ev.Ruleset = kv["vd"]
	fgEndpoints(kv, ev)
	switch typ {
	case "traffic":
		return fgTraffic(kv, ev)
	case "utm":
		return fgUTM(kv, ev)
	case "event":
		return fgEvent(kv, ev)
	}
	return unparsed("fortigate: type=" + typ + " not mapped")
}

// fgType returns the FortiOS log type, inferring it when `type=` is missing:
// the first two digits of logid are the type (00 traffic, 01 event, the rest
// UTM: 02 virus, 03 webfilter, 04 ips, 05 emailfilter, 07 anomaly, 09 dlp,
// 10 app-ctrl, 12 waf, 13 dns, 14 ssh, 15 ssl, 16 cifs, 17 file-filter,
// 18 icap), and failing that the subtype vocabulary is unambiguous per type.
// A line with none of the three is not a FortiOS log. This keeps a truncated
// or hand-fed line (`action="deny" srcip=… policyid=…`) on the same path the
// deny projection has always taken for it.
func fgType(kv map[string]string) string {
	if t := kv["type"]; t != "" {
		return t
	}
	if id := kv["logid"]; len(id) >= 2 {
		switch id[:2] {
		case "00":
			return "traffic"
		case "01":
			return "event"
		case "02", "03", "04", "05", "07", "09", "10", "12", "13", "14", "15", "16", "17", "18":
			return "utm"
		}
	}
	switch kv["subtype"] {
	case "forward", "local", "multicast", "sniffer":
		return "traffic"
	case "vpn", "system", "ha", "sdwan", "user", "router", "wireless", "endpoint", "connector", "fortiextender", "security-rating", "switch-controller":
		return "event"
	case "ips", "anomaly", "virus", "app-ctrl", "webfilter", "dns", "emailfilter", "dlp", "waf", "ssh", "ssl", "cifs", "file-filter", "icap":
		return "utm"
	}
	return ""
}

// fgEndpoints fills the tuple, interfaces, identity and geo every FortiOS log
// type shares.
func fgEndpoints(kv map[string]string, ev *Event) {
	ev.SrcIP, ev.DstIP = ev.ip(kv["srcip"]), ev.ip(kv["dstip"])
	ev.SrcPort, ev.DstPort = ev.port(kv["srcport"]), ev.port(kv["dstport"])
	ev.Proto = ev.protoNum(kv["proto"])
	ev.SrcIf, ev.DstIf = kv["srcintf"], kv["dstintf"]
	if r, ok := kv["srcintfrole"]; ok {
		ev.SrcRole = ptrRole(fgRole(r))
	}
	if r, ok := kv["dstintfrole"]; ok {
		ev.DstRole = ptrRole(fgRole(r))
	}
	ev.SrcMAC, ev.DstMAC = parseMAC(kv["srcmac"]), parseMAC(kv["dstmac"])
	ev.User, ev.Group = fgStr(kv["user"]), fgStr(kv["group"])
	ev.SrcHostname, ev.DevType, ev.OSName = kv["srcname"], kv["devtype"], kv["osname"]
	ev.SessionID = kv["sessionid"]
	ev.SrcCountry = fgCountry(kv["srccountry"], "src_country_name", ev)
	ev.DstCountry = fgCountry(kv["dstcountry"], "dst_country_name", ev)
}

// fgStr turns FortiOS's "N/A" placeholder (VPN events write it for user,
// group, xauthuser, assignip …) into an absent value.
func fgStr(s string) string {
	if s == "N/A" {
		return ""
	}
	return s
}

// fgCountry maps the FortiOS country name to its ISO code. The raw name is
// kept in Extra whenever it is not the canonical spelling for that code
// (unmapped buckets such as "Reserved", and alternates such as "Czechia" or
// "Russia"), so deny.FromEvent can store exactly the name the device wrote —
// the same value ProjectVendor stores today.
func fgCountry(name, extraKey string, ev *Event) string {
	if name == "" {
		return ""
	}
	cc := CountryCode(name)
	if cc == "" || name != CountryName(cc) {
		ev.extra(extraKey, name)
	}
	return cc
}

func fgRole(s string) Role {
	switch strings.ToLower(s) {
	case "wan":
		return RoleWAN
	case "lan":
		return RoleLAN
	case "dmz":
		return RoleDMZ
	case "undefined":
		return RoleUndefined
	}
	return RoleUnknown
}

// fgRule fills the policy identity: poluuid (tier u) > policyid (tier i).
func fgRule(kv map[string]string, ev *Event) {
	ev.RuleUID, ev.RuleName = kv["poluuid"], kv["policyname"]
	ev.RuleID = ev.i64(kv["policyid"])
}

func fgTraffic(kv map[string]string, ev *Event) Outcome {
	ev.Class = ClassNetwork
	action := kv["action"]
	switch action {
	case "start":
		ev.Activity, ev.Action = ActivityOpen, ActionAllow
	case "accept":
		ev.Activity, ev.Action = ActivityTraffic, ActionAllow
	case "close", "client-rst", "server-rst":
		ev.Activity, ev.Action = ActivityClose, ActionAllow
	case "timeout":
		ev.Activity, ev.Action = ActivityClose, ActionTimeoutClose
	case "deny":
		ev.Activity, ev.Action = ActivityTraffic, ActionDeny
	case "ip-conn", "dns":
		ev.Activity, ev.Action = ActivityClose, ActionOther
	case "":
		ev.Activity, ev.Action = ActivityTraffic, ActionUnknown
	default:
		// The FortiOS traffic verdict vocabulary is the list above; any other
		// word (a UTM verdict such as "blocked" leaking into a traffic line,
		// a future FortiOS value) is recorded as other rather than guessed,
		// so denied_events parity with the literal action="deny" gate holds.
		ev.Activity, ev.Action = ActivityTraffic, ActionOther
	}
	fgRule(kv, ev)
	ev.App, ev.AppCat = kv["app"], kv["appcat"]
	ev.AppRisk = ev.fgAppRisk(kv["apprisk"])
	ev.BytesOut, ev.BytesIn = ev.i64(kv["sentbyte"]), ev.i64(kv["rcvdbyte"])
	ev.PktsOut, ev.PktsIn = ev.i64(kv["sentpkt"]), ev.i64(kv["rcvdpkt"])
	if d := ev.i64(kv["duration"]); d != nil && *d*1000 <= 2147483647 {
		ev.DurationMS = ev.p32(int32(*d * 1000))
	}
	switch kv["trandisp"] {
	case "snat":
		ev.NatSrcIP, ev.NatSrcPort = ev.ip(kv["transip"]), ev.port(kv["transport"])
	case "dnat":
		ev.NatDstIP, ev.NatDstPort = ev.ip(kv["tranip"]), ev.port(kv["tranport"])
	case "snat+dnat":
		ev.NatSrcIP, ev.NatSrcPort = ev.ip(kv["transip"]), ev.port(kv["transport"])
		ev.NatDstIP, ev.NatDstPort = ev.ip(kv["tranip"]), ev.port(kv["tranport"])
	}
	// Kept for the denied_events projection (deny.FromEvent): the FortiOS
	// service name and the local/forward subtype have no typed column.
	ev.extra("service", kv["service"])
	ev.extra("subtype", kv["subtype"])
	return ok()
}

func (ev *Event) fgAppRisk(s string) *int16 {
	switch strings.ToLower(s) {
	case "low":
		return ev.p16(1)
	case "elevated":
		return ev.p16(2)
	case "medium":
		return ev.p16(3)
	case "high":
		return ev.p16(4)
	case "critical":
		return ev.p16(5)
	}
	return nil
}

func fgUTM(kv map[string]string, ev *Event) Outcome {
	sub := kv["subtype"]
	fgRule(kv, ev)
	ev.Severity = ev.sevWord(kv["severity"])
	ev.Message = kv["msg"]
	switch sub {
	case "ips", "anomaly":
		ev.Class, ev.Activity = ClassFinding, ActivityDetect
		ev.SigID, ev.SigName, ev.ThreatCat = kv["attackid"], kv["attack"], sub
		ev.Action = fgUTMAction(kv["action"])
		ev.extra("ref", kv["ref"])
	case "virus":
		ev.Class, ev.Activity = ClassFinding, ActivityDetect
		ev.SigName, ev.ThreatCat = kv["virus"], "virus"
		ev.FileHash = firstNonEmpty(kv["filehash"], kv["checksum"])
		ev.Action = fgUTMAction(kv["action"])
		if u := kv["url"]; u != "" {
			ev.URLHost, ev.URLPath = splitURL(u)
		}
		ev.extra("filename", kv["filename"])
	case "app-ctrl":
		ev.Class, ev.Activity = ClassFinding, ActivityDetect
		ev.App, ev.AppCat, ev.AppRisk = kv["app"], kv["appcat"], ev.fgAppRisk(kv["apprisk"])
		ev.SigID, ev.SigName, ev.ThreatCat = kv["appid"], kv["app"], "app-ctrl"
		ev.Action = fgUTMAction(kv["action"])
	case "webfilter":
		ev.Class, ev.Activity = ClassNetwork, ActivityHTTP
		ev.URLHost, ev.URLPath, ev.WebCat = kv["hostname"], kv["url"], kv["catdesc"]
		ev.Action = fgUTMAction(kv["action"])
		ev.BytesOut, ev.BytesIn = ev.i64(kv["sentbyte"]), ev.i64(kv["rcvdbyte"])
	case "dns":
		ev.Class, ev.Activity = ClassNetwork, ActivityDNS
		ev.DNSQName, ev.DNSQType, ev.WebCat = kv["qname"], ev.i16(kv["qtypeval"]), kv["catdesc"]
		if ev.DNSQType == nil {
			ev.DNSQType = ev.dnsQType(kv["qtype"])
		}
		ev.Action = fgUTMAction(kv["action"])
	default:
		return unparsed("fortigate: utm/" + sub + " not mapped")
	}
	return ok()
}

// fgUTMAction: UTM verdict words differ from the traffic ones (detected =
// seen and let through, dropped / blocked / reset = enforced).
func fgUTMAction(s string) Action {
	switch strings.ToLower(s) {
	case "detected", "passthrough", "pass", "monitor", "allow":
		return ActionAllow
	case "dropped", "blocked", "block", "redirect", "clear_session", "drop":
		return ActionDeny
	case "reset":
		return ActionReject
	case "":
		return ActionUnknown
	}
	return ActionOther
}

func fgEvent(kv map[string]string, ev *Event) Outcome {
	sub := kv["subtype"]
	logdesc := strings.ToLower(kv["logdesc"])
	ev.Message = firstNonEmpty(kv["msg"], kv["logdesc"])
	switch sub {
	case "vpn":
		return fgVPN(kv, ev)
	case "system":
		if _, isCfg := kv["cfgpath"]; isCfg {
			return fgConfigChange(kv, ev)
		}
		switch {
		case strings.HasPrefix(logdesc, "admin login"):
			ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogon, ActionAllow
			if strings.Contains(logdesc, "fail") || strings.Contains(logdesc, "disabled") {
				ev.Action = ActionDeny
			}
			fgAdmin(kv, ev)
			return ok()
		case strings.HasPrefix(logdesc, "admin logout"):
			ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogoff, ActionAllow
			fgAdmin(kv, ev)
			return ok()
		case strings.Contains(logdesc, "conserve"):
			ev.Class, ev.Activity = ClassDeviceHealth, ActivityResource
			ev.MetricName = "conserve_mode"
			return ok()
		}
		return unparsed("fortigate: event/system " + strings.ToLower(kv["logdesc"]) + " not mapped")
	case "ha":
		ev.Class, ev.Activity = ClassDeviceHealth, ActivityHAState
		return ok()
	case "sdwan":
		return fgSDWAN(kv, ev)
	case "user":
		ev.Class, ev.Activity = ClassAuth, ActivityLogon
		switch strings.ToLower(kv["status"]) {
		case "success":
			ev.Action = ActionAllow
		case "failure", "failed":
			ev.Action = ActionDeny
		}
		if strings.Contains(strings.ToLower(kv["action"]), "logout") || strings.Contains(logdesc, "logout") {
			ev.Activity = ActivityLogoff
		}
		return ok()
	}
	return unparsed("fortigate: event/" + sub + " not mapped")
}

func fgVPN(kv map[string]string, ev *Event) Outcome {
	action := strings.ToLower(kv["action"])
	ev.TunnelName = fgStr(firstNonEmpty(kv["tunnelname"], kv["vpntunnel"]))
	ev.TunnelType = fgStr(kv["tunneltype"])
	ev.TunnelPeer = ev.ip(kv["remip"])
	ev.User = firstNonEmpty(fgStr(kv["xauthuser"]), fgStr(kv["user"]))
	ev.BytesOut, ev.BytesIn = ev.i64(kv["sentbyte"]), ev.i64(kv["rcvdbyte"])
	switch {
	case strings.Contains(action, "login"): // ssl-login-fail, ssl-login …
		ev.Class, ev.Activity, ev.Action = ClassAuth, ActivityLogon, ActionAllow
		if strings.Contains(action, "fail") {
			ev.Action = ActionDeny
		}
		if ev.SrcIP == nil {
			ev.SrcIP = ev.TunnelPeer
		}
		return ok()
	case action == "tunnel-up":
		ev.Class, ev.Activity = ClassVPNSession, ActivityTunnelUp
	case action == "tunnel-down":
		ev.Class, ev.Activity = ClassVPNSession, ActivityTunnelDown
	case action == "tunnel-stat", action == "tunnel-stats":
		ev.Class, ev.Activity = ClassVPNSession, ActivityTunnelStats
	default: // negotiate, install_sa, phase errors …
		ev.Class, ev.Activity = ClassVPNSession, ActivityUnknown
		if strings.Contains(strings.ToLower(kv["level"]), "error") {
			ev.Action = ActionDeny
		}
	}
	return ok()
}

// fgAdmin fills the admin columns from user / srcip / ui.
func fgAdmin(kv map[string]string, ev *Event) {
	ev.AdminUser = kv["user"]
	ev.AdminMethod, ev.AdminSrcIP = fgUI(kv["ui"])
	if ip := kv["srcip"]; ip != "" {
		ev.AdminSrcIP = ip
	}
}

// fgUI decodes `ui="GUI(203.0.113.9)"` / `ssh(…)` / `jsconsole` into the
// admin_method vocabulary (gui / ssh / console / api / cloud) and the source
// address it may carry.
func fgUI(ui string) (method, ip string) {
	if ui == "" {
		return "", ""
	}
	if i := strings.IndexByte(ui, '('); i >= 0 {
		if j := strings.IndexByte(ui[i:], ')'); j > 0 {
			ip = ui[i+1 : i+j]
		}
		ui = ui[:i]
	}
	l := strings.ToLower(ui)
	switch {
	case l == "gui", l == "https", l == "http":
		method = "gui"
	case l == "ssh", l == "telnet":
		method = "ssh"
	case l == "console", l == "jsconsole":
		method = "console"
	case strings.Contains(l, "api") || strings.Contains(l, "rest"):
		method = "api"
	case strings.Contains(l, "fortimanager") || strings.Contains(l, "forticloud") || strings.Contains(l, "fortigate cloud"):
		method = "cloud"
	default:
		method = l
	}
	return method, ip
}

// fgConfigChange maps the cfgpath / cfgobj / cfgattr audit event
// (`cfgattr="status[enable->disable]"`).
func fgConfigChange(kv map[string]string, ev *Event) Outcome {
	ev.Class = ClassConfigChange
	switch strings.ToLower(kv["action"]) {
	case "add":
		ev.Activity = ActivityCreate
	case "delete":
		ev.Activity = ActivityDelete
	default:
		ev.Activity = ActivityUpdate
	}
	ev.ConfigPath, ev.ConfigObj = kv["cfgpath"], kv["cfgobj"]
	if attr := kv["cfgattr"]; attr != "" {
		if open := strings.IndexByte(attr, '['); open > 0 && strings.HasSuffix(attr, "]") {
			if old, nw, found := strings.Cut(attr[open+1:len(attr)-1], "->"); found {
				ev.ConfigOld, ev.ConfigNew = old, nw
			}
			ev.extra("attr", attr[:open])
		} else {
			ev.extra("attr", attr)
		}
	}
	fgAdmin(kv, ev)
	return ok()
}

// fgSDWAN maps SD-WAN health-check and member events: a latency / jitter /
// packet-loss sample becomes one metric row, a member state change a
// wan_up / wan_down.
func fgSDWAN(kv map[string]string, ev *Event) Outcome {
	ev.Class = ClassDeviceHealth
	ev.WANName = firstNonEmpty(kv["interface"], kv["member"])
	ev.extra("health_check", kv["healthcheck"])
	// A health-check sample carries status AND metrics; a member going down
	// is the headline, otherwise the latency sample is (jitter / loss ride
	// along in Extra), and a bare status=up is a wan_up.
	switch {
	case kv["status"] == "down" || strings.Contains(strings.ToLower(kv["msg"]), "down"):
		ev.Activity = ActivityWANDown
	case kv["latency"] != "":
		ev.Activity, ev.MetricName, ev.MetricValue = ActivityLatency, "latency_ms", ev.f64(kv["latency"])
		ev.extra("jitter_ms", kv["jitter"])
		ev.extra("packet_loss_pct", strings.TrimSuffix(kv["packetloss"], "%"))
	case kv["packetloss"] != "":
		ev.Activity, ev.MetricName, ev.MetricValue = ActivityPacketLoss, "packet_loss_pct", ev.f64(strings.TrimSuffix(kv["packetloss"], "%"))
	case kv["status"] == "up":
		ev.Activity = ActivityWANUp
	default:
		return unparsed("fortigate: event/sdwan without status or metric")
	}
	return ok()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
