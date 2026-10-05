package normalize

import (
	"strings"

	"firewall-mon/internal/models"
)

// genericMapper is the fallback for vendors without a mapper (and the
// registered `generic` vendor): it recognises the three self-describing
// shapes — a CEF record, a pf filterlog CSV, a space-separated `key=value`
// line — and maps only what those shapes state outright under their common
// key names. It never guesses a class from free text.
type genericMapper struct{}

func init() { Register(genericMapper{}) }

func (genericMapper) Vendor() string     { return "generic" }
func (genericMapper) Families() []Family { return []Family{FamilyCEF, FamilyFilterlog, FamilyKV} }

func (genericMapper) Map(tok Tokens, _ *models.SyslogMessage, ev *Event) Outcome {
	switch tok.Family {
	case FamilyCEF:
		return mapCEFGeneric(tok.CEF, ev)
	case FamilyFilterlog:
		return mapFilterlog(tok.FL, ev)
	}
	return genericKV(tok.KV, ev)
}

// genericKV maps the key names shared by the key=value dialects (SonicWall,
// Sophos, WatchGuard, Check Point kv mode, FortiOS): at least a source or
// destination address, or a verdict, must be present or the line is reported
// Unparsed — a `k=v` line from an unrelated daemon is not a firewall event.
func genericKV(kv map[string]string, ev *Event) Outcome {
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v := kv[k]; v != "" {
				return v
			}
		}
		return ""
	}
	src, dst := pick("srcip", "src", "source", "src_ip"), pick("dstip", "dst", "destination", "dst_ip")
	action := pick("action", "act", "fw_action", "disposition")
	if src == "" && dst == "" && action == "" {
		return unparsed("generic: kv without src/dst/action")
	}
	ev.Class, ev.Activity = ClassNetwork, ActivityTraffic
	ev.VendorEventID = pick("logid", "id", "msg_id", "event_id")
	sh, sp, sif := splitCompound(src)
	dh, dp, dif := splitCompound(dst)
	ev.SrcIP, ev.DstIP = ev.ip(sh), ev.ip(dh)
	ev.SrcPort, ev.DstPort = ev.port(pick("srcport", "sport", "spt", "src_port")), ev.port(pick("dstport", "dport", "dpt", "dst_port"))
	if ev.SrcPort == nil {
		ev.SrcPort = ev.port(sp)
	}
	if ev.DstPort == nil {
		ev.DstPort = ev.port(dp)
	}
	ev.Proto = ev.protoNum(pick("proto", "protocol"))
	ev.Action = actionWord(action)
	ev.User, ev.App = pick("user", "usr", "suser", "user_name", "src_user"), pick("app", "appname", "application", "app_name")
	ev.RuleName = pick("policyname", "rule_name", "fw_rule_name", "rule")
	ev.RuleID = ev.i64(pick("policyid", "rule_id", "fw_rule_id"))
	ev.RuleUID = pick("poluuid", "rule_uid")
	ev.BytesOut, ev.BytesIn = ev.i64(pick("sentbyte", "sent", "sent_bytes", "bytes_out")), ev.i64(pick("rcvdbyte", "rcvd", "rcvd_bytes", "bytes_in"))
	ev.SrcIf, ev.DstIf = firstNonEmpty(pick("srcintf", "in_interface", "srcif"), sif), firstNonEmpty(pick("dstintf", "out_interface", "dstif"), dif)
	ev.Message = kv["msg"]
	return ok()
}

// splitCompound reads the `ip[:port[:interface]]` compound SonicWall and a few
// other k=v dialects write (`src=203.0.113.9:44000:X1`); an IPv6 address
// (more than one ':' and no '.') is returned whole.
func splitCompound(s string) (ip, port, iface string) {
	if strings.Count(s, ":") <= 1 || !strings.Contains(s, ".") {
		ip, port = splitHostPort(s)
		return ip, port, ""
	}
	parts := strings.SplitN(s, ":", 3)
	return parts[0], parts[1], parts[2]
}
