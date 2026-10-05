package normalize

// ObservedFields names the Event columns the capability matrix's observed
// half tracks (roadmap §1.4), spelled as internal/normalize/capability spells
// its Field constants and as the `event.*` rule view does without the prefix.
// The index of a name is its bit in Presence, so the ingest can fold one
// event into a per-(device, class) counter row with a handful of ORs and
// adds instead of a map per message. Append-only: device_field_observed
// stores the NAME, not the bit, so reordering costs nothing in the table but
// would silently change what an in-flight counter means.
var ObservedFields = [...]string{
	"action", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
	"src_mac", "dst_mac", "src_if", "dst_if", "src_zone", "dst_zone",
	"src_role", "dst_role", "direction",
	"rule_key", "rule_uid", "rule_id", "rule_name", "rule_index", "ruleset",
	"user", "group", "app", "app_cat", "app_risk", "dev_type", "os_name", "src_hostname",
	"bytes_out", "bytes_in", "pkts_out", "pkts_in", "duration_ms", "session_id",
	"nat_src_ip", "nat_dst_ip", "src_country", "dst_country",
	"url_host", "url_path", "dns_qname", "dns_qtype", "web_cat",
	"severity", "sig_id", "sig_name", "threat_cat", "file_hash",
	"admin_user", "admin_src_ip", "admin_method",
	"tunnel_name", "tunnel_type", "tunnel_peer",
	"config_path", "config_obj", "config_old", "config_new",
	"wan_name", "metric_name", "metric_value",
}

// Presence is the set of ObservedFields an Event supplied (non-NULL), one
// bit per index. len(ObservedFields) must stay <= 64; TestObservedFields
// pins it.
type Presence uint64

// Has reports whether field i (an ObservedFields index) is present.
func (p Presence) Has(i int) bool { return p&(1<<uint(i)) != 0 }

// Present returns the Event's non-NULL ObservedFields, with the same NULL
// discipline as Fields and the storage row: nil pointer / empty string / nil
// address = absent; Action is absent only when unknown.
func (e *Event) Present() Presence {
	var p Presence
	i := 0
	set := func(ok bool) {
		if ok {
			p |= 1 << uint(i)
		}
		i++
	}
	set(e.Action != ActionUnknown)
	set(e.SrcIP != nil)
	set(e.DstIP != nil)
	set(e.SrcPort != nil)
	set(e.DstPort != nil)
	set(e.Proto != nil)
	set(e.SrcMAC != nil)
	set(e.DstMAC != nil)
	set(e.SrcIf != "")
	set(e.DstIf != "")
	set(e.SrcZone != "")
	set(e.DstZone != "")
	set(e.SrcRole != nil)
	set(e.DstRole != nil)
	set(e.Direction != nil)
	set(e.RuleKey != "")
	set(e.RuleUID != "")
	set(e.RuleID != nil)
	set(e.RuleName != "")
	set(e.RuleIndex != nil)
	set(e.Ruleset != "")
	set(e.User != "")
	set(e.Group != "")
	set(e.App != "")
	set(e.AppCat != "")
	set(e.AppRisk != nil)
	set(e.DevType != "")
	set(e.OSName != "")
	set(e.SrcHostname != "")
	set(e.BytesOut != nil)
	set(e.BytesIn != nil)
	set(e.PktsOut != nil)
	set(e.PktsIn != nil)
	set(e.DurationMS != nil)
	set(e.SessionID != "")
	set(e.NatSrcIP != nil)
	set(e.NatDstIP != nil)
	set(e.SrcCountry != "")
	set(e.DstCountry != "")
	set(e.URLHost != "")
	set(e.URLPath != "")
	set(e.DNSQName != "")
	set(e.DNSQType != nil)
	set(e.WebCat != "")
	set(e.Severity != nil)
	set(e.SigID != "")
	set(e.SigName != "")
	set(e.ThreatCat != "")
	set(e.FileHash != "")
	set(e.AdminUser != "")
	set(e.AdminSrcIP != "")
	set(e.AdminMethod != "")
	set(e.TunnelName != "")
	set(e.TunnelType != "")
	set(e.TunnelPeer != nil)
	set(e.ConfigPath != "")
	set(e.ConfigObj != "")
	set(e.ConfigOld != "")
	set(e.ConfigNew != "")
	set(e.WANName != "")
	set(e.MetricName != "")
	set(e.MetricValue != nil)
	return p
}
