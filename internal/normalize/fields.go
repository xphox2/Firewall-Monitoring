package normalize

import (
	"net"
	"strconv"
)

// FieldPrefix is the namespace of the canonical rule fields. The vendor's own
// keys keep their bare names (FortiOS `action="deny"`, filterlog
// `action=block`), so a bare canonical `action` would clobber or be
// clobbered; `event.action` sits beside them (operator decision, plan §7.1).
const FieldPrefix = "event."

// Fields writes the Event's non-NULL columns into dst under `event.*` names
// for the rule engine (logfields.Fields calls this). Enums are written by
// NAME (`event.action=deny`, `event.class=network`) because rules compare
// strings; Extra keys go under `event.extra.<key>`. Nothing is written for a
// NULL column, so `event.rule_key` absent means "rule not reported" exactly
// as the storage NULL will.
//
// Every number and address is rendered into ONE scratch buffer and the map
// values are substrings of the single string made from it (a FortiOS traffic
// line has a dozen such values; one allocation instead of twelve on the
// per-message rule path).
func (e *Event) Fields(dst map[string]string) {
	// arr is a separate local so w holds no slice into itself (that
	// self-reference would force w onto the heap); neither escapes.
	var arr [384]byte
	w := fieldWriter{dst: dst, buf: arr[:0]}
	dst["event.class"] = e.Class.String()
	dst["event.activity"] = e.Activity.String()
	dst["event.action"] = e.Action.String()
	setS(dst, "event.vendor_event_id", e.VendorEventID)
	w.ip("event.src_ip", e.SrcIP)
	w.ip("event.dst_ip", e.DstIP)
	w.i32("event.src_port", e.SrcPort)
	w.i32("event.dst_port", e.DstPort)
	w.i16("event.proto", e.Proto)
	w.mac("event.src_mac", e.SrcMAC)
	w.mac("event.dst_mac", e.DstMAC)
	setS(dst, "event.src_if", e.SrcIf)
	setS(dst, "event.dst_if", e.DstIf)
	setS(dst, "event.src_zone", e.SrcZone)
	setS(dst, "event.dst_zone", e.DstZone)
	if e.SrcRole != nil {
		dst["event.src_role"] = e.SrcRole.String()
	}
	if e.DstRole != nil {
		dst["event.dst_role"] = e.DstRole.String()
	}
	if e.Direction != nil {
		dst["event.direction"] = e.Direction.String()
	}
	setS(dst, "event.rule_key", e.RuleKey)
	setS(dst, "event.rule_uid", e.RuleUID)
	w.i64("event.rule_id", e.RuleID)
	setS(dst, "event.rule_name", e.RuleName)
	w.i32("event.rule_index", e.RuleIndex)
	setS(dst, "event.ruleset", e.Ruleset)
	setS(dst, "event.user", e.User)
	setS(dst, "event.group", e.Group)
	setS(dst, "event.app", e.App)
	setS(dst, "event.app_cat", e.AppCat)
	w.i16("event.app_risk", e.AppRisk)
	setS(dst, "event.dev_type", e.DevType)
	setS(dst, "event.os_name", e.OSName)
	setS(dst, "event.src_hostname", e.SrcHostname)
	w.i64("event.bytes_out", e.BytesOut)
	w.i64("event.bytes_in", e.BytesIn)
	w.i64("event.pkts_out", e.PktsOut)
	w.i64("event.pkts_in", e.PktsIn)
	w.i32("event.duration_ms", e.DurationMS)
	setS(dst, "event.session_id", e.SessionID)
	w.ip("event.nat_src_ip", e.NatSrcIP)
	w.ip("event.nat_dst_ip", e.NatDstIP)
	w.i32("event.nat_src_port", e.NatSrcPort)
	w.i32("event.nat_dst_port", e.NatDstPort)
	setS(dst, "event.src_country", e.SrcCountry)
	setS(dst, "event.dst_country", e.DstCountry)
	if e.ThreatFlag != 0 {
		w.num("event.threat_flag", int64(e.ThreatFlag))
	}
	setS(dst, "event.url_host", e.URLHost)
	setS(dst, "event.url_path", e.URLPath)
	setS(dst, "event.dns_qname", e.DNSQName)
	w.i16("event.dns_qtype", e.DNSQType)
	setS(dst, "event.web_cat", e.WebCat)
	w.i16("event.severity", e.Severity)
	setS(dst, "event.sig_id", e.SigID)
	setS(dst, "event.sig_name", e.SigName)
	setS(dst, "event.threat_cat", e.ThreatCat)
	setS(dst, "event.file_hash", e.FileHash)
	setS(dst, "event.admin_user", e.AdminUser)
	setS(dst, "event.admin_src_ip", e.AdminSrcIP)
	setS(dst, "event.admin_method", e.AdminMethod)
	setS(dst, "event.tunnel_name", e.TunnelName)
	setS(dst, "event.tunnel_type", e.TunnelType)
	w.ip("event.tunnel_peer", e.TunnelPeer)
	setS(dst, "event.config_path", e.ConfigPath)
	setS(dst, "event.config_obj", e.ConfigObj)
	setS(dst, "event.config_old", e.ConfigOld)
	setS(dst, "event.config_new", e.ConfigNew)
	setS(dst, "event.wan_name", e.WANName)
	setS(dst, "event.metric_name", e.MetricName)
	if e.MetricValue != nil {
		w.mark("event.metric_value")
		w.buf = strconv.AppendFloat(w.buf, *e.MetricValue, 'f', -1, 64)
	}
	setS(dst, "event.message", e.Message)
	for k, v := range e.Extra {
		key, ok := extraKeys[k]
		if !ok {
			key = "event.extra." + k
		}
		dst[key] = v
	}
	w.flush()
}

// extraKeys pre-joins the `event.extra.` names the mappers use, so the
// common ones cost no concatenation per message.
var extraKeys = func() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"service", "subtype", "src_country_name", "dst_country_name", "ref", "reason", "attr",
		"filename", "health_check", "jitter_ms", "packet_loss_pct", "auth_method", "method", "risk", "ssid", "ap",
		"channel", "rssi", "len", "version", "prior_version"} {
		m[k] = "event.extra." + k
	}
	return m
}()

func setS(dst map[string]string, k, v string) {
	if v != "" {
		dst[k] = v
	}
}

// fieldWriter renders numeric / address values into one buffer, remembering
// (key, start, end) per value, and flush converts the buffer to a single
// string whose substrings become the map values.
//
// The arrays live in the caller's frame (the writer never escapes); 32 slots
// cover the ~27 numeric / address columns an Event can carry, and a flush
// mid-way handles any overflow.
type fieldWriter struct {
	dst  map[string]string
	buf  []byte
	keys [32]string
	offs [32][2]int // start, end
	n    int
}

func (w *fieldWriter) mark(key string) {
	if w.n > 0 {
		w.offs[w.n-1][1] = len(w.buf) // close the previous value
	}
	if w.n == len(w.keys) {
		w.flush()
		w.n, w.buf = 0, w.buf[:0]
	}
	w.keys[w.n] = key
	w.offs[w.n] = [2]int{len(w.buf), -1}
	w.n++
}

func (w *fieldWriter) num(key string, v int64) {
	w.mark(key)
	w.buf = strconv.AppendInt(w.buf, v, 10)
}

func (w *fieldWriter) i64(key string, v *int64) {
	if v != nil {
		w.num(key, *v)
	}
}

func (w *fieldWriter) i32(key string, v *int32) {
	if v != nil {
		w.num(key, int64(*v))
	}
}

func (w *fieldWriter) i16(key string, v *int16) {
	if v != nil {
		w.num(key, int64(*v))
	}
}

func (w *fieldWriter) ip(key string, ip net.IP) {
	if ip == nil {
		return
	}
	w.mark(key)
	w.buf, _ = ip.AppendText(w.buf)
}

func (w *fieldWriter) mac(key string, m net.HardwareAddr) {
	if m == nil {
		return
	}
	w.mark(key)
	const hexDigit = "0123456789abcdef"
	for i, b := range m {
		if i > 0 {
			w.buf = append(w.buf, ':')
		}
		w.buf = append(w.buf, hexDigit[b>>4], hexDigit[b&0xF])
	}
}

func (w *fieldWriter) flush() {
	if w.n == 0 {
		return
	}
	w.offs[w.n-1][1] = len(w.buf)
	s := string(w.buf)
	for i := 0; i < w.n; i++ {
		w.dst[w.keys[i]] = s[w.offs[i][0]:w.offs[i][1]]
	}
}
