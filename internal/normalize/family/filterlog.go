package family

import "strings"

// Filterlog is one pf `filterlog` CSV record as OPNsense and pfSense emit it
// for every packet-filter verdict. Column layout (0-based), common prefix:
//
//	0 rulenr 1 subrulenr 2 anchor 3 tracker 4 interface 5 reason 6 action
//	7 direction 8 ipversion
//
// IPv4 (ipversion=4): 9 tos 10 ecn 11 ttl 12 id 13 offset 14 ipflags
// 15 protonum 16 prototext 17 length 18 src 19 dst (+ 20 srcport 21 dstport
// for tcp/udp). IPv6 (ipversion=6): 9 class 10 flowlabel 11 hoplimit
// 12 prototext 13 protonum 14 length 15 src 16 dst (+ 17 srcport 18 dstport).
//
// Moved from internal/logfields (AUDIT-280), which keeps the same named keys
// through Fields so no event rule changes meaning.
type Filterlog struct {
	RuleNr, SubRuleNr, Anchor, Tracker string
	Interface, Reason, Action, Dir     string
	IPVersion                          string // "4" | "6"
	Proto, ProtoName                   string // numeric id, text
	Length                             string
	Src, Dst, SrcPort, DstPort         string
}

// HasFilterlog is the cheap gate: a comma-dense token with the filterlog
// signature exists in s (FindFilterlog validates it).
func HasFilterlog(s string) bool { return FindFilterlog(s) != "" }

// FindFilterlog returns the comma-separated filterlog payload from a re-joined
// syslog line. The CSV is a single whitespace-free token with many commas (>=
// the 8-field common prefix), so it is located by comma density — surviving
// the collector's RFC5424 space-split moving the leading tokens around — and
// then VALIDATED against the filterlog signature: field 0 (rulenr) a small
// integer, field 6 (action) a pf verdict, field 8 (ipversion) 4 or 6. The
// signature gate stops a comma-dense token from an UNRELATED daemon on a
// pf/opnsense-vendor device from polluting the structured fields.
func FindFilterlog(raw string) string {
	if strings.Count(raw, ",") < 8 {
		return "" // cheap pre-gate: strings.Fields allocates, most lines are not CSV
	}
	for _, tok := range strings.Fields(raw) {
		if strings.Count(tok, ",") < 8 {
			continue
		}
		f := strings.Split(tok, ",")
		if len(f) < 9 || !isSmallUint(f[0]) {
			continue
		}
		switch f[6] { // pf action verdict
		case "pass", "block", "reject":
		default:
			continue
		}
		if f[8] != "4" && f[8] != "6" { // ipversion
			continue
		}
		return tok
	}
	return ""
}

// isSmallUint reports whether s is a short, all-digit, non-negative integer —
// the shape of a filterlog rulenr. Rejects empty, signed, or oversized tokens
// so the signature gate can't be satisfied by arbitrary comma-dense text.
func isSmallUint(s string) bool {
	if s == "" || len(s) > 7 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ParseFilterlog tokenizes the filterlog record found in raw. ok=false when
// none is present.
func ParseFilterlog(raw string) (Filterlog, bool) {
	csv := FindFilterlog(raw)
	if csv == "" {
		return Filterlog{}, false
	}
	f := strings.Split(csv, ",")
	fl := Filterlog{RuleNr: f[0], SubRuleNr: f[1], Anchor: f[2], Tracker: f[3],
		Interface: f[4], Reason: f[5], Action: f[6], Dir: f[7], IPVersion: f[8]}
	at := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	switch fl.IPVersion {
	case "4":
		fl.Proto, fl.ProtoName, fl.Length = at(15), at(16), at(17)
		fl.Src, fl.Dst = at(18), at(19)
		fl.SrcPort, fl.DstPort = at(20), at(21)
	case "6":
		fl.ProtoName, fl.Proto, fl.Length = at(12), at(13), at(14)
		fl.Src, fl.Dst = at(15), at(16)
		fl.SrcPort, fl.DstPort = at(17), at(18)
	}
	return fl, true
}

// Fields writes the record under the key names internal/logfields has always
// exposed to event rules (interface, reason, action, dir, ipversion, proto,
// protoname, srcip, dstip, srcport, dstport); empty values are not written.
func (fl Filterlog) Fields(dst map[string]string) {
	set := func(k, v string) {
		if v != "" {
			dst[k] = v
		}
	}
	set("interface", fl.Interface)
	set("reason", fl.Reason)
	set("action", fl.Action) // pass | block | reject | rdr | ...
	set("dir", fl.Dir)       // in | out
	set("ipversion", fl.IPVersion)
	set("proto", fl.Proto) // numeric protocol id — the FortiGate `proto` convention deny.Project consumes
	set("protoname", fl.ProtoName)
	set("srcip", fl.Src)
	set("dstip", fl.Dst)
	set("srcport", fl.SrcPort)
	set("dstport", fl.DstPort)
}
