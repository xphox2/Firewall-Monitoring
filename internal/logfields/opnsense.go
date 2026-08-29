package logfields

import "strings"

// opnsenseExtractor parses the pf `filterlog` structured CSV that OPNsense (and
// pfSense — same schema family, see pfsense.go) emit for every packet-filter
// verdict, so Event Rules can match on action/interface/proto/src/dst/ports and
// the deny projector (internal/deny) can turn block/reject verdicts into
// denied_events (AUDIT-280). OPNsense is a fully registered SNMP vendor, so this
// is a live path, not a stub.
//
// filterlog CSV layout (0-based), common prefix for every line:
//
//	0 rulenr 1 subrulenr 2 anchor 3 tracker 4 interface 5 reason 6 action
//	7 direction 8 ipversion
//
// IPv4 (ipversion=4): 9 tos 10 ecn 11 ttl 12 id 13 offset 14 ipflags
//
//	15 protonum 16 prototext 17 length 18 src 19 dst   (+ 20 srcport 21 dstport for tcp/udp)
//
// IPv6 (ipversion=6): 9 class 10 flowlabel 11 hoplimit 12 prototext 13 protonum
//
//	14 length 15 src 16 dst   (+ 17 srcport 18 dstport for tcp/udp)
type opnsenseExtractor struct{}

func init() { Register(opnsenseExtractor{}) }

func (opnsenseExtractor) Vendor() string { return "opnsense" }

func (opnsenseExtractor) Extract(raw string, dst map[string]string) {
	extractFilterlog(raw, dst)
}

// extractFilterlog finds the filterlog CSV token within the reconstructed raw
// line and parses its structured fields into dst. Shared by the OPNsense and
// pfSense extractors (identical log format). No regex — cheap enough for the
// syslog hot path.
func extractFilterlog(raw string, dst map[string]string) {
	csv := filterlogCSV(raw)
	if csv == "" {
		return
	}
	f := strings.Split(csv, ",")
	if len(f) < 9 {
		return
	}
	set := func(k, v string) {
		if v != "" {
			dst[k] = v
		}
	}
	set("interface", f[4])
	set("reason", f[5])
	set("action", f[6]) // pass | block | reject | rdr | ...
	set("dir", f[7])    // in | out
	set("ipversion", f[8])

	switch f[8] {
	case "4":
		if len(f) > 16 {
			set("proto", f[15])     // numeric protocol id — matches the FortiGate `proto` convention deny.Project consumes
			set("protoname", f[16]) // text (tcp|udp|icmp) for rule matching
		}
		if len(f) > 19 {
			set("srcip", f[18])
			set("dstip", f[19])
		}
		if len(f) > 21 {
			set("srcport", f[20])
			set("dstport", f[21])
		}
	case "6":
		if len(f) > 13 {
			set("protoname", f[12])
			set("proto", f[13])
		}
		if len(f) > 16 {
			set("srcip", f[15])
			set("dstip", f[16])
		}
		if len(f) > 18 {
			set("srcport", f[17])
			set("dstport", f[18])
		}
	}
}

// filterlogCSV returns the comma-separated filterlog payload from a reconstructed
// syslog line. The CSV is a single whitespace-free token with many commas
// (>= the 8-field common prefix), so it's located by comma density — surviving
// the collector's RFC5424 space-split moving the leading tokens around — and then
// VALIDATED against the filterlog signature: field 0 (rulenr) a small integer,
// field 6 (action) a pf verdict, field 8 (ipversion) 4 or 6. The signature gate
// stops a comma-dense token from an UNRELATED daemon on a pf/opnsense-vendor
// device from polluting the Event-Rule structured fields (AUDIT-280 follow-up).
func filterlogCSV(raw string) string {
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

// isSmallUint reports whether s is a short, all-digit, non-negative integer — the
// shape of a filterlog rulenr. Rejects empty, signed, or oversized tokens so the
// signature gate can't be satisfied by arbitrary comma-dense text.
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
