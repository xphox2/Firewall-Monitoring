package family

import "regexp"

// Text is a free-text daemon line matched by the regex catalogue below. Kind
// names the pattern; Fields holds its named groups. The catalogue is small
// and grows one entry per verified sample; it runs last in every vendor's
// family order, so the regexes never see the key=value / CSV bulk streams.
type Text struct {
	Kind   string
	Fields map[string]string
}

type textPattern struct {
	kind string
	gate string // cheap substring that must be present before the regex runs
	re   *regexp.Regexp
}

// textCatalogue: dnsmasq (UniFi gateways log DNS queries and DHCP leases
// through it — the identity source for IP↔MAC↔hostname), sshd and the two
// VPN daemons pfSense/OPNsense and UniFi gateways run. Regexes are anchored
// on the daemon's own vocabulary, not on syslog header columns, so a
// re-joined v5 line and a clean v6 message both match.
var textCatalogue = []textPattern{
	{"dnsmasq_query", "query[", regexp.MustCompile(`query\[(?P<qtype>[A-Z0-9]+)\] (?P<qname>\S+) from (?P<src>[0-9a-fA-F.:]+)`)},
	{"dnsmasq_dhcpack", "DHCPACK", regexp.MustCompile(`DHCPACK\((?P<iface>[^)]+)\) (?P<ip>[0-9a-fA-F.:]+) (?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})(?: (?P<host>\S+))?`)},
	{"sshd_accepted", "Accepted ", regexp.MustCompile(`Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src>[0-9a-fA-F.:]+) port (?P<port>\d+)`)},
	{"sshd_failed", "Failed ", regexp.MustCompile(`Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<src>[0-9a-fA-F.:]+) port (?P<port>\d+)`)},
	{"charon_established", "established between", regexp.MustCompile(`IKE_SA (?P<tunnel>\S+)\[\d+\] established between (?P<local>[0-9a-fA-F.:]+)\[[^\]]*\]\.\.\.(?P<peer>[0-9a-fA-F.:]+)\[`)},
	{"charon_deleted", "IKE_SA", regexp.MustCompile(`deleting IKE_SA (?P<tunnel>\S+)\[\d+\] between (?P<local>[0-9a-fA-F.:]+)\[[^\]]*\]\.\.\.(?P<peer>[0-9a-fA-F.:]+)\[`)},
	{"openvpn_connected", "Peer Connection Initiated", regexp.MustCompile(`(?P<user>[^\s/\[]+)/(?P<peer>[0-9a-fA-F.:]+):(?P<port>\d+) .*Peer Connection Initiated`)},
	{"openvpn_disconnected", "SIGTERM", regexp.MustCompile(`(?P<user>[^\s/\[]+)/(?P<peer>[0-9a-fA-F.:]+):(?P<port>\d+) SIGTERM\[soft,[^\]]*\] received, client-instance exiting`)},
}

// HasText reports whether any catalogue gate substring is present (cheap;
// the regex only runs in ParseText).
func HasText(s string) bool {
	for i := range textCatalogue {
		if containsStr(s, textCatalogue[i].gate) {
			return true
		}
	}
	return false
}

// ParseText matches s against the catalogue and returns the first hit.
func ParseText(s string) (Text, bool) {
	for i := range textCatalogue {
		p := &textCatalogue[i]
		if !containsStr(s, p.gate) {
			continue
		}
		m := p.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		t := Text{Kind: p.kind, Fields: make(map[string]string, len(m))}
		for j, name := range p.re.SubexpNames() {
			if name != "" && m[j] != "" {
				t.Fields[name] = m[j]
			}
		}
		return t, true
	}
	return Text{}, false
}

func containsStr(s, sub string) bool {
	n := len(sub)
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return true
		}
	}
	return false
}
