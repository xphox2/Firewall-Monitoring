package classify

import "strings"

// appNameCategory maps EXPORTER-provided application names (PAN App-ID,
// FortiGate application options) to our Category taxonomy. This is the
// "vendor truth outranks the port heuristic" contract documented on
// FlowSample.AppName: the firewall performed real L7 identification, so when
// it says a flow on a non-standard port is SSL or SSH, we believe it over the
// port table.
//
// Deliberately conservative: only protocol-shaped names with an unambiguous
// category mapping are listed (mostly PAN App-ID names, which are lowercase —
// https://applipedia.paloaltonetworks.com). Thousands of PAN App-IDs name
// SaaS products ("salesforce", "dropbox") whose category in OUR taxonomy is
// genuinely ambiguous — those fall through to the port heuristic rather than
// guess. Keys are matched after lowercasing and stripping a "-base" suffix
// (PAN ships container apps as "dns-base", "bittorrent-base", …).
var appNameCategory = map[string]Category{
	// Web
	"web-browsing": Web, "http": Web, "https": Web, "ssl": Web, "tls": Web,
	"http2": Web, "quic": Web,
	// DNS
	"dns": DNS, "mdns": DNS, "dns-over-https": DNS, "dns-over-tls": DNS,
	// Email
	"smtp": Email, "imap": Email, "pop3": Email,
	// File share
	"ftp": FileShare, "tftp": FileShare, "smb": FileShare, "ms-ds-smb": FileShare,
	"nfs": FileShare, "netbios-ss": FileShare,
	// VPN
	"ipsec": VPN, "ike": VPN, "openvpn": VPN, "wireguard": VPN,
	"l2tp": VPN, "pptp": VPN, "gre": VPN, "ipsec-esp": VPN, "ipsec-esp-udp": VPN,
	// Database
	"mssql": Database, "mssql-db": Database, "mysql": Database, "postgres": Database,
	"postgresql": Database, "oracle": Database, "redis": Database, "mongodb": Database,
	"memcached": Database, "elasticsearch": Database,
	// Remote access
	"ssh": RemoteAccess, "telnet": RemoteAccess, "ms-rdp": RemoteAccess,
	"rdp": RemoteAccess, "vnc": RemoteAccess,
	// Streaming
	"rtsp": Streaming, "rtmp": Streaming, "rtmpt": Streaming,
	// VoIP
	"sip": VoIP, "rtp": VoIP, "rtcp": VoIP,
	// Backup
	"rsync": Backup,
	// Management / control plane
	"ntp": Management, "snmp": Management, "syslog": Management, "dhcp": Management,
	"bgp": Management, "ospf": Management, "radius": Management, "tacacs-plus": Management,
	// P2P
	"bittorrent": P2P, "gnutella": P2P, "emule": P2P,
	// ICMP
	"icmp": ICMP, "ping": ICMP,
}

// FromAppName maps an exporter-provided application name to a Category.
// ok=false means the name is empty or unknown — the caller falls through to
// the port heuristic (Classify). Never returns Unknown with ok=true: a mapped
// name is always a definite category, so vendor truth can only ADD precision,
// never erase what the port heuristic would have found.
func FromAppName(name string) (Category, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return Unknown, false
	}
	if cat, ok := appNameCategory[name]; ok {
		return cat, true
	}
	// PAN container-app convention: "dns-base" is the base signature of "dns".
	if base, found := strings.CutSuffix(name, "-base"); found {
		if cat, ok := appNameCategory[base]; ok {
			return cat, true
		}
	}
	return Unknown, false
}
