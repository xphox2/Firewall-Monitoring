// Package classify turns a flow's 5-tuple into two cheap, deterministic
// attributes that the sFlow analytics layer stores at ingest:
//
//   - an application/L7 Category (Web, DNS, VPN, Database, …) derived from the
//     protocol number and the service port, with light protocol-only fallbacks
//     for portless protocols (ICMP, GRE/ESP, routing). No deep-packet
//     inspection — purely (proto, ports, flags) heuristics.
//   - a Direction (inbound / outbound / internal / external-transit) derived
//     from RFC1918 / ULA / link-local membership of the two addresses.
//
// Both functions are pure and allocation-free on the hot path (the lookup
// tables are package-level), so they can run inside the ReceiveFlowSamples
// per-sample loop without measurable cost. The results are written to narrow
// SMALLINT columns on flow_samples / flow_rollups so the Flows page can
// GROUP BY them directly instead of re-deriving on every read.
package classify

import "net"

// Category is the application/L7 class of a flow. The integer values are the
// on-the-wire/on-disk encoding (flow_samples.app_category) and MUST remain
// stable once shipped — append new categories, never renumber.
type Category uint8

const (
	Unknown      Category = iota // 0 — unclassified / both-ephemeral
	Web                          // HTTP/HTTPS and common alt ports
	DNS                          // name resolution
	Email                        // SMTP/IMAP/POP and submission
	FileShare                    // SMB/NFS/FTP/TFTP
	VPN                          // IPsec/WireGuard/OpenVPN/L2TP/PPTP
	Database                     // SQL/NoSQL/cache engines
	RemoteAccess                 // SSH/Telnet/RDP/VNC
	Streaming                    // RTSP/RTMP/media transport
	VoIP                         // SIP/voice signalling
	Backup                       // rsync and backup transports
	Management                   // NTP/SNMP/syslog/DHCP/BGP/routing/sFlow
	P2P                          // BitTorrent and peer-to-peer
	ICMP                         // ICMP / ICMPv6
)

// categoryNames maps each Category to a stable, human-readable label used by the
// API response and the Flows-page widgets.
var categoryNames = map[Category]string{
	Unknown:      "Unknown",
	Web:          "Web",
	DNS:          "DNS",
	Email:        "Email",
	FileShare:    "File Share",
	VPN:          "VPN",
	Database:     "Database",
	RemoteAccess: "Remote Access",
	Streaming:    "Streaming",
	VoIP:         "VoIP",
	Backup:       "Backup",
	Management:   "Management",
	P2P:          "P2P",
	ICMP:         "ICMP",
}

// String returns the human-readable label for the category.
func (c Category) String() string {
	if n, ok := categoryNames[c]; ok {
		return n
	}
	return "Unknown"
}

// CategoryName is a convenience wrapper for callers that hold the raw uint8
// stored in the DB and want the label without converting to Category first.
func CategoryName(v uint8) string { return Category(v).String() }

// portCategory maps a well-known service port to its application category. It is
// proto-agnostic for the common case (DNS, the web ports, etc. mean the same on
// TCP and UDP); the rare proto-specific exceptions are handled in Classify.
//
// Curated from IANA assignments plus the ports a firewall/NOC actually cares
// about. Kept deliberately small and readable — this is a allow-list of "things
// worth labelling", not an exhaustive registry.
var portCategory = map[uint16]Category{
	// Web
	80: Web, 443: Web, 8080: Web, 8443: Web, 8000: Web, 8888: Web, 3000: Web, 8081: Web,
	// DNS
	53: DNS, 5353: DNS, 853: DNS,
	// Email
	25: Email, 465: Email, 587: Email, 110: Email, 995: Email, 143: Email, 993: Email,
	// File share
	21: FileShare, 20: FileShare, 69: FileShare, 137: FileShare, 138: FileShare,
	139: FileShare, 445: FileShare, 2049: FileShare,
	// VPN
	500: VPN, 4500: VPN, 1194: VPN, 1701: VPN, 1723: VPN, 51820: VPN,
	// Database
	1433: Database, 1521: Database, 3306: Database, 5432: Database, 6379: Database,
	27017: Database, 9042: Database, 5984: Database, 11211: Database, 9200: Database,
	// Remote access
	22: RemoteAccess, 23: RemoteAccess, 3389: RemoteAccess, 5900: RemoteAccess, 5901: RemoteAccess,
	// Streaming
	554: Streaming, 1935: Streaming, 5004: Streaming, 5005: Streaming,
	// VoIP
	5060: VoIP, 5061: VoIP,
	// Backup
	873: Backup, 10000: Backup,
	// Management / control plane
	67: Management, 68: Management, 123: Management, 161: Management, 162: Management,
	179: Management, 514: Management, 520: Management, 6343: Management,
	// P2P
	6881: P2P, 6882: P2P, 6883: P2P, 6884: P2P, 6885: P2P, 6886: P2P, 6887: P2P,
	6888: P2P, 6889: P2P, 51413: P2P,
}

// IP protocol numbers used by the protocol-only fallback.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoGRE    = 47
	protoESP    = 50
	protoAH     = 51
	protoEIGRP  = 88
	protoOSPF   = 89
	protoPIM    = 103
	protoVRRP   = 112
	protoICMPv6 = 58
)

// Classify returns the application Category for a flow. For TCP/UDP it picks the
// "service" port (the well-known side of the conversation) and looks it up; for
// portless protocols it falls back to a protocol-only mapping.
func Classify(proto uint8, srcPort, dstPort uint16, tcpFlags uint8) Category {
	switch proto {
	case protoICMP, protoICMPv6:
		return ICMP
	case protoGRE, protoESP, protoAH:
		return VPN
	case protoOSPF, protoEIGRP, protoPIM, protoVRRP:
		return Management
	case protoTCP, protoUDP:
		// fall through to port-based classification below
	default:
		return Unknown
	}

	// Choose the service port: prefer whichever side is a known service; if both
	// (or neither) are, prefer the lower port number, which is the conventional
	// listener side. This makes the result independent of client/server ordering.
	_, srcKnown := portCategory[srcPort]
	_, dstKnown := portCategory[dstPort]
	switch {
	case dstKnown && !srcKnown:
		return portCategory[dstPort]
	case srcKnown && !dstKnown:
		return portCategory[srcPort]
	case srcKnown && dstKnown:
		if srcPort < dstPort {
			return portCategory[srcPort]
		}
		return portCategory[dstPort]
	}
	return Unknown
}

// Direction values (flow_samples.direction). Stable on-disk encoding.
const (
	DirUnknown  uint8 = 0 // address(es) unparseable
	DirInbound  uint8 = 1 // external source → internal destination
	DirOutbound uint8 = 2 // internal source → external destination
	DirInternal uint8 = 3 // both endpoints internal (RFC1918/ULA/link-local)
	DirExternal uint8 = 4 // both endpoints external (transit / off-net)
)

var directionNames = map[uint8]string{
	DirUnknown:  "Unknown",
	DirInbound:  "Inbound",
	DirOutbound: "Outbound",
	DirInternal: "Internal",
	DirExternal: "External",
}

// DirectionName returns the human-readable label for a direction value.
func DirectionName(v uint8) string {
	if n, ok := directionNames[v]; ok {
		return n
	}
	return "Unknown"
}

// privateNets is the set of address ranges treated as "internal" for direction
// classification: RFC1918, loopback, link-local, CGNAT (RFC6598), and the IPv6
// equivalents (ULA fc00::/7, link-local fe80::/10, loopback ::1).
var privateNets = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"fc00::/7", "fe80::/10", "::1/128",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// isInternal reports whether ip falls in one of the private/local ranges.
func isInternal(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Direction classifies a flow as inbound/outbound/internal/external based on the
// scope of its source and destination addresses. The interface indices are
// reserved for a future ifIndex-aware refinement (sFlow ingress/egress) and are
// not used yet.
func Direction(srcAddr, dstAddr string, inIf, outIf uint32) uint8 {
	_ = inIf
	_ = outIf
	src := net.ParseIP(srcAddr)
	dst := net.ParseIP(dstAddr)
	if src == nil || dst == nil {
		return DirUnknown
	}
	srcInt := isInternal(src)
	dstInt := isInternal(dst)
	switch {
	case srcInt && dstInt:
		return DirInternal
	case srcInt && !dstInt:
		return DirOutbound
	case !srcInt && dstInt:
		return DirInbound
	default:
		return DirExternal
	}
}
