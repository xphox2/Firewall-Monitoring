package ipsec

import (
	"fmt"
	"net"
	"strings"
)

// Severity of a validation finding.
type Severity string

const (
	// SeverityBlock refuses deploy until fixed (or auto-remediated).
	SeverityBlock Severity = "block"
	// SeverityWarn requires explicit acknowledgement to proceed.
	SeverityWarn Severity = "warn"
)

// Finding is one validation result. Code is a stable machine key; Message is
// human-facing.
type Finding struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

// HasBlock reports whether any finding blocks deploy.
func HasBlock(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SeverityBlock {
			return true
		}
	}
	return false
}

// Validate runs the vendor-neutral pre-flight linters against an intent, given
// each end's capability descriptor (caps[i] is Ends[i]'s vendor descriptor). It
// is pure — no device I/O — so it runs on every wizard step and again server-side
// before deploy. Cross-tunnel uniqueness (duplicate peer/ID triples) is checked
// at the handler layer where the other tunnels are known.
func Validate(intent *TunnelIntent, caps [2]CapabilityDescriptor) []Finding {
	var fs []Finding
	add := func(sev Severity, code, msg string) { fs = append(fs, Finding{sev, code, msg}) }

	// Reserve the <uuid:NAME> substitution token: operator free-text that reaches a
	// checksummed apply-step body (IKE identities, PSK) must not contain it, or the
	// collector's UUID substitution would either splice into operator text or abort
	// on a bogus token (F7).
	if strings.Contains(intent.PSK, "<uuid:") {
		add(SeverityBlock, "reserved_token", "the PSK must not contain the reserved substring \"<uuid:\"")
	}
	for i := range intent.Ends {
		if strings.Contains(intent.Ends[i].LocalID.Value, "<uuid:") {
			add(SeverityBlock, "reserved_token",
				fmt.Sprintf("%s identity must not contain the reserved substring \"<uuid:\"", endLabel(intent, i)))
		}
	}

	// --- capability intersection: both ends must support the chosen crypto/mode.
	for i, c := range caps {
		if !c.supportsIKE(intent.IKEVersion) {
			add(SeverityBlock, "ike_version_unsupported",
				fmt.Sprintf("%s does not support IKE %s", endLabel(intent, i), intent.IKEVersion))
		}
		if !c.supportsMode(intent.Mode) {
			add(SeverityBlock, "mode_unsupported",
				fmt.Sprintf("%s does not support %s tunnels", endLabel(intent, i), intent.Mode))
		}
		if !c.supportsEnc(intent.IKE.Enc) || !c.supportsEnc(intent.ESP.Enc) {
			add(SeverityBlock, "encryption_unsupported",
				fmt.Sprintf("%s does not support the selected encryption", endLabel(intent, i)))
		}
		if !c.supportsDH(intent.IKE.DH) {
			add(SeverityBlock, "dhgroup_unsupported",
				fmt.Sprintf("%s does not support IKE DH group %s", endLabel(intent, i), intent.IKE.DH))
		}
		if !c.supportsInteg(intent.IKE.Integ) || !c.supportsInteg(intent.ESP.Integ) {
			add(SeverityBlock, "integrity_unsupported",
				fmt.Sprintf("%s does not support the selected integrity algorithm", endLabel(intent, i)))
		}
		if !c.supportsPRF(intent.IKE.PRF) {
			add(SeverityBlock, "prf_unsupported",
				fmt.Sprintf("%s does not support the selected PRF", endLabel(intent, i)))
		}
		// Interface names and IKE IDs are interpolated into vendor CLI/config the
		// collector will apply — reject anything outside a safe token set so a
		// stray quote/space can't break out of the config context downstream.
		for _, tok := range []struct{ label, val string }{
			{"egress interface", intent.Ends[i].EgressIface},
			{"LAN interface", intent.Ends[i].LANIface},
			{"IKE identity", intent.Ends[i].LocalID.Value},
		} {
			if tok.val != "" && !safeToken(tok.val) {
				add(SeverityBlock, "unsafe_value",
					fmt.Sprintf("%s %s %q contains characters outside [A-Za-z0-9._:-]", endLabel(intent, i), tok.label, tok.val))
			}
		}
		// Explicit IKE identity is mandatory (the wizard designs out IP-default IDs
		// to avoid the NAT-ID failure class); an empty ID renders `set localid ""`.
		if intent.Ends[i].LocalID.Value == "" {
			add(SeverityBlock, "id_missing",
				fmt.Sprintf("%s must have an explicit IKE identity value", endLabel(intent, i)))
		}
		// Egress + LAN interfaces are required: route-based rendering binds the VTI
		// to the egress and writes the LAN firewall policy, so an empty value would
		// emit `set interface ""` / a rule with no source interface downstream.
		if intent.Ends[i].EgressIface == "" {
			add(SeverityBlock, "egress_missing",
				fmt.Sprintf("%s must specify an egress (WAN) interface", endLabel(intent, i)))
		}
		if intent.Ends[i].LANIface == "" {
			add(SeverityBlock, "lan_missing",
				fmt.Sprintf("%s must specify a LAN interface", endLabel(intent, i)))
		}
		if intent.ESP.PFS != DHGroupNone && !c.supportsDH(intent.ESP.PFS) {
			add(SeverityBlock, "pfs_unsupported",
				fmt.Sprintf("%s does not support PFS DH group %s", endLabel(intent, i), intent.ESP.PFS))
		}
		if c.MaxTunnelNameLen > 0 && len(intent.Name) > c.MaxTunnelNameLen {
			add(SeverityBlock, "name_too_long",
				fmt.Sprintf("tunnel name %q exceeds %s's %d-character limit", intent.Name, c.Vendor, c.MaxTunnelNameLen))
		}
	}

	// --- deprecated crypto: red-flag (warn), never silently accept.
	if intent.IKEVersion == IKEv1 {
		add(SeverityWarn, "ikev1_deprecated", "IKEv1 is deprecated (RFC 9395) — use IKEv2 unless a peer requires it")
	}
	for _, e := range []Encryption{intent.IKE.Enc, intent.ESP.Enc} {
		if e == Enc3DES {
			add(SeverityWarn, "weak_encryption", "3DES is broken (SWEET32) — do not use for new tunnels")
		}
	}
	for _, in := range []Integrity{intent.IKE.Integ, intent.ESP.Integ} {
		if in == IntegritySHA1 {
			add(SeverityWarn, "weak_integrity", "SHA-1 is deprecated — use SHA-256 or better")
		}
	}
	for _, g := range []DHGroup{intent.IKE.DH, intent.ESP.PFS} {
		if g == DHGroup2 || g == DHGroup5 {
			add(SeverityWarn, "weak_dhgroup", fmt.Sprintf("DH group %s is too weak — use group 14 or an ECP group", g))
		}
	}

	// --- non-AEAD ciphers REQUIRE an integrity algorithm (GCM carries its own).
	if !isAEAD(intent.IKE.Enc) && intent.IKE.Integ == IntegrityNone {
		add(SeverityBlock, "integrity_required", "the IKE cipher is not AEAD and needs an integrity algorithm")
	}
	if !isAEAD(intent.ESP.Enc) && intent.ESP.Integ == IntegrityNone {
		add(SeverityBlock, "integrity_required", "the ESP cipher is not AEAD and needs an integrity algorithm")
	}

	// --- PSK hard floor.
	if ok, reason := validPSK(intent.PSK); !ok {
		add(SeverityBlock, "psk_invalid", reason)
	}

	// --- initiator: at least one end must be static (able to be dialed).
	if intent.Ends[0].Dynamic && intent.Ends[1].Dynamic {
		add(SeverityBlock, "no_initiator", "both ends are dynamic/behind NAT — at least one end must have a reachable static endpoint")
	}

	// --- route-based needs a VTI transit subnet.
	if intent.Mode == ModeRouteBased && strings.TrimSpace(intent.VTISubnet) == "" {
		add(SeverityBlock, "vti_missing", "a route-based tunnel needs a VTI transit subnet")
	}

	// --- protected-subnet linters (overlap + self-lockout).
	fs = append(fs, validateSubnets(intent)...)

	// --- MTU/MSS + reachability warnings.
	for i := range intent.Ends {
		e := &intent.Ends[i]
		if caps[i].MSSClamp && e.MSSClamp == 0 {
			add(SeverityWarn, "mss_unset",
				fmt.Sprintf("%s has no TCP MSS clamp — large packets may drop over the tunnel (recommend ~1350)", endLabel(intent, i)))
		}
		// A non-dynamic (dialable) end MUST carry a valid endpoint IP: it is
		// interpolated unquoted into vendor config (FortiGate `set remote-gw`,
		// OPNsense remote_addrs), so an unparsable/empty value must be blocked,
		// not just warned. (Dynamic ends legitimately have no static peer IP.)
		if !e.Dynamic {
			ip := net.ParseIP(e.PeerIP)
			if ip == nil {
				add(SeverityBlock, "peer_ip_invalid",
					fmt.Sprintf("%s has no valid static endpoint IP address", endLabel(intent, i)))
			} else if isPrivate(ip) {
				add(SeverityWarn, "peer_private",
					fmt.Sprintf("%s's endpoint %s is a private/CGNAT address — confirm it is reachable by the peer", endLabel(intent, i), e.PeerIP))
			}
		}
		if e.InnerIP != "" && net.ParseIP(e.InnerIP) == nil {
			add(SeverityBlock, "inner_ip_invalid",
				fmt.Sprintf("%s VTI inner address %q is not a valid IP", endLabel(intent, i), e.InnerIP))
		}
	}
	if intent.DPD.DelaySecs <= 0 {
		add(SeverityWarn, "dpd_off", "dead-peer detection is off — a dead peer won't be noticed and routes may blackhole")
	}

	return fs
}

// validateSubnets checks overlap between the two ends' protected subnets and the
// self-lockout condition (a routed subnet containing the remote peer's endpoint).
func validateSubnets(intent *TunnelIntent) []Finding {
	var fs []Finding
	a, aErr := parseCIDRs(intent.Ends[0].ProtectedSubnets)
	b, bErr := parseCIDRs(intent.Ends[1].ProtectedSubnets)
	for _, e := range append(aErr, bErr...) {
		fs = append(fs, Finding{SeverityBlock, "subnet_invalid", e})
	}

	// Cap protected subnets per end: FortiGate routes/policies use deterministic
	// mkeys in a per-tunnel block (see allocation.go FGRouteKey/FGPolicyKey) that
	// fits at most MaxProtectedSubnetsPerEnd routed subnets before the route keys
	// would overrun the policy keys. Enforce it here so a too-large tunnel is
	// blocked at validation, never silently overwriting its own policy on apply.
	for i := range intent.Ends {
		if n := len(intent.Ends[i].ProtectedSubnets); n > MaxProtectedSubnetsPerEnd {
			fs = append(fs, Finding{SeverityBlock, "too_many_subnets",
				fmt.Sprintf("%s has %d protected subnets — the maximum is %d (deterministic route/policy key allocation); split into multiple tunnels", endLabel(intent, i), n, MaxProtectedSubnetsPerEnd)})
		}
	}

	// Overlap: the two sides must be disjoint (or 1:1 NAT — deferred past v1).
	for _, na := range a {
		for _, nb := range b {
			if netsOverlap(na, nb) {
				fs = append(fs, Finding{SeverityBlock, "subnet_overlap",
					fmt.Sprintf("protected networks overlap (%s ↔ %s) — they must be disjoint", na.String(), nb.String())})
			}
		}
	}

	// Self-lockout: end i routes the OTHER end's subnets into the tunnel. If a
	// routed subnet contains that peer's own endpoint IP, IKE/ESP to the peer get
	// swallowed by the tunnel → permanent flap. Also flag a default route (0/0)
	// over the VTI, which needs an explicit pinned peer host-route.
	for i := range intent.Ends {
		peer := &intent.Ends[1-i]
		routed, _ := parseCIDRs(peer.ProtectedSubnets) // subnets end i installs toward the tunnel
		peerIP := net.ParseIP(peer.PeerIP)
		for _, n := range routed {
			if isDefaultRoute(n) {
				// A default route already implies the peer-path problem; report it
				// once (the more specific self_lockout below is skipped for 0/0).
				fs = append(fs, Finding{SeverityBlock, "default_route_over_vti",
					fmt.Sprintf("%s would route 0.0.0.0/0 over the tunnel — a pinned host route to the peer is required first", endLabel(intent, i))})
				continue
			}
			if peerIP != nil && n.Contains(peerIP) {
				// A very broad covering prefix (e.g. the 0.0.0.0/1 + 128.0.0.0/1
				// full-tunnel split) is a default-route equivalent: it captures the
				// peer's own path and ~all traffic, so it needs a pinned peer route
				// first — block it like 0/0, above. isBroadCoverPrefix keeps this
				// from being bypassed by the /1 halves of a full tunnel.
				if isBroadCoverPrefix(n) {
					fs = append(fs, Finding{SeverityBlock, "default_route_over_vti",
						fmt.Sprintf("%s would route %s over the tunnel — effectively a default route capturing the peer %s; a pinned host route to the peer is required first", endLabel(intent, i), n.String(), peer.PeerIP)})
					continue
				}
				// A specific routed subnet that contains the peer's own endpoint is
				// safe ONLY if a host route to the peer via the WAN is pinned. When
				// THIS end supplies a WAN Gateway, the apply path renders that /32
				// automatically (see the driver's peer-route step) — so the case is
				// resolved and NO finding is raised. Without a Gateway it's an
				// acknowledgeable warning (a WAN default route may already cover it).
				if intent.Ends[i].Gateway != "" {
					continue
				}
				fs = append(fs, Finding{SeverityWarn, "self_lockout",
					fmt.Sprintf("protected subnet %s includes the peer's WAN endpoint %s — set this end's WAN gateway to auto-pin a /32 host route to the peer, or remove the WAN/transit network from the protected list", n.String(), peer.PeerIP)})
			}
		}
	}
	return fs
}

func parseCIDRs(cidrs []string) (nets []*net.IPNet, errs []string) {
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			errs = append(errs, fmt.Sprintf("invalid subnet %q", c))
			continue
		}
		nets = append(nets, n)
	}
	return nets, errs
}

func netsOverlap(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }

// SubnetContainsIP reports whether any of the CIDR subnets contains ipStr. It
// mirrors the self_lockout test above and is the single source both vendor
// drivers use to decide whether a peer /32 host route must be pinned (so the
// render condition and the validator can never drift).
func SubnetContainsIP(subnets []string, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	nets, _ := parseCIDRs(subnets)
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isAEAD reports whether an encryption algorithm carries its own integrity
// (Galois/Counter mode), so a separate integrity algorithm is neither needed nor
// used.
func isAEAD(e Encryption) bool { return e == EncAES256GCM16 || e == EncAES128GCM16 }

// safeToken reports whether s is a safe interface-name/IKE-ID token: only
// [A-Za-z0-9._:-], so it can't break out of a quoted CLI/config context.
func safeToken(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == ':':
		default:
			return false
		}
	}
	return true
}

func isDefaultRoute(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	return ones == 0 && bits != 0
}

// isBroadCoverPrefix reports whether n is broad enough to be a default-route
// equivalent (prefix shorter than /8 ⇒ ≥16M addresses — no real LAN is that wide,
// so a prefix this broad that also contains the peer is a full-tunnel attempt, not
// a specific protected subnet). Catches the 0.0.0.0/1 + 128.0.0.0/1 split.
func isBroadCoverPrefix(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	return bits != 0 && ones < 8
}

func isPrivate(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	// CGNAT 100.64.0.0/10 (RFC 6598).
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

func endLabel(intent *TunnelIntent, i int) string {
	if intent.Ends[i].Vendor != "" {
		return fmt.Sprintf("end %c (%s)", 'A'+i, intent.Ends[i].Vendor)
	}
	return fmt.Sprintf("end %c", 'A'+i)
}
