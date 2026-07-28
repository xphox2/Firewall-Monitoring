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
//
// End and Subject exist so the UI can put a finding next to the thing that
// caused it instead of in a flat list at the bottom of the form. Both are
// additive JSON: older consumers that read only severity/message are unaffected.
//
//   - End is the endpoint index the finding is about, or nil for a tunnel-level
//     finding (crypto, mode, subnet overlap). It is a POINTER because end A is
//     index 0, and a plain int would be indistinguishable from "not set" — in
//     JS, `if (f.end)` on a 0 silently drops every end-A finding.
//   - Subject is the specific value the finding is about (usually a subnet) when
//     one finding of a code can be raised several times for one end. Without it
//     the UI cannot tell WHICH of two mismatched subnets to highlight, and the
//     only alternative — parsing it back out of Message — would weld the client
//     to server prose.
type Finding struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	End      *int     `json:"end,omitempty"`
	Subject  string   `json:"subject,omitempty"`
}

// endRef is the End value for a finding that belongs to one endpoint.
func endRef(i int) *int { return &i }

// tunnelWide is the End value for a finding that belongs to the tunnel rather
// than to either endpoint. Named rather than a bare nil so every call site has
// to state which it means.
var tunnelWide *int

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
	// end is the endpoint the finding belongs to (endRef(i)), or tunnelWide.
	// Taking it as a parameter — rather than defaulting it — is deliberate: the
	// signature change makes the compiler enumerate every call site so each one
	// has to decide, instead of ~37 of them silently compiling with no end and
	// leaving the UI unable to anchor them.
	add := func(end *int, sev Severity, code, msg string) {
		fs = append(fs, Finding{Severity: sev, Code: code, Message: msg, End: end})
	}

	// Reserve the <uuid:NAME> substitution token: operator free-text that reaches a
	// checksummed apply-step body (IKE identities, PSK) must not contain it, or the
	// collector's UUID substitution would either splice into operator text or abort
	// on a bogus token (F7).
	if strings.Contains(intent.PSK, "<uuid:") {
		add(tunnelWide, SeverityBlock, "reserved_token", "the PSK must not contain the reserved substring \"<uuid:\"")
	}
	for i := range intent.Ends {
		if strings.Contains(intent.Ends[i].LocalID.Value, "<uuid:") {
			add(endRef(i), SeverityBlock, "reserved_token",
				fmt.Sprintf("%s identity must not contain the reserved substring \"<uuid:\"", endLabel(intent, i)))
		}
	}

	// --- capability intersection: both ends must support the chosen crypto/mode.
	for i, c := range caps {
		if !c.supportsIKE(intent.IKEVersion) {
			add(endRef(i), SeverityBlock, "ike_version_unsupported",
				fmt.Sprintf("%s does not support IKE %s", endLabel(intent, i), intent.IKEVersion))
		}
		if !c.supportsMode(intent.Mode) {
			add(endRef(i), SeverityBlock, "mode_unsupported",
				fmt.Sprintf("%s does not support %s tunnels", endLabel(intent, i), intent.Mode))
		}
		if !c.supportsEnc(intent.IKE.Enc) || !c.supportsEnc(intent.ESP.Enc) {
			add(endRef(i), SeverityBlock, "encryption_unsupported",
				fmt.Sprintf("%s does not support the selected encryption", endLabel(intent, i)))
		}
		if !c.supportsDH(intent.IKE.DH) {
			add(endRef(i), SeverityBlock, "dhgroup_unsupported",
				fmt.Sprintf("%s does not support IKE DH group %s", endLabel(intent, i), intent.IKE.DH))
		}
		if !c.supportsInteg(intent.IKE.Integ) || !c.supportsInteg(intent.ESP.Integ) {
			add(endRef(i), SeverityBlock, "integrity_unsupported",
				fmt.Sprintf("%s does not support the selected integrity algorithm", endLabel(intent, i)))
		}
		if !c.supportsPRF(intent.IKE.PRF) {
			add(endRef(i), SeverityBlock, "prf_unsupported",
				fmt.Sprintf("%s does not support the selected PRF", endLabel(intent, i)))
		}
		// Interface names and IKE IDs are interpolated into vendor CLI/config the
		// collector will apply — reject anything outside a safe token set so a
		// stray quote/space can't break out of the config context downstream.
		toks := []struct{ label, val string }{
			{"egress interface", intent.Ends[i].EgressIface},
			{"IKE identity", intent.Ends[i].LocalID.Value},
		}
		// Every LAN interface is interpolated, not just the first.
		for _, lan := range intent.Ends[i].EffectiveLANIfaces() {
			toks = append(toks, struct{ label, val string }{"LAN interface", lan})
		}
		for _, tok := range toks {
			if tok.val != "" && !safeToken(tok.val) {
				add(endRef(i), SeverityBlock, "unsafe_value",
					fmt.Sprintf("%s %s %q contains characters outside [A-Za-z0-9._:-]", endLabel(intent, i), tok.label, tok.val))
			}
		}
		// Explicit IKE identity is mandatory (the wizard designs out IP-default IDs
		// to avoid the NAT-ID failure class); an empty ID renders `set localid ""`.
		if intent.Ends[i].LocalID.Value == "" {
			add(endRef(i), SeverityBlock, "id_missing",
				fmt.Sprintf("%s must have an explicit IKE identity value", endLabel(intent, i)))
		}
		// Type-aware identity validation: block any value that would fail phase-1
		// auth on a FortiGate⇄OPNsense tunnel (see validateIdentity).
		fs = append(fs, validateIdentity(intent, i)...)
		// Egress + LAN interfaces are required: route-based rendering binds the VTI
		// to the egress and writes the LAN firewall policy, so an empty value would
		// emit `set interface ""` / a rule with no source interface downstream.
		if intent.Ends[i].EgressIface == "" {
			add(endRef(i), SeverityBlock, "egress_missing",
				fmt.Sprintf("%s must specify an egress (WAN) interface", endLabel(intent, i)))
		}
		// Only for vendors whose rules actually name an inside interface. OPNsense's
		// are floating and subnet-scoped, so requiring one there would demand a
		// value nothing reads. Tested on the EFFECTIVE list so a legacy intent
		// carrying only the singular still satisfies it, and so a list of blank
		// entries does not.
		if c.UsesLANIface && len(intent.Ends[i].EffectiveLANIfaces()) == 0 {
			add(endRef(i), SeverityBlock, "lan_missing",
				fmt.Sprintf("%s must specify at least one LAN interface", endLabel(intent, i)))
		}
		if intent.ESP.PFS != DHGroupNone && !c.supportsDH(intent.ESP.PFS) {
			add(endRef(i), SeverityBlock, "pfs_unsupported",
				fmt.Sprintf("%s does not support PFS DH group %s", endLabel(intent, i), intent.ESP.PFS))
		}
		if c.MaxTunnelNameLen > 0 && len(intent.Name) > c.MaxTunnelNameLen {
			add(endRef(i), SeverityBlock, "name_too_long",
				fmt.Sprintf("tunnel name %q exceeds %s's %d-character limit", intent.Name, c.Vendor, c.MaxTunnelNameLen))
		}
	}

	// --- deprecated crypto: red-flag (warn), never silently accept.
	if intent.IKEVersion == IKEv1 {
		add(tunnelWide, SeverityWarn, "ikev1_deprecated", "IKEv1 is deprecated (RFC 9395) — use IKEv2 unless a peer requires it")
	}
	for _, e := range []Encryption{intent.IKE.Enc, intent.ESP.Enc} {
		if e == Enc3DES {
			add(tunnelWide, SeverityWarn, "weak_encryption", "3DES is broken (SWEET32) — do not use for new tunnels")
		}
	}
	for _, in := range []Integrity{intent.IKE.Integ, intent.ESP.Integ} {
		if in == IntegritySHA1 {
			add(tunnelWide, SeverityWarn, "weak_integrity", "SHA-1 is deprecated — use SHA-256 or better")
		}
	}
	for _, g := range []DHGroup{intent.IKE.DH, intent.ESP.PFS} {
		if g == DHGroup2 || g == DHGroup5 {
			add(tunnelWide, SeverityWarn, "weak_dhgroup", fmt.Sprintf("DH group %s is too weak — use group 14 or an ECP group", g))
		}
	}

	// --- non-AEAD ciphers REQUIRE an integrity algorithm (GCM carries its own).
	if !isAEAD(intent.IKE.Enc) && intent.IKE.Integ == IntegrityNone {
		add(tunnelWide, SeverityBlock, "integrity_required", "the IKE cipher is not AEAD and needs an integrity algorithm")
	}
	if !isAEAD(intent.ESP.Enc) && intent.ESP.Integ == IntegrityNone {
		add(tunnelWide, SeverityBlock, "integrity_required", "the ESP cipher is not AEAD and needs an integrity algorithm")
	}

	// --- PSK hard floor.
	if ok, reason := validPSK(intent.PSK); !ok {
		add(tunnelWide, SeverityBlock, "psk_invalid", reason)
	}

	// --- initiator: at least one end must be static (able to be dialed).
	if intent.Ends[0].Dynamic && intent.Ends[1].Dynamic {
		add(tunnelWide, SeverityBlock, "no_initiator", "both ends are dynamic/behind NAT — at least one end must have a reachable static endpoint")
	}

	// --- route-based needs a VTI transit subnet.
	if intent.Mode == ModeRouteBased && strings.TrimSpace(intent.VTISubnet) == "" {
		add(tunnelWide, SeverityBlock, "vti_missing", "a route-based tunnel needs a VTI transit subnet")
	}

	// --- route-based + a dynamic (dialup) peer has no working way to steer
	// return traffic on FortiGate, so refuse it rather than deploy a tunnel that
	// comes up and silently carries nothing outbound.
	//
	// Since FortiOS 7.0.1 a route binds to a tunnel by tun_id. A dialup phase1
	// gives each peer a sub-tunnel with its own tun_id, so a static route naming
	// the parent interface matches no sub-tunnel and traffic dies at IPsec
	// egress. The supported substitute is phase1 add-route, which installs a
	// route per NEGOTIATED phase2 selector — but a route-based tunnel negotiates
	// 0.0.0.0/0, so add-route would install a DEFAULT ROUTE via the tunnel
	// instead of the protected subnets. That is both wrong (the protected
	// subnets get no specific route) and dangerous (it can capture unrelated
	// traffic on a device whose own default route has a higher distance).
	//
	// Policy-based is unaffected: it negotiates the protected subnets as the
	// selectors, so add-route installs exactly the right per-subnet routes.
	if intent.Mode == ModeRouteBased {
		for i := range intent.Ends {
			peer := 1 - i
			if intent.Ends[peer].Dynamic && intent.Ends[i].Vendor == "fortigate" {
				add(endRef(i), SeverityBlock, "routebased_dialup_unsupported",
					fmt.Sprintf("%s: a route-based tunnel to a dynamic/behind-NAT peer cannot steer return traffic on FortiGate "+
						"(a dialup peer's routes must come from phase1 add-route, which follows the negotiated selectors — and "+
						"route-based negotiates 0.0.0.0/0, so it would install a default route via the tunnel rather than the "+
						"protected subnets). Use policy-based mode for this tunnel, or give the peer a reachable static address.",
						endLabel(intent, i)))
			}
		}
	}

	// --- policy-based: the protected subnets ARE the traffic selectors, so each
	// end must declare at least one (empty selectors = no tunneled traffic).
	if intent.Mode == ModePolicyBased {
		for i := range intent.Ends {
			if len(intent.Ends[i].ProtectedSubnets) == 0 {
				add(endRef(i), SeverityBlock, "selectors_missing",
					fmt.Sprintf("%s: a policy-based tunnel needs at least one protected subnet (it is the traffic selector)", endLabel(intent, i)))
			}
		}
	}

	// --- protected-subnet linters (overlap + self-lockout).
	fs = append(fs, validateSubnets(intent)...)

	// --- selectively disabled paths.
	fs = append(fs, validateDisabledPaths(intent)...)

	// --- MTU/MSS + reachability warnings.
	for i := range intent.Ends {
		e := &intent.Ends[i]
		if caps[i].MSSClamp && e.MSSClamp == 0 {
			add(endRef(i), SeverityWarn, "mss_unset",
				fmt.Sprintf("%s has no TCP MSS clamp — large packets may drop over the tunnel (recommend ~1350)", endLabel(intent, i)))
		}
		// A non-dynamic (dialable) end MUST carry a valid endpoint IP: it is
		// interpolated unquoted into vendor config (FortiGate `set remote-gw`,
		// OPNsense remote_addrs), so an unparsable/empty value must be blocked,
		// not just warned. (Dynamic ends legitimately have no static peer IP.)
		if !e.Dynamic {
			ip := net.ParseIP(e.PeerIP)
			peer := &intent.Ends[1-i]
			peerIP := net.ParseIP(peer.PeerIP)
			switch {
			case ip == nil:
				add(endRef(i), SeverityBlock, "peer_ip_invalid",
					fmt.Sprintf("%s has no valid static endpoint IP address", endLabel(intent, i)))
			case isPrivate(ip) && !peer.Dynamic && peerIP != nil && !isPrivate(peerIP):
				// This end's private/CGNAT address becomes the far (public) peer's
				// STATIC remote-gateway (FortiGate `set remote-gw`, OPNsense
				// remote_addrs) — an unroutable address across the internet, so the
				// tunnel can never establish. The behind-NAT end must be marked
				// dynamic (dialup) or carry its real public IP. Block, don't warn:
				// this is a guaranteed dead tunnel, not a "confirm reachability".
				add(endRef(i), SeverityBlock, "peer_unroutable",
					fmt.Sprintf("%s endpoint %s is a private/CGNAT address but %s is public — the peer cannot reach a private address across the internet. Mark %s as dynamic (behind NAT), or enter its real public IP.",
						endLabel(intent, i), e.PeerIP, endLabel(intent, 1-i), endLabel(intent, i)))
			case isPrivate(ip):
				// Both ends private (LAN-to-LAN) or the peer is itself dynamic —
				// plausibly reachable; keep the softer confirm-reachability warning.
				add(endRef(i), SeverityWarn, "peer_private",
					fmt.Sprintf("%s's endpoint %s is a private/CGNAT address — confirm it is reachable by the peer", endLabel(intent, i), e.PeerIP))
			}
		}
		// OPNsense's data-plane pass rule is FLOATING (interface-agnostic — its filter
		// API cannot name the enc0/IPsec interface), so it also matches a same-5-tuple
		// packet arriving on ANY interface. For PRIVATE protected subnets, OPNsense's
		// default WAN block-private/antispoof drops a spoofed WAN packet before this
		// rule; with a PUBLIC protected subnet that guarantee is gone. Warn so the
		// operator confirms WAN anti-spoofing is enabled.
		if e.Vendor == "opnsense" {
			for _, s := range append(append([]string{}, e.ProtectedSubnets...), intent.Ends[1-i].ProtectedSubnets...) {
				if ip, _, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil && !isPrivate(ip) {
					// Word it as a tunnel-level fact (the public subnet may be on either
					// end); the pass rule lives on this OPNsense end.
					add(endRef(i), SeverityWarn, "firewall_floating_public_subnet",
						fmt.Sprintf("%s's tunnel pass rule is interface-agnostic (floating) and this tunnel carries a public subnet (%s) — ensure WAN anti-spoofing/block-private is enabled so the rule can't be abused by spoofed traffic", endLabel(intent, i), s))
					break
				}
			}
		}
		if e.InnerIP != "" && net.ParseIP(e.InnerIP) == nil {
			add(endRef(i), SeverityBlock, "inner_ip_invalid",
				fmt.Sprintf("%s VTI inner address %q is not a valid IP", endLabel(intent, i), e.InnerIP))
		}
		// AUDIT IP5: the WAN next-hop gateway, when set, is rendered unquoted into
		// the FortiGate peer host-route (`set gateway <ip>`); an unparsable value
		// reaches the device and fails the route write → rollback. Block early.
		if e.Gateway != "" && net.ParseIP(e.Gateway) == nil {
			add(endRef(i), SeverityBlock, "gateway_invalid",
				fmt.Sprintf("%s WAN gateway %q is not a valid IP", endLabel(intent, i), e.Gateway))
		}
		// AUDIT IP5: child (phase2) lifetime sanity. Negative is nonsensical;
		// it should also rekey before the IKE SA so the initiator owns rekey.
		if e.ChildLifetimeSecs < 0 {
			add(endRef(i), SeverityBlock, "child_lifetime_invalid",
				fmt.Sprintf("%s child lifetime must not be negative", endLabel(intent, i)))
		} else if e.ChildLifetimeSecs > 0 && intent.IKELifetimeSecs > 0 && e.ChildLifetimeSecs >= intent.IKELifetimeSecs {
			add(endRef(i), SeverityWarn, "child_lifetime_ge_ike",
				fmt.Sprintf("%s child lifetime (%ds) is not shorter than the IKE lifetime (%ds) — the child should rekey first",
					endLabel(intent, i), e.ChildLifetimeSecs, intent.IKELifetimeSecs))
		}
	}
	// AUDIT IP5: IKE lifetime range. Values outside the commonly-supported
	// 120–172800s window are rejected at render on some vendors (FortiGate), which
	// otherwise surfaces only as a cryptic pre-dispatch 400. Warn (OPNsense accepts
	// a wider range, so don't hard-block) unless it's non-positive.
	if intent.IKELifetimeSecs < 0 {
		add(tunnelWide, SeverityBlock, "ike_lifetime_invalid", "IKE lifetime must be positive")
	} else if intent.IKELifetimeSecs > 0 && (intent.IKELifetimeSecs < 120 || intent.IKELifetimeSecs > 172800) {
		add(tunnelWide, SeverityWarn, "ike_lifetime_range",
			fmt.Sprintf("IKE lifetime %ds is outside the commonly-supported 120–172800s range and may be rejected by some vendors", intent.IKELifetimeSecs))
	}
	if intent.DPD.DelaySecs <= 0 {
		add(tunnelWide, SeverityWarn, "dpd_off", "dead-peer detection is off — a dead peer won't be noticed and routes may blackhole")
	}

	return fs
}

// validateSubnets checks overlap between the two ends' protected subnets and the
// self-lockout condition (a routed subnet containing the remote peer's endpoint).
func validateSubnets(intent *TunnelIntent) []Finding {
	var fs []Finding
	a, aErr := parseCIDRs(intent.Ends[0].ProtectedSubnets)
	b, bErr := parseCIDRs(intent.Ends[1].ProtectedSubnets)
	// Reported per end rather than as one merged list: a malformed CIDR is only
	// actionable if the operator knows WHICH side's box to fix.
	// Fixed order, not a map: ranging over a map randomizes which end's parse
	// errors come first, so the findings list would reorder run-to-run for
	// identical input — noise in diffs, snapshots and any UI that lists them.
	for end, errs := range [2][]string{aErr, bErr} {
		for _, e := range errs {
			fs = append(fs, Finding{Severity: SeverityBlock, Code: "subnet_invalid", Message: e, End: endRef(end)})
		}
	}

	// Cap protected subnets per end: FortiGate routes/policies use deterministic
	// mkeys in a per-tunnel block (see allocation.go FGRouteKey/FGPolicyKey) that
	// fits at most MaxProtectedSubnetsPerEnd routed subnets before the route keys
	// would overrun the policy keys. Enforce it here so a too-large tunnel is
	// blocked at validation, never silently overwriting its own policy on apply.
	for i := range intent.Ends {
		if n := len(intent.Ends[i].ProtectedSubnets); n > MaxProtectedSubnetsPerEnd {
			fs = append(fs, Finding{Severity: SeverityBlock, Code: "too_many_subnets", End: endRef(i), Message: fmt.Sprintf("%s has %d protected subnets — the maximum is %d (deterministic route/policy key allocation); split into multiple tunnels", endLabel(intent, i), n, MaxProtectedSubnetsPerEnd)})
		}
	}

	// Duplicate canonical networks WITHIN one end.
	//
	// Nothing forbade this before, and it was merely wasteful — two entries that
	// canonicalise the same render identical duplicate phase2s. It becomes a
	// correctness problem once DisabledPaths keys are content-addressed: two raw
	// entries collapsing to one key means a single disabled entry silently
	// governs two lanes, and the "is any path still using this subnet" count is
	// wrong. Content keys are only trustworthy while canonical forms are unique
	// within an end.
	//
	// One finding per offending RAW entry, each carrying its own Subject, so the
	// wizard highlights both rows rather than only the first match.
	for i := range intent.Ends {
		seen := make(map[string]string, len(intent.Ends[i].ProtectedSubnets))
		for _, raw := range intent.Ends[i].ProtectedSubnets {
			c := canonCIDR(raw)
			if c == "" {
				continue // subnet_invalid already covers unparseable entries
			}
			if first, dup := seen[c]; dup {
				fs = append(fs, Finding{
					Severity: SeverityBlock, Code: "subnet_duplicate_within_end", End: endRef(i),
					Subject: raw,
					Message: fmt.Sprintf("%s: %s and %s are the same network (%s) — list it once",
						endLabel(intent, i), first, raw, c),
				})
				continue
			}
			seen[c] = raw
		}
	}

	// Overlap: the two sides must be disjoint (or 1:1 NAT — deferred past v1).
	for _, na := range a {
		for _, nb := range b {
			if netsOverlap(na, nb) {
				fs = append(fs, Finding{Severity: SeverityBlock, Code: "subnet_overlap", End: tunnelWide, Message: fmt.Sprintf("protected networks overlap (%s ↔ %s) — they must be disjoint", na.String(), nb.String())})
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
				// End is the PEER, not i: the finding is raised for end i but the
				// 0/0 lives in the peer's protected list, and that is the field the
				// operator has to edit.
				fs = append(fs, Finding{Severity: SeverityBlock, Code: "default_route_over_vti", End: endRef(1 - i), Subject: subjectFor(peer.ProtectedSubnets, n),
					Message: fmt.Sprintf("%s would route 0.0.0.0/0 over the tunnel — a pinned host route to the peer is required first", endLabel(intent, i))})
				continue
			}
			// A very broad covering prefix (e.g. the 0.0.0.0/1 + 128.0.0.0/1
			// full-tunnel split) is a default-route equivalent: it captures ~all
			// traffic including the peer's own path, so it needs a pinned peer route
			// first — block it like 0/0, above. isBroadCoverPrefix keeps this from
			// being bypassed by the /1 halves of a full tunnel.
			//
			// For a DYNAMIC peer this blocks UNCONDITIONALLY, without asking whether
			// the prefix contains PeerIP. The recorded PeerIP of a dialup end is its
			// management address, not the endpoint it actually dials in from, so a
			// "does not contain it" answer proves nothing — and a broad prefix is
			// long enough to beat the device's own default route regardless of
			// distance, so it can swallow the peer's real NAT address and capture a
			// huge slice of traffic. There is also no remedy available: the /32 pin
			// needs an address nobody knows. Like routebased_dialup_unsupported,
			// this combination has no working form, so refuse it outright.
			if isBroadCoverPrefix(n) && (peer.Dynamic || (peerIP != nil && n.Contains(peerIP))) {
				msg := fmt.Sprintf("%s would route %s over the tunnel — effectively a default route capturing the peer %s; a pinned host route to the peer is required first", endLabel(intent, i), n.String(), peer.PeerIP)
				if peer.Dynamic {
					msg = fmt.Sprintf("%s would route %s over the tunnel to a dynamic/behind-NAT peer — effectively a default route, and the peer's real endpoint is not known in advance, so it cannot be excluded with a pinned host route. Narrow the protected subnets to the networks that actually need the tunnel.", endLabel(intent, i), n.String())
				}
				fs = append(fs, Finding{Severity: SeverityBlock, Code: "default_route_over_vti", End: endRef(1 - i), Subject: subjectFor(peer.ProtectedSubnets, n), Message: msg})
				continue
			}
			// Beyond the broad-prefix case, a DYNAMIC peer's PeerIP is not an IKE
			// endpoint — this end never dials it (the peer initiates, and ESP returns
			// to whatever source its NAT presents), so it cannot be locked out by
			// routing its subnet down the tunnel. Warning about it would be a false
			// premise, and would invite the operator to set a Gateway that pins a /32
			// out the WAN over a legitimate in-tunnel host. The driver's
			// peerRouteNeeded declines that route for the same reason; keep in step.
			if peer.Dynamic {
				continue
			}
			if peerIP != nil && n.Contains(peerIP) {
				// A specific routed subnet that contains the peer's own endpoint is
				// safe ONLY if a host route to the peer via the WAN is pinned. When
				// THIS end supplies a WAN Gateway, the apply path renders that /32
				// automatically (see the driver's peer-route step) — so the case is
				// resolved and NO finding is raised. Without a Gateway it's an
				// acknowledgeable warning (a WAN default route may already cover it).
				if intent.Ends[i].Gateway != "" {
					continue
				}
				fs = append(fs, Finding{Severity: SeverityWarn, Code: "self_lockout", End: endRef(1 - i), Subject: subjectFor(peer.ProtectedSubnets, n), Message: fmt.Sprintf("protected subnet %s includes the peer's WAN endpoint %s — set %s's WAN gateway to auto-pin a /32 host route to the peer, or remove the WAN/transit network from this protected list", n.String(), peer.PeerIP, endLabel(intent, i))})
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

// subjectFor returns the subnet AS THE OPERATOR TYPED IT.
//
// Subject is a UI matching key: the wizard highlights the row whose text equals
// it. net.IPNet.String() canonicalizes, so a textarea holding "10.0.0.1/8" would
// yield Subject "10.0.0.0/8" and match nothing on screen — the finding would
// anchor to the field but the offending row would never light up. Falls back to
// the canonical form when no raw entry corresponds (it always should).
func subjectFor(raw []string, n *net.IPNet) string {
	want := n.String()
	for _, c := range raw {
		c = strings.TrimSpace(c)
		if _, p, err := net.ParseCIDR(c); err == nil && p.String() == want {
			return c
		}
	}
	return want
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

// validateIdentity blocks IKE identity VALUES that would fail phase-1 auth on a
// FortiGate⇄OPNsense tunnel. The two vendors classify the identity TYPE
// differently: FortiGate's `localid-type` FORCES the type, but OPNsense renders
// the swanctl id bare, so strongSwan AUTO-classifies it (an IP-literal →
// ID_IPV4/6_ADDR, an "ip-ip" range → ID_IPV4_ADDR_RANGE, a value with `:` →
// IPv6-or-KEY_ID, else → ID_FQDN). If the two ends disagree on the type the SA
// fails with AUTH_FAILED (the same class as the v0.11.147 keyid fix). A
// single-label value like "TECHLABS" is fine — both vendors accept it as an
// FQDN identity, so it is deliberately NOT flagged. The generic charset gate
// (safeToken) has already run in the caller; this adds the type-specific rules.
func validateIdentity(intent *TunnelIntent, i int) []Finding {
	var fs []Finding
	id := intent.Ends[i].LocalID
	val := id.Value
	if val == "" {
		return fs // handled by the id_missing block
	}
	label := endLabel(intent, i)

	// The value mirrors into FortiGate `localid` AND `peerid` (the other end's id),
	// both capped at 63 characters — applies to every identity type.
	if len(val) > 63 {
		fs = append(fs, Finding{Severity: SeverityBlock, Code: "id_too_long", End: endRef(i), Message: fmt.Sprintf("%s IKE identity %q is %d characters — the maximum is 63 (FortiGate limit)", label, val, len(val))})
	}

	switch id.Type {
	case IDTypeFQDN:
		switch {
		case net.ParseIP(val) != nil:
			fs = append(fs, Finding{Severity: SeverityBlock, Code: "id_fqdn_is_ip", End: endRef(i), Message: fmt.Sprintf("%s FQDN identity %q is an IP address — strongSwan would treat it as an IP identity while FortiGate sends it as an FQDN, so the tunnel fails to authenticate. Set the identity type to IP instead.", label, val)})
		case isIPRange(val):
			fs = append(fs, Finding{Severity: SeverityBlock, Code: "id_fqdn_is_range", End: endRef(i), Message: fmt.Sprintf("%s FQDN identity %q is an IP address range — strongSwan parses it as an address range, which cannot be an IKE identity.", label, val)})
		case safeToken(val) && !fqdnCharsOK(val):
			// safeToken permits ':' but a ':'-bearing value is read by strongSwan as
			// an IPv6 address, a KEY_ID, or a `type:` prefix — never the ID_FQDN
			// FortiGate sends. (Every other hostile char is already blocked by
			// safeToken/unsafe_value above, so this branch only catches ':'.)
			fs = append(fs, Finding{Severity: SeverityBlock, Code: "id_fqdn_charset", End: endRef(i), Message: fmt.Sprintf("%s FQDN identity %q must not contain ':' — the peer would interpret it as an IP/key-id, not an FQDN.", label, val)})
		}
	case IDTypeIP:
		if net.ParseIP(val) == nil {
			fs = append(fs, Finding{Severity: SeverityBlock, Code: "id_ip_invalid", End: endRef(i), Message: fmt.Sprintf("%s IP identity %q is not a valid IP address.", label, val)})
		}
	}
	return fs
}

// isIPRange reports whether s is an "ip-ip" address range (e.g.
// 10.0.0.1-10.0.0.9) — strongSwan (≥5.4.0) parses these as ID_IPV4_ADDR_RANGE,
// not an FQDN. Splits on the FIRST '-' so hostnames like "my-fw.example.com"
// (whose first segment isn't an IP) are not misdetected.
func isIPRange(s string) bool {
	i := strings.IndexByte(s, '-')
	if i <= 0 || i >= len(s)-1 {
		return false
	}
	return net.ParseIP(s[:i]) != nil && net.ParseIP(s[i+1:]) != nil
}

// fqdnCharsOK reports whether every rune is in [A-Za-z0-9._-] — the interop-safe
// FQDN-identity charset. Stricter than safeToken (which also allows ':') and
// deliberately includes '_' (strongSwan classifies it as FQDN, OPNsense allows
// it, and Fortinet's own docs use e.g. prince_1.test.com).
func fqdnCharsOK(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
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

// validateDisabledPaths checks the selective-path overlay.
//
// The wizard maintains the invariant that a subnet only stays listed while some
// path still uses it, but UpdateIPSecTunnel binds arbitrary intent JSON, so the
// server cannot assume it.
func validateDisabledPaths(intent *TunnelIntent) []Finding {
	var fs []Finding

	if intent.Mode != ModePolicyBased {
		if len(intent.DisabledPaths) > 0 {
			// Route-based negotiates a single 0.0.0.0/0 child and steers by route,
			// so there is nothing per-path to switch off and the list would sit
			// there looking effective while doing nothing.
			fs = append(fs, Finding{
				Severity: SeverityWarn, Code: "disabled_paths_ignored", End: tunnelWide,
				Message: "individual paths are disabled, but a route-based tunnel negotiates one 0.0.0.0/0 selector and steers by route — the selection has no effect here",
			})
		}
		return fs
	}

	paths := intent.PathsFor(0)
	if len(paths) == 0 {
		return fs // empty subnet lists — selectors_missing already covers it
	}

	enabled := 0
	for _, p := range paths {
		if p.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		fs = append(fs, Finding{
			Severity: SeverityBlock, Code: "all_paths_disabled", End: tunnelWide,
			Message: "every path is disabled — the tunnel would come up carrying nothing",
		})
		return fs
	}

	// A subnet that survives in the list with all of its paths switched off still
	// gets its route and blackhole on FortiGate, so traffic is sent into a tunnel
	// that holds no matching selector and is dropped. Fail-closed, but a silent
	// drop nobody asked for — worth saying out loud.
	for end := range intent.Ends {
		used := make(map[string]bool)
		for _, p := range intent.PathsFor(end) {
			if p.Enabled {
				used[p.Local] = true
			}
		}
		for _, s := range intent.Ends[end].ProtectedSubnets {
			if used[s] || canonCIDR(s) == "" {
				continue
			}
			fs = append(fs, Finding{
				Severity: SeverityWarn, Code: "subnet_all_paths_disabled", End: endRef(end),
				Subject: s,
				Message: fmt.Sprintf("%s: %s is listed but every path using it is disabled — it carries nothing, and traffic to it is dropped rather than routed elsewhere",
					endLabel(intent, end), s),
			})
		}
	}
	return fs
}
