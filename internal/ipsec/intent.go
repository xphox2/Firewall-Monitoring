// Package ipsec is the vendor-neutral core of the cross-vendor IPSec tunnel
// provisioning wizard. It defines ONE canonical tunnel intent, renders it to
// per-vendor configuration through pluggable drivers, and validates it before
// any device is ever touched.
//
// Design axioms (see the plan):
//   - One intent → both ends. "local"/"remote" is a render-time projection
//     (RenderView), never stored — so the two ends can never drift.
//   - Crypto is structured enums, never vendor config strings. Each driver maps
//     the neutral token to its own dialect.
//   - Field classes (RFC 7296 semantics): tunnel-level fields are written
//     IDENTICALLY to both ends (proposal, PSK, PFS, mode); mirrored pairs are
//     auto-derived (IDs, subnets, gateways); per-end-local fields never go on
//     the wire (lifetimes, DPD, MSS, reqid).
//
// This package performs NO I/O and holds NO secrets in plaintext beyond the
// caller-provided PSK passed through at render time; persistence + encryption
// live in the database layer.
package ipsec

import (
	"net"
	"strings"
)

// Encryption, Integrity, PRF and DHGroup are neutral crypto tokens. Drivers
// translate them to vendor dialect; the wizard/validation never sees a vendor
// string. Empty means "not applicable" (e.g. AEAD ciphers carry their own
// integrity, so ESP integrity is IntegrityNone).
type (
	Encryption string
	Integrity  string
	PRF        string
	DHGroup    string
)

const (
	EncAES256GCM16 Encryption = "aes256gcm16"
	EncAES128GCM16 Encryption = "aes128gcm16"
	EncAES256CBC   Encryption = "aes256cbc"
	EncAES128CBC   Encryption = "aes128cbc"
	// Deprecated ciphers — allowed only via the Custom profile, always flagged.
	Enc3DES Encryption = "3des"

	IntegrityNone   Integrity = ""
	IntegritySHA512 Integrity = "sha512"
	IntegritySHA384 Integrity = "sha384"
	IntegritySHA256 Integrity = "sha256"
	IntegritySHA1   Integrity = "sha1" // deprecated
	PRFSHA512       PRF       = "prfsha512"
	PRFSHA384       PRF       = "prfsha384"
	PRFSHA256       PRF       = "prfsha256"
	PRFSHA1         PRF       = "prfsha1" // deprecated

	// DHGroupNone disables PFS on the child SA. Any other value is the PFS group.
	DHGroupNone DHGroup = ""
	DHGroup21   DHGroup = "21" // ECP-521
	DHGroup20   DHGroup = "20" // ECP-384
	DHGroup19   DHGroup = "19" // ECP-256
	DHGroup16   DHGroup = "16" // MODP-4096
	DHGroup15   DHGroup = "15" // MODP-3072
	DHGroup14   DHGroup = "14" // MODP-2048
	DHGroup5    DHGroup = "5"  // deprecated
	DHGroup2    DHGroup = "2"  // deprecated
)

// IKEVersion and Mode are small closed sets.
type (
	IKEVersion string
	Mode       string
	IDType     string
)

const (
	IKEv2 IKEVersion = "ikev2"
	IKEv1 IKEVersion = "ikev1" // deprecated (RFC 9395); aggressive+PSK is blocked entirely

	ModeRouteBased  Mode = "route-based"
	ModePolicyBased Mode = "policy-based"

	// IKE identity types. The wizard always sets explicit IDs (never IP-default)
	// to design out the NAT-ID failure class.
	IDTypeIP    IDType = "ip"
	IDTypeFQDN  IDType = "fqdn"
	IDTypeKeyID IDType = "keyid"
)

// IKEProposal is the Phase-1 (IKE SA) transform set. Integ is IntegrityNone for
// AEAD ciphers (GCM). Written IDENTICALLY to both ends.
type IKEProposal struct {
	Enc   Encryption `json:"enc"`
	Integ Integrity  `json:"integ"`
	PRF   PRF        `json:"prf"`
	DH    DHGroup    `json:"dh"`
}

// ESPProposal is the Phase-2 (child SA) transform set. Integ is IntegrityNone
// for AEAD. PFS is the DH group for perfect forward secrecy (DHGroupNone = off).
// Written IDENTICALLY to both ends.
type ESPProposal struct {
	Enc   Encryption `json:"enc"`
	Integ Integrity  `json:"integ"`
	PFS   DHGroup    `json:"pfs"`
}

// IKEIdentity is a peer's explicit IKE identity (never rely on IP-default).
type IKEIdentity struct {
	Type  IDType `json:"type"`
	Value string `json:"value"`
}

// EndpointSpec is one end of the tunnel. The two EndpointSpecs are symmetric;
// which is "local" vs "remote" depends only on the RenderView.
type EndpointSpec struct {
	// DeviceID is the monitored device this end provisions onto (0 = unmanaged
	// peer, rendered as a downloadable parameter sheet — deferred past v1).
	DeviceID uint   `json:"device_id"`
	Vendor   string `json:"vendor"`

	// PeerIP is this end's own tunnel endpoint address (its WAN / the address
	// the OTHER end dials). May be empty for a dynamic responder end.
	PeerIP string `json:"peer_ip"`
	// EgressIface is the WAN/outgoing interface the phase1 binds to.
	EgressIface string `json:"egress_iface"`
	// Gateway is this end's physical WAN next-hop IP. Used ONLY to pin a peer
	// /32 host route when a protected subnet would otherwise pull the peer's WAN
	// address into the tunnel (self-lockout). Empty unless that case applies;
	// operator-supplied (there is no route-table telemetry to auto-fill it).
	Gateway string `json:"gateway"`
	// LANIface is the inside interface for firewall policy src/dst.
	//
	// Deprecated as the source of truth: use EffectiveLANIfaces(). Kept populated
	// (mirroring LANIfaces[0]) so intents persisted before LANIfaces existed keep
	// working and older readers of the JSON are unaffected.
	LANIface string `json:"lan_iface"`
	// LANIfaces is the full set of inside interfaces for firewall policy src/dst.
	// A protected-subnet list can span several ports; naming only one meant the
	// policies covered one port while the phase2 selectors covered all of them,
	// so traffic on the others was silently dropped.
	LANIfaces []string `json:"lan_ifaces"`
	// LocalID is this end's IKE identity (mirrored as the peer's Remote ID).
	LocalID IKEIdentity `json:"local_id"`
	// Dynamic marks a responder end whose peer address is not statically known
	// (behind NAT / RFC1918 WAN); the other end must be the sole initiator.
	Dynamic bool `json:"dynamic"`

	// ProtectedSubnets drive STATIC ROUTES + firewall rules only (NOT phase2
	// selectors, which stay 0/0 for route-based).
	ProtectedSubnets []string `json:"protected_subnets"`

	// InnerIP is this end's address on the VTI /30 (route-based).
	InnerIP string `json:"inner_ip"`
	// Reqid / IfID / TunnelNum are per-end-local allocations the wizard owns.
	Reqid     int `json:"reqid"`
	IfID      int `json:"if_id"`
	TunnelNum int `json:"tunnel_num"`

	// ChildLifetimeSecs is per-end (deliberately offset — the initiator side is
	// shorter so it owns rekey, avoiding simultaneous-rekey duplicate SAs).
	ChildLifetimeSecs int `json:"child_lifetime_secs"`
	// MSSClamp is the per-end TCP MSS clamp (0 = none/auto).
	MSSClamp int `json:"mss_clamp"`
}

// EffectiveLANIfaces is the ONLY correct way to read this end's inside
// interfaces. It resolves LANIfaces, falling back to the legacy singular, then
// trims, drops empties and dedupes.
//
// It exists because the resolution has to hold on paths that never normalize.
// hydrateDerived runs on fresh JSON binds only — every read of a persisted
// intent (deploy, preflight, status, recheck) unmarshals straight from
// intent_json — so an intent stored before LANIfaces existed reaches the driver
// with the slice nil. A driver reading the slice directly would render a policy
// with no interface members: rejected by the device, or worse, a tunnel that
// comes up and drops everything.
//
// Normalizing here rather than at save time is likewise load-bearing: the
// wizard's comma-separated custom entry can yield empty elements, and a
// {"name": ""} member passes conformance (which models only `action`) before
// failing on the device mid-apply. FortiOS also rejects duplicate members.
func (e *EndpointSpec) EffectiveLANIfaces() []string {
	raw := e.LANIfaces
	if len(raw) == 0 && e.LANIface != "" {
		raw = []string{e.LANIface}
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, n := range raw {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// DPD is dead-peer-detection config (per-end-local, not negotiated).
type DPD struct {
	DelaySecs   int `json:"delay_secs"`
	TimeoutSecs int `json:"timeout_secs"` // IKEv1-only for strongSwan; drivers ignore where N/A
}

// TunnelIntent is the ONE canonical description of a tunnel. It renders to both
// ends. Tunnel-level crypto/PSK/mode are written identically to both ends;
// per-end detail lives in Ends[i].
type TunnelIntent struct {
	ID      uint   `json:"id"`
	Name    string `json:"name"` // fwm-t<ID>-safe; drivers truncate to CapabilityDescriptor.MaxTunnelNameLen
	Enabled bool   `json:"enabled"`

	IKEVersion IKEVersion  `json:"ike_version"`
	Mode       Mode        `json:"mode"`
	IKE        IKEProposal `json:"ike"`
	ESP        ESPProposal `json:"esp"`

	IKELifetimeSecs int `json:"ike_lifetime_secs"`
	DPD             DPD `json:"dpd"`

	// PSK is the plaintext pre-shared key, supplied only at render time (stored
	// encrypted; never persisted here). Redacted from every log/echo.
	PSK string `json:"psk,omitempty"`

	// VTISubnet is the /30 transit network for route-based tunnels (e.g.
	// 169.254.x.y/30); Ends[i].InnerIP are the two host addresses.
	VTISubnet string `json:"vti_subnet"`

	// DisabledPaths turns OFF individual subnet pairs. The selectors are
	// otherwise the full cross product of the two ends' ProtectedSubnets, which
	// grants every network on one side a path to every network on the other —
	// routinely handing a user VLAN a route to the far side's management net
	// purely because both were listed.
	//
	// Entries are "aCIDR|bCIDR" in tunnel A|B orientation (A is Ends[0]),
	// CANONICALISED via net.IPNet.String(). Canonical rather than raw — unlike
	// Finding.Subject, which must stay raw to match the operator's text on
	// screen — because this is a persisted identity: reformatting 10.0.0.1/8 to
	// 10.0.0.0/8 must keep a path disabled rather than silently re-enable it.
	// Fail closed. ('|' cannot occur in CIDR text, so it is an unambiguous
	// separator.)
	//
	// Empty (including absent from older stored JSON) means the full mesh, so
	// every tunnel written before this existed keeps exactly its old behaviour.
	// Read it through PathsFor, never directly.
	DisabledPaths []string `json:"disabled_paths"`

	Ends [2]EndpointSpec `json:"ends"`
}

// SubnetPath is one (local, remote) selector pair for a specific end.
//
// Index is the pair's position in THIS end's local×remote enumeration and is
// load-bearing: both drivers mint device object keys from it (FortiGate phase2
// mkeys name/name-1/name-2…, OPNsense child_<i>/rule_out_<i>/rule_in_<i>, whose
// tokens key the captured-UUID map rollback depends on). It therefore counts
// over the FULL cross product and never compacts — a disabled pair consumes its
// index and simply is not emitted. Compacting would slide name-3 down to name-2
// and silently re-point an existing device object at a different selector.
type SubnetPath struct {
	Index   int
	Local   string // raw, as the operator listed it
	Remote  string
	Enabled bool
}

// canonCIDR returns the canonical network form of a CIDR string, or "" if it
// does not parse. "" never matches a stored key, so an unparseable subnet
// renders ENABLED — bounded by the subnet_invalid block, which stops deploy.
func canonCIDR(s string) string {
	_, n, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return n.String()
}

// PathKey builds the canonical A|B lookup key for a pair given in TUNNEL
// orientation (a from Ends[0], b from Ends[1]). Returns "" if either side fails
// to parse.
func PathKey(a, b string) string {
	ca, cb := canonCIDR(a), canonCIDR(b)
	if ca == "" || cb == "" {
		return ""
	}
	return ca + "|" + cb
}

// PathsFor enumerates the selector pairs for ONE end, in that end's
// local×remote order, each flagged Enabled.
//
// Per-end rather than tunnel-canonical because both drivers enumerate
// local×remote and local/remote flip with RenderView.Self — a tunnel-canonical
// A×B order would reorder end B's indices and change the device keys it mints.
// The index here is byte-for-byte what the drivers produced before this
// existed; only Enabled is new.
//
// It is the ONE place the cross product is resolved, for the same reason
// EffectiveLANIfaces exists: hydrateDerived runs on fresh JSON binds only, and
// every read of a persisted intent — deploy included — unmarshals straight from
// intent_json without it.
func (t *TunnelIntent) PathsFor(self int) []SubnetPath {
	// Route-based negotiates a single 0.0.0.0/0 child and steers with per-subnet
	// static routes, so there are no per-pair selectors to switch off. Resolve
	// the mode here once rather than at each call site.
	if t.Mode != ModePolicyBased {
		return []SubnetPath{{Index: 0, Local: "0.0.0.0/0", Remote: "0.0.0.0/0", Enabled: true}}
	}

	local, remote := &t.Ends[self], &t.Ends[1-self]
	// Deliberately zero paths, NOT a single 0/0 path, when either side is empty.
	// The drivers' own empty-list fallback is a 0/0 selector, so yielding one
	// here would show an operator who just disabled their last path something
	// WIDER than everything. Deploy is separately blocked by subnets_required.
	if len(local.ProtectedSubnets) == 0 || len(remote.ProtectedSubnets) == 0 {
		return nil
	}

	disabled := make(map[string]bool, len(t.DisabledPaths))
	for _, k := range t.DisabledPaths {
		if k = strings.TrimSpace(k); k != "" {
			disabled[k] = true
		}
	}

	out := make([]SubnetPath, 0, len(local.ProtectedSubnets)*len(remote.ProtectedSubnets))
	idx := 0
	for _, ls := range local.ProtectedSubnets {
		for _, rs := range remote.ProtectedSubnets {
			// Keys are stored in tunnel A|B orientation; paths are yielded
			// local×remote. For end B those are swapped, so swap back before
			// looking up or every end-B lookup silently misses and the two ends
			// disagree about which pairs exist.
			a, b := ls, rs
			if self == 1 {
				a, b = rs, ls
			}
			key := PathKey(a, b)
			out = append(out, SubnetPath{
				Index:   idx,
				Local:   ls,
				Remote:  rs,
				Enabled: key == "" || !disabled[key],
			})
			idx++
		}
	}
	return out
}

// EnabledPathCount reports how many pairs will actually be provisioned.
func (t *TunnelIntent) EnabledPathCount(self int) int {
	n := 0
	for _, p := range t.PathsFor(self) {
		if p.Enabled {
			n++
		}
	}
	return n
}

// RenderView projects the symmetric intent into local/remote terms for ONE end.
// Drivers consume a RenderView, never raw Ends indexing, so the same driver
// renders either side.
type RenderView struct {
	Intent *TunnelIntent
	Self   int // index into Intent.Ends for the end being rendered
}

// Local returns the end being rendered; Remote returns the peer end.
func (v RenderView) Local() *EndpointSpec  { return &v.Intent.Ends[v.Self] }
func (v RenderView) Remote() *EndpointSpec { return &v.Intent.Ends[1-v.Self] }

// ViewFor builds a RenderView for the given end index of an intent.
func ViewFor(intent *TunnelIntent, self int) RenderView {
	return RenderView{Intent: intent, Self: self}
}
