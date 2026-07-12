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
	Enc   Encryption
	Integ Integrity
	PRF   PRF
	DH    DHGroup
}

// ESPProposal is the Phase-2 (child SA) transform set. Integ is IntegrityNone
// for AEAD. PFS is the DH group for perfect forward secrecy (DHGroupNone = off).
// Written IDENTICALLY to both ends.
type ESPProposal struct {
	Enc   Encryption
	Integ Integrity
	PFS   DHGroup
}

// IKEIdentity is a peer's explicit IKE identity (never rely on IP-default).
type IKEIdentity struct {
	Type  IDType
	Value string
}

// EndpointSpec is one end of the tunnel. The two EndpointSpecs are symmetric;
// which is "local" vs "remote" depends only on the RenderView.
type EndpointSpec struct {
	// DeviceID is the monitored device this end provisions onto (0 = unmanaged
	// peer, rendered as a downloadable parameter sheet — deferred past v1).
	DeviceID uint
	Vendor   string

	// PeerIP is this end's own tunnel endpoint address (its WAN / the address
	// the OTHER end dials). May be empty for a dynamic responder end.
	PeerIP string
	// EgressIface is the WAN/outgoing interface the phase1 binds to.
	EgressIface string
	// LANIface is the inside interface for firewall policy src/dst.
	LANIface string
	// LocalID is this end's IKE identity (mirrored as the peer's Remote ID).
	LocalID IKEIdentity
	// Dynamic marks a responder end whose peer address is not statically known
	// (behind NAT / RFC1918 WAN); the other end must be the sole initiator.
	Dynamic bool

	// ProtectedSubnets drive STATIC ROUTES + firewall rules only (NOT phase2
	// selectors, which stay 0/0 for route-based).
	ProtectedSubnets []string

	// InnerIP is this end's address on the VTI /30 (route-based).
	InnerIP string
	// Reqid / IfID / TunnelNum are per-end-local allocations the wizard owns.
	Reqid     int
	IfID      int
	TunnelNum int

	// ChildLifetimeSecs is per-end (deliberately offset — the initiator side is
	// shorter so it owns rekey, avoiding simultaneous-rekey duplicate SAs).
	ChildLifetimeSecs int
	// MSSClamp is the per-end TCP MSS clamp (0 = none/auto).
	MSSClamp int
}

// DPD is dead-peer-detection config (per-end-local, not negotiated).
type DPD struct {
	DelaySecs   int
	TimeoutSecs int // IKEv1-only for strongSwan; drivers ignore where N/A
}

// TunnelIntent is the ONE canonical description of a tunnel. It renders to both
// ends. Tunnel-level crypto/PSK/mode are written identically to both ends;
// per-end detail lives in Ends[i].
type TunnelIntent struct {
	ID      uint
	Name    string // fwm-t<ID>-safe; drivers truncate to CapabilityDescriptor.MaxTunnelNameLen
	Enabled bool

	IKEVersion IKEVersion
	Mode       Mode
	IKE        IKEProposal
	ESP        ESPProposal

	IKELifetimeSecs int
	DPD             DPD

	// PSK is the plaintext pre-shared key, supplied only at render time (stored
	// encrypted; never persisted here). Redacted from every log/echo.
	PSK string

	// VTISubnet is the /30 transit network for route-based tunnels (e.g.
	// 169.254.x.y/30); Ends[i].InnerIP are the two host addresses.
	VTISubnet string

	Ends [2]EndpointSpec
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
