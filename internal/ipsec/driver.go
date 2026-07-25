package ipsec

import (
	"fmt"
	"sort"
	"sync"
)

// SelectorModel captures how a vendor expresses phase-2 traffic selectors for a
// route-based tunnel. Almost every vendor uses 0.0.0.0/0; pfSense VTI is the
// exception (it uses the tunnel-endpoint /30 host addresses).
type SelectorModel string

const (
	SelectorZero     SelectorModel = "zero"     // 0.0.0.0/0 both ends (FortiGate/OPNsense/Cisco/PAN)
	SelectorEndpoint SelectorModel = "endpoint" // VTI endpoint /32s (pfSense)
)

// PushTransport is how the collector applies this vendor's config.
type PushTransport string

const (
	PushSSHCLI PushTransport = "ssh_cli"
	PushREST   PushTransport = "rest"
)

// CapabilityDescriptor is the declarative, per-vendor feature/constraint sheet.
// It drives BOTH pre-flight validation AND the wizard UI (options offered =
// intersection of both ends' descriptors), so there is no vendor-specific UI or
// validation branching. Adding a vendor = adding a descriptor + templates.
type CapabilityDescriptor struct {
	Vendor      string       `json:"vendor"`
	IKEVersions []IKEVersion `json:"ike_versions"`
	Modes       []Mode       `json:"modes"`

	Encryption []Encryption `json:"encryption"`
	Integrity  []Integrity  `json:"integrity"`
	PRF        []PRF        `json:"prf"`
	DHGroups   []DHGroup    `json:"dh_groups"`

	PFS      bool `json:"pfs"`
	MSSClamp bool `json:"mss_clamp"`

	// MaxTunnelNameLen bounds the generated object name (FortiGate phase1-iface
	// is 15 chars). 0 = unbounded.
	MaxTunnelNameLen int `json:"max_tunnel_name_len"`
	// RequiresFirewallPolicy: the driver must emit a pass rule/policy or traffic
	// is dropped (OPNsense Connections, Palo Alto).
	RequiresFirewallPolicy bool `json:"requires_firewall_policy"`
	// AutoObjects the driver injects that the operator would otherwise forget
	// (e.g. "blackhole_route", "firewall_policy") — surfaced in preview.
	AutoObjects []string `json:"auto_objects"`

	SelectorModel   SelectorModel `json:"selector_model"`
	IDTypes         []IDType      `json:"id_types"`
	PushTransport   PushTransport `json:"push_transport"`
	RendererName    string        `json:"renderer_name"`
	TemplateVersion string        `json:"template_version"`
}

func (d CapabilityDescriptor) supportsEnc(e Encryption) bool { return containsEnc(d.Encryption, e) }
func (d CapabilityDescriptor) supportsDH(g DHGroup) bool     { return containsDH(d.DHGroups, g) }
func (d CapabilityDescriptor) supportsMode(m Mode) bool      { return containsMode(d.Modes, m) }
func (d CapabilityDescriptor) supportsIKE(v IKEVersion) bool { return containsIKE(d.IKEVersions, v) }
func (d CapabilityDescriptor) supportsInteg(i Integrity) bool {
	return i == IntegrityNone || containsInteg(d.Integrity, i)
}
func (d CapabilityDescriptor) supportsPRF(p PRF) bool { return containsPRF(d.PRF, p) }

func containsInteg(s []Integrity, i Integrity) bool {
	for _, x := range s {
		if x == i {
			return true
		}
	}
	return false
}
func containsPRF(s []PRF, p PRF) bool {
	for _, x := range s {
		if x == p {
			return true
		}
	}
	return false
}

// Intersect returns the capabilities BOTH vendors support — the exact option set
// the wizard may offer for a tunnel between them (so it never presents a choice
// one end can't honor). Vendor/renderer-specific scalar fields are left zero;
// only the negotiable sets + booleans are meaningful on the result.
func Intersect(a, b CapabilityDescriptor) CapabilityDescriptor {
	out := CapabilityDescriptor{
		Vendor:           a.Vendor + "+" + b.Vendor,
		PFS:              a.PFS && b.PFS,
		MSSClamp:         a.MSSClamp && b.MSSClamp,
		SelectorModel:    a.SelectorModel, // informational; render uses each end's own
		MaxTunnelNameLen: minNonZero(a.MaxTunnelNameLen, b.MaxTunnelNameLen),
	}
	for _, v := range a.IKEVersions {
		if containsIKE(b.IKEVersions, v) {
			out.IKEVersions = append(out.IKEVersions, v)
		}
	}
	for _, m := range a.Modes {
		if containsMode(b.Modes, m) {
			out.Modes = append(out.Modes, m)
		}
	}
	for _, e := range a.Encryption {
		if containsEnc(b.Encryption, e) {
			out.Encryption = append(out.Encryption, e)
		}
	}
	for _, in := range a.Integrity {
		if containsInteg(b.Integrity, in) {
			out.Integrity = append(out.Integrity, in)
		}
	}
	for _, p := range a.PRF {
		if containsPRF(b.PRF, p) {
			out.PRF = append(out.PRF, p)
		}
	}
	for _, g := range a.DHGroups {
		if containsDH(b.DHGroups, g) {
			out.DHGroups = append(out.DHGroups, g)
		}
	}
	for _, t := range a.IDTypes {
		if containsIDType(b.IDTypes, t) {
			out.IDTypes = append(out.IDTypes, t)
		}
	}
	return out
}

func minNonZero(a, b int) int {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

func containsIDType(s []IDType, t IDType) bool {
	for _, x := range s {
		if x == t {
			return true
		}
	}
	return false
}

// ApplyStepKind distinguishes a CLI text block from a structured HTTP API call —
// so a FortiGate CLI script and an OPNsense REST batch are the SAME abstraction.
type ApplyStepKind string

const (
	StepSSHCLI  ApplyStepKind = "ssh_cli"
	StepHTTPAPI ApplyStepKind = "http_api"
)

// ApplyStep is one unit of config the collector applies. Exactly one of the CLI
// or HTTP fields is populated per Kind. Description is human-facing (shown in
// preview); it must never contain the PSK.
//
// CaptureAs and the <uuid:NAME> token convention support UUID-chained vendors
// (OPNsense): a create step with CaptureAs="conn" means "after this returns 2xx,
// read the device-assigned uuid from the response and register it under token
// `conn`"; a later step referencing "<uuid:conn>" in its Path/Body has that token
// substituted with the captured value BEFORE the request is sent. Both CaptureAs
// and the substitution happen on the collector AFTER checksum-verify; neither is
// part of ChecksumSteps (Description/CaptureAs are excluded), so the operator-
// approved template is what is checksummed and only opaque device IDs fill the
// documented placeholder slots. FortiGate uses neither (no tokens, no CaptureAs)
// so its steps are byte-identical to before.
type ApplyStep struct {
	Kind        ApplyStepKind `json:"kind"`
	Description string        `json:"description"`

	// SSH_CLI
	CLI string `json:"cli,omitempty"`

	// HTTP_API
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Body   string `json:"body,omitempty"`

	// CaptureAs names the token to bind to this create's returned device uuid
	// (empty = capture nothing). NOT part of ChecksumSteps.
	CaptureAs string `json:"capture_as,omitempty"`
}

// ArtifactKind labels what an Artifact does, for ordering + rollback.
type ArtifactKind string

const (
	ArtifactApply  ArtifactKind = "apply"
	ArtifactRemove ArtifactKind = "remove"
	ArtifactStatus ArtifactKind = "status"
)

// Artifact is the rendered, ready-to-apply config for ONE end. The collector
// checksum-verifies before applying exactly these bytes — so the preview the
// operator approved is provably what runs.
type Artifact struct {
	Vendor          string       `json:"vendor"`
	Kind            ArtifactKind `json:"kind"`
	Steps           []ApplyStep  `json:"steps"`
	Checksum        string       `json:"checksum"`
	TemplateVersion string       `json:"template_version"`
	// PreviewText is a human-readable rendering (native syntax) for the wizard
	// preview pane; it has the PSK REDACTED and is not what gets applied.
	PreviewText string `json:"preview_text"`
	// AutoObjects lists the auto-injected objects (routes/policies/MSS) surfaced
	// in preview so the operator sees what changes forwarding.
	AutoObjects []string `json:"auto_objects,omitempty"`
}

// ProbeStep is a read-only command the collector runs to read SA state.
type ProbeStep struct {
	Kind   ApplyStepKind `json:"kind"`
	CLI    string        `json:"cli,omitempty"`
	Method string        `json:"method,omitempty"`
	Path   string        `json:"path,omitempty"`
}

// SAState is the normalized liveness of one SA layer.
type SAState string

const (
	SAUp      SAState = "up"
	SADown    SAState = "down"
	SAUnknown SAState = "unknown"
)

// TunnelStatus is the vendor-normalized result of a StatusProbe.
type TunnelStatus struct {
	IKE      SAState `json:"ike"`
	Child    SAState `json:"child"`
	RawError string  `json:"raw_error,omitempty"`
}

// VendorDriver renders and reads an intent for one vendor. All methods are pure
// (no I/O): Render/RenderRemove build Artifacts; StatusProbe returns the
// commands to run; ParseStatus interprets their raw output. The collector does
// the I/O.
type VendorDriver interface {
	Capabilities() CapabilityDescriptor
	Render(v RenderView) (Artifact, error)
	RenderRemove(v RenderView) (Artifact, error)
	StatusProbe(v RenderView) []ProbeStep
	// ParseStatus interprets the raw device document the collector fetched with
	// StatusProbe's steps. It MUST be tunnel-aware (v carries the intent): a
	// device hosts many tunnels, so a bare "any tunnel is up" check would
	// false-up. When the document can't be matched to THIS tunnel with
	// confidence, return SAUnknown — never a guessed up/down (C2b-2b).
	ParseStatus(raw string, v RenderView) (TunnelStatus, error)
	// PreflightProbe returns the READ-ONLY REST GETs the collector runs before a
	// deploy: an auth/version check plus reads of the exact objects a deploy
	// would create, so name/VTI/reqid collisions surface without any write. Each
	// step's Path is checked against the collision-detection contract in the
	// collector; steps are HTTP GETs only and MUST never mutate device state.
	PreflightProbe(v RenderView) []PreflightStep
	// AdvisoryProbe returns READ-ONLY GETs whose bodies feed Advisories. It is
	// DELIBERATELY separate from PreflightProbe: PreflightProbe's steps are also
	// the deploy saga's collision-precheck (an ExpectAbsent hit ABORTS the write),
	// so advisory reads live on their own method and the deploy path never sees
	// them. That makes "an advisory can never block a deploy" structural rather
	// than a property of how the collector happens to interpret a flag.
	AdvisoryProbe(v RenderView) []PreflightStep
	// Advisories turns the AdvisoryProbe bodies (keyed by the step's Check) into
	// NON-BLOCKING findings. Vendor parsing lives here, server-side, mirroring
	// StatusProbe/ParseStatus — the collector stays a dumb transport. A body that
	// is missing (older collector), empty, or unparseable yields NO advisory: this
	// must never invent a warning it cannot substantiate.
	Advisories(v RenderView, bodies map[string]string) []Advisory
}

// PreflightStep is one read-only check the collector performs before a deploy.
// Check names the semantic (auth / phase1 / phase2 / vti / connection) so the
// collector can turn the raw GET result into a structured finding; ExpectAbsent
// = a non-empty/200 result is a COLLISION (an object we intended to create
// already exists), whereas the auth/version checks expect success.
//
// ReturnBody asks the collector to echo the (size-capped) response body back in
// the report so the SERVER can parse it; it is only set on AdvisoryProbe steps.
// A collector predating the field simply omits the body and the advisory is
// skipped — additive, so no wire-version bump is needed.
type PreflightStep struct {
	Check        string `json:"check"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	ExpectAbsent bool   `json:"expect_absent"`
	ReturnBody   bool   `json:"return_body,omitempty"`
}

// Advisory is a NON-BLOCKING preflight finding: something already on the device
// that will degrade or defeat the tunnel, but that is the operator's call to
// resolve — never grounds to refuse a deploy. Distinct from a Finding (which can
// be blocking) and from a collision (which aborts the apply saga).
type Advisory struct {
	Check   string `json:"check"`             // the AdvisoryProbe step that produced it
	Title   string `json:"title"`             // one-line summary
	Detail  string `json:"detail,omitempty"`  // the concrete device state observed
	Remedy  string `json:"remedy,omitempty"`  // what the operator can do about it
	Subject string `json:"subject,omitempty"` // the object/prefix concerned
}

var (
	registryMu sync.RWMutex
	registry   = map[string]VendorDriver{}
)

// Register adds a vendor driver. Called from each vendor package's init().
func Register(d VendorDriver) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[d.Capabilities().Vendor] = d
}

// Driver returns the registered driver for a vendor, or (nil,false).
func Driver(vendor string) (VendorDriver, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := registry[vendor]
	return d, ok
}

// Vendors returns the sorted list of vendors with a provisioning driver.
func Vendors() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for v := range registry {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Capabilities returns a vendor's descriptor, or an error if unregistered.
func Capabilities(vendor string) (CapabilityDescriptor, error) {
	d, ok := Driver(vendor)
	if !ok {
		return CapabilityDescriptor{}, fmt.Errorf("no IPSec provisioning driver for vendor %q", vendor)
	}
	return d.Capabilities(), nil
}

func containsEnc(s []Encryption, e Encryption) bool {
	for _, x := range s {
		if x == e {
			return true
		}
	}
	return false
}
func containsDH(s []DHGroup, g DHGroup) bool {
	for _, x := range s {
		if x == g {
			return true
		}
	}
	return false
}
func containsMode(s []Mode, m Mode) bool {
	for _, x := range s {
		if x == m {
			return true
		}
	}
	return false
}
func containsIKE(s []IKEVersion, v IKEVersion) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
