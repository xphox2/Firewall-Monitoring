// Package opnsense renders the vendor-neutral IPSec intent to OPNsense's
// swanctl-based "Connections" model via its REST API (os-ipsec, core in 26.1).
// The apply-plane is config.xml/REST — NEVER raw swanctl.conf — so every object
// is visible in the UI, captured by config.xml backup (keeping the mandatory-
// backup gate honest), and survives configd regeneration.
//
// Route-based (VTI): a Virtual Tunnel Interface with a pinned reqid, a child
// with 0/0 selectors and "Install Policies" OFF, plus a gateway, static route
// and firewall pass rule (OPNsense drops tunnel traffic without an explicit
// rule). All objects carry a `fwm-t<ID>` description for search-then-update
// idempotency and RenderRemove. Fixtures re-pinned to real OPNsense 26.1 output
// at the PR-A exit gate.
package opnsense

import (
	"encoding/json"
	"fmt"
	"strings"

	"firewall-mon/internal/ipsec"
)

const templateVersion = "opnsense-swanctl-v1"

type driver struct{}

func init() { ipsec.Register(driver{}) }

func (driver) Capabilities() ipsec.CapabilityDescriptor {
	return ipsec.CapabilityDescriptor{
		Vendor:      "opnsense",
		IKEVersions: []ipsec.IKEVersion{ipsec.IKEv2, ipsec.IKEv1},
		Modes:       []ipsec.Mode{ipsec.ModeRouteBased}, // v1 is route-based only (the driver renders a VTI)
		Encryption:  []ipsec.Encryption{ipsec.EncAES256GCM16, ipsec.EncAES128GCM16, ipsec.EncAES256CBC, ipsec.EncAES128CBC},
		Integrity:   []ipsec.Integrity{ipsec.IntegritySHA512, ipsec.IntegritySHA384, ipsec.IntegritySHA256},
		PRF:         []ipsec.PRF{ipsec.PRFSHA512, ipsec.PRFSHA384, ipsec.PRFSHA256},
		DHGroups:    []ipsec.DHGroup{ipsec.DHGroup21, ipsec.DHGroup20, ipsec.DHGroup19, ipsec.DHGroup16, ipsec.DHGroup15, ipsec.DHGroup14},
		PFS:         true,
		MSSClamp:    true,

		MaxTunnelNameLen:       0, // strongSwan connection names are unbounded
		RequiresFirewallPolicy: true,
		AutoObjects:            []string{"vti_interface", "gateway", "static_route", "firewall_rule"},
		SelectorModel:          ipsec.SelectorZero,
		IDTypes:                []ipsec.IDType{ipsec.IDTypeIP, ipsec.IDTypeFQDN, ipsec.IDTypeKeyID},
		PushTransport:          ipsec.PushREST,
		RendererName:           "opnsense_rest",
		TemplateVersion:        templateVersion,
	}
}

func (d driver) Render(v ipsec.RenderView) (ipsec.Artifact, error) {
	in := v.Intent
	local, remote := v.Local(), v.Remote()
	desc := in.Name // fwm-t<ID> — the idempotency search key

	ikeProp, err := ikeProposal(in.IKE)
	if err != nil {
		return ipsec.Artifact{}, err
	}
	espProp, err := espProposal(in.ESP)
	if err != nil {
		return ipsec.Artifact{}, err
	}
	childLife := local.ChildLifetimeSecs
	if childLife <= 0 {
		childLife = 3600
	}
	// strongSwan reads rekey_time=0 as "never rekey the IKE SA" — a security
	// footgun. Default a missing tunnel lifetime to 24h (mirrors childLife above)
	// so a preview/apply never silently disables IKE rekeying.
	ikeLife := in.IKELifetimeSecs
	if ikeLife <= 0 {
		ikeLife = 86400
	}
	localAddr := local.PeerIP
	if local.Dynamic {
		localAddr = "%any"
	}
	remoteAddr := remote.PeerIP
	if remote.Dynamic {
		remoteAddr = "%any"
	}

	// One connection with local/remote auth + a child. Route-based ⇒ 0/0
	// selectors, policies_installed=false, pinned reqid.
	conn := jsonBody(map[string]any{
		"connection": map[string]any{
			"enabled":      boolStr(in.Enabled),
			"description":  desc,
			"version":      ikeVersion(in.IKEVersion),
			"proposals":    ikeProp,
			"local_addrs":  localAddr,
			"remote_addrs": remoteAddr,
			"dpd_delay":    itoa(in.DPD.DelaySecs),
			"rekey_time":   itoa(ikeLife),
			"unique":       "replace",
		},
	})
	localAuth := jsonBody(map[string]any{
		"local": map[string]any{"description": desc, "connection": tokName(nameConn), "round": "0", "auth": "psk", "id": local.LocalID.Value},
	})
	remoteAuth := jsonBody(map[string]any{
		"remote": map[string]any{"description": desc, "connection": tokName(nameConn), "round": "0", "auth": "psk", "id": remote.LocalID.Value},
	})
	child := jsonBody(map[string]any{
		"child": map[string]any{
			"description":   desc,
			"connection":    tokName(nameConn),
			"mode":          "tunnel",
			"policies":      "0", // route-based: Install Policies OFF
			"reqid":         itoa(local.Reqid),
			"esp_proposals": espProp,
			"local_ts":      "0.0.0.0/0",
			"remote_ts":     "0.0.0.0/0",
			"rekey_time":    itoa(childLife),
			"start_action":  startAction(remote.Dynamic),
			"close_action":  "start",
			"dpd_action":    "restart",
		},
	})
	// Marshal the PSK step with the REAL key so json.Marshal escapes it correctly
	// (a post-marshal string replace would corrupt a key containing JSON-special
	// chars). This body is a step (never the preview), so the redacted preview
	// still never sees the PSK.
	pskStep := jsonBody(map[string]any{
		"preSharedKey": map[string]any{"description": desc, "type": "PSK", "ident": local.LocalID.Value, "keyid": remote.LocalID.Value, "Key": in.PSK},
	})
	vti := jsonBody(map[string]any{
		"vti": map[string]any{"description": desc, "reqid": itoa(local.Reqid), "local": local.InnerIP, "remote": remote.InnerIP},
	})
	gw := jsonBody(map[string]any{
		"gateway": map[string]any{"description": desc, "interface": "vti_" + desc, "gateway": remote.InnerIP},
	})

	// Every create step CaptureAs a token so the collector binds the device-
	// assigned UUID; child bodies reference <uuid:conn>; RenderRemove deletes by
	// the same tokens. Children are captured + explicitly deleted (cascade
	// insurance — we do not trust delConnection to cascade local/remote/child).
	steps := []ipsec.ApplyStep{
		apiCap("Create IPsec connection (IKE)", epConnAdd, conn, nameConn),
		apiCap("Add local auth (PSK identity)", epLocalAdd, localAuth, nameLocal),
		apiCap("Add remote auth (PSK identity)", epRemoteAdd, remoteAuth, nameRemote),
		apiCap("Add child SA (0/0 selectors, policies off, pinned reqid)", epChildAdd, child, nameChild),
		apiCap("Store pre-shared key", epPSKAdd, pskStep, namePSK),
		apiCap("Create VTI (Virtual Tunnel Interface)", epVTIAdd, vti, nameVTI),
		apiCap("Create gateway on the VTI", epGWAdd, gw, nameGW),
	}
	// static routes + a firewall pass rule per remote subnet (traffic is dropped
	// without the rule — the classic OPNsense omission we auto-include).
	for i, s := range remote.ProtectedSubnets {
		route := jsonBody(map[string]any{"route": map[string]any{"description": desc, "network": s, "gateway": desc}})
		rule := jsonBody(map[string]any{"rule": map[string]any{"description": desc, "action": "pass", "interface": "vti_" + desc, "source_net": "any", "destination_net": s}})
		steps = append(steps,
			apiCap("Static route "+s+" via VTI", epRouteAdd, route, nameRoute(i)),
			apiCap("Firewall pass rule for "+s, epRuleAdd, rule, nameRule(i)),
		)
	}
	// Conditional peer /32: when a routed (remote) subnet contains the peer's own
	// WAN endpoint, pin a host route to it via the physical WAN so IKE/ESP to the
	// peer isn't swallowed by the tunnel (self-lockout). OPNsense routes reference
	// a gateway by NAME, so first create a WAN gateway object bound to the
	// operator-supplied next-hop IP (tagged desc-peer to disambiguate from the VTI
	// gateway), then the /32 route referencing it.
	if peerRouteNeeded(local, remote) {
		peerDesc := desc + "-peer"
		pgw := jsonBody(map[string]any{"gateway": map[string]any{"description": peerDesc, "interface": local.EgressIface, "gateway": local.Gateway}})
		proute := jsonBody(map[string]any{"route": map[string]any{"description": peerDesc, "network": remote.PeerIP + "/32", "gateway": peerDesc}})
		steps = append(steps,
			apiCap("Peer WAN gateway (self-lockout /32 next-hop)", epGWAdd, pgw, nameGWPeer),
			apiCap("Peer /32 host route via WAN (self-lockout guard)", epRouteAdd, proute, nameRoutePeer),
		)
	}
	// Per-subsystem activation. OPNsense stages object CRUD to config.xml and only
	// activates on a per-subsystem apply/reconfigure. NOTE: these endpoints are
	// UNVERIFIED against a live 26.1 box (the C2a render only had ipsec reconfigure)
	// — confirm/adjust at the live exit gate; the saga machinery does not depend on
	// which specific applies exist.
	steps = append(steps, applySteps()...)

	return ipsec.Artifact{
		Vendor:          "opnsense",
		Kind:            ipsec.ArtifactApply,
		Steps:           steps,
		Checksum:        ipsec.ChecksumSteps(steps),
		TemplateVersion: templateVersion,
		PreviewText:     swanctlPreview(desc, ikeProp, espProp, localAddr, remoteAddr, local, remote),
		AutoObjects:     []string{"VTI vti_" + desc, "gateway", "static route(s)", "firewall pass rule(s)"},
	}, nil
}

func (d driver) RenderRemove(v ipsec.RenderView) (ipsec.Artifact, error) {
	local, remote := v.Local(), v.Remote()
	desc := v.Intent.Name
	// Delete by CAPTURED UUID (POST del<X>/<uuid:NAME>), reverse dependency order,
	// reversing exactly the tokens Render captured. The collector substitutes each
	// <uuid:NAME> from the server-stored map; a token with no stored UUID (object
	// never created) is skipped. Idempotent: OPNsense returns 200 {"result":"not
	// found"} for an already-gone UUID.
	var steps []ipsec.ApplyStep
	// Peer /32 objects first (route before its gateway).
	if peerRouteNeeded(local, remote) {
		steps = append(steps,
			delByUUID("Delete peer /32 route", epRouteDel, nameRoutePeer),
			delByUUID("Delete peer WAN gateway", epGWDel, nameGWPeer),
		)
	}
	// Rules + routes (reverse subnet order) before the gateway/VTI they reference.
	for i := len(remote.ProtectedSubnets) - 1; i >= 0; i-- {
		steps = append(steps,
			delByUUID("Delete firewall pass rule", epRuleDel, nameRule(i)),
			delByUUID("Delete static route", epRouteDel, nameRoute(i)),
		)
	}
	steps = append(steps,
		delByUUID("Delete gateway", epGWDel, nameGW),
		delByUUID("Delete VTI", epVTIDel, nameVTI),
		// Children before the connection (cascade insurance — do not assume
		// delConnection reaps local/remote/child).
		delByUUID("Delete child SA", epChildDel, nameChild),
		delByUUID("Delete remote auth", epRemoteDel, nameRemote),
		delByUUID("Delete local auth", epLocalDel, nameLocal),
		delByUUID("Delete IPsec connection", epConnDel, nameConn),
		delByUUID("Delete pre-shared key", epPSKDel, namePSK),
	)
	steps = append(steps, applySteps()...)
	return ipsec.Artifact{
		Vendor: "opnsense", Kind: ipsec.ArtifactRemove, Steps: steps,
		Checksum: ipsec.ChecksumSteps(steps), TemplateVersion: templateVersion,
		PreviewText: "Delete all fwm-t objects (connection, local/remote/child, PSK, VTI, gateway, route(s), rule(s)) by captured UUID for " + desc,
	}, nil
}

func (d driver) StatusProbe(v ipsec.RenderView) []ipsec.ProbeStep {
	return []ipsec.ProbeStep{{Kind: ipsec.StepHTTPAPI, Method: "GET", Path: "/api/ipsec/sessions/searchPhase1"}}
}

// PreflightProbe emits read-only OPNsense REST GETs: firmware status (auth +
// product version) and a search over the FULL footprint the deploy creates
// (connection, PSK, VTI, gateway, protected-subnet routes, firewall rules) — the
// collector matches the `fwm-t<ID>` description against each result to detect a
// collision before any write, and re-runs these post-write to VERIFY the objects
// exist. All GETs; nothing is mutated.
//
// The conditional peer objects (`fwm-t<ID>-peer`) are deliberately verify-EXEMPT:
// opnsenseRowsMatch is exact-equality on the tunnel description, so `-peer` rows
// won't match, and they're the auxiliary self-lockout guard, not the tunnel
// footprint — a create failure of a peer object is still caught by writeOK at
// apply time.
func (d driver) PreflightProbe(v ipsec.RenderView) []ipsec.PreflightStep {
	return []ipsec.PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/core/firmware/status"},
		{Check: "connection", Method: "GET", Path: epConnSearch, ExpectAbsent: true},
		{Check: "psk", Method: "GET", Path: epPSKSearch, ExpectAbsent: true},
		{Check: "vti", Method: "GET", Path: epVTISearch, ExpectAbsent: true},
		{Check: "gateway", Method: "GET", Path: epGWSearch, ExpectAbsent: true},
		{Check: "route", Method: "GET", Path: epRouteSearch, ExpectAbsent: true},
		{Check: "rule", Method: "GET", Path: epRuleSearch, ExpectAbsent: true},
	}
}

func (d driver) ParseStatus(raw string) (ipsec.TunnelStatus, error) {
	low := strings.ToLower(raw)
	st := ipsec.TunnelStatus{IKE: ipsec.SAUnknown, Child: ipsec.SAUnknown}
	if strings.Contains(low, "\"connected\"") || strings.Contains(low, "established") {
		st.IKE = ipsec.SAUp
	} else if strings.Contains(low, "connecting") || strings.Contains(low, "\"down\"") {
		st.IKE = ipsec.SADown
	}
	if strings.Contains(low, "installed") || strings.Contains(low, "child") && st.IKE == ipsec.SAUp {
		st.Child = ipsec.SAUp
	} else {
		st.Child = st.IKE
	}
	return st, nil
}

// ---- UUID-chaining tokens + endpoints ----
//
// Each created object binds its device-assigned UUID to a base NAME (CaptureAs);
// bodies/paths reference it as the token <uuid:NAME>. Render captures and
// RenderRemove deletes by the SAME names (a parity test pins this).
const (
	nameConn      = "conn"
	nameLocal     = "local"
	nameRemote    = "remote"
	nameChild     = "child"
	namePSK       = "psk"
	nameVTI       = "vti"
	nameGW        = "gw"
	nameGWPeer    = "gw_peer"
	nameRoutePeer = "route_peer"
)

func tokName(n string) string { return "<uuid:" + n + ">" }
func nameRoute(i int) string  { return fmt.Sprintf("route%d", i) }
func nameRule(i int) string   { return fmt.Sprintf("rule%d", i) }

// OPNsense REST MVC endpoints. add*/del* are POST; search* are GET. NOTE: the
// per-subsystem apply/reconfigure endpoints (applySteps) and some del* verbs are
// UNVERIFIED against a live 26.1 box (C2a only exercised connections/reconfigure)
// and are the live-gate iteration items — the saga machinery does not depend on
// their exact spelling.
const (
	epConnAdd   = "/api/ipsec/connections/addConnection"
	epLocalAdd  = "/api/ipsec/connections/addLocal"
	epRemoteAdd = "/api/ipsec/connections/addRemote"
	epChildAdd  = "/api/ipsec/connections/addChild"
	epPSKAdd    = "/api/ipsec/pre_shared_keys/addItem"
	epVTIAdd    = "/api/interfaces/vti_settings/addItem"
	epGWAdd     = "/api/routing/settings/addGateway"
	epRouteAdd  = "/api/routes/routes/addroute"
	epRuleAdd   = "/api/firewall/filter/addRule"

	epConnDel   = "/api/ipsec/connections/delConnection"
	epLocalDel  = "/api/ipsec/connections/delLocal"
	epRemoteDel = "/api/ipsec/connections/delRemote"
	epChildDel  = "/api/ipsec/connections/delChild"
	epPSKDel    = "/api/ipsec/pre_shared_keys/delItem"
	epVTIDel    = "/api/interfaces/vti_settings/delItem"
	epGWDel     = "/api/routing/settings/delGateway"
	epRouteDel  = "/api/routes/routes/delroute"
	epRuleDel   = "/api/firewall/filter/delRule"

	epConnSearch  = "/api/ipsec/connections/searchConnection"
	epPSKSearch   = "/api/ipsec/pre_shared_keys/searchItem"
	epVTISearch   = "/api/interfaces/vti_settings/searchItem"
	epGWSearch    = "/api/routing/settings/searchGateway"
	epRouteSearch = "/api/routes/routes/searchroute"
	epRuleSearch  = "/api/firewall/filter/searchRule"
)

// applySteps activates staged config per subsystem (see the UNVERIFIED note
// above). Shared by Render and RenderRemove so both leave the box consistent.
func applySteps() []ipsec.ApplyStep {
	return []ipsec.ApplyStep{
		api("Apply IPsec configuration", "POST", "/api/ipsec/connections/reconfigure", "{}"),
		api("Apply VTI interface", "POST", "/api/interfaces/vti_settings/reconfigure", "{}"),
		api("Apply gateways", "POST", "/api/routing/settings/reconfigure", "{}"),
		api("Apply static routes", "POST", "/api/routes/routes/reconfigure", "{}"),
		api("Apply firewall rules", "POST", "/api/firewall/filter/apply", "{}"),
	}
}

// peerRouteNeeded reports whether the conditional peer /32 self-lockout guard
// renders: a Gateway is set AND a protected subnet contains the peer's WAN IP.
func peerRouteNeeded(local, remote *ipsec.EndpointSpec) bool {
	return local.Gateway != "" && ipsec.SubnetContainsIP(remote.ProtectedSubnets, remote.PeerIP)
}

// ---- helpers ----

func api(desc, method, path, body string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepHTTPAPI, Description: desc, Method: method, Path: path, Body: body}
}

// apiCap is a create step that captures its device-assigned uuid under NAME.
func apiCap(desc, path, body, captureName string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepHTTPAPI, Description: desc, Method: "POST", Path: path, Body: body, CaptureAs: captureName}
}

// delByUUID is a POST delete whose path ends in the <uuid:NAME> token the
// collector substitutes from the stored capture map (skipped if unresolved).
func delByUUID(desc, delPath, name string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepHTTPAPI, Description: desc, Method: "POST", Path: delPath + "/" + tokName(name)}
}

// jsonBody marshals a request body WITHOUT HTML-escaping, so a <uuid:NAME>
// substitution token embedded in a string value survives as the literal
// "<uuid:NAME>" (default json.Marshal would emit "<uuid:NAME>", which
// the collector's substitute() — matching literal "<uuid:…>" — would never
// resolve, aborting every apply). encoding/json still sorts map keys, so the
// output stays deterministic (stable checksum). Encode appends a trailing
// newline; trim it so the bytes match what the collector checksums.
func jsonBody(m map[string]any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return ""
	}
	return strings.TrimRight(b.String(), "\n")
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func ikeVersion(v ipsec.IKEVersion) string {
	if v == ipsec.IKEv1 {
		return "1"
	}
	return "2"
}

// startAction decides whether THIS end initiates. If the REMOTE peer is dynamic
// (behind NAT / no reachable static address) this end cannot dial it, so it must
// be a pure responder ("none"); otherwise it initiates ("start").
func startAction(remoteDynamic bool) string {
	if remoteDynamic {
		return "none"
	}
	return "start"
}

// ikeProposal / espProposal map neutral tokens to strongSwan proposal strings
// (e.g. aes256gcm16-prfsha384-ecp384, aes256gcm16-ecp384).
func ikeProposal(p ipsec.IKEProposal) (string, error) {
	enc, err := encToken(p.Enc)
	if err != nil {
		return "", err
	}
	dh, err := dhToken(p.DH)
	if err != nil {
		return "", err
	}
	if isGCM(p.Enc) {
		prf, err := prfToken(p.PRF)
		if err != nil {
			return "", err
		}
		return strings.Join([]string{enc, prf, dh}, "-"), nil
	}
	integ, err := integToken(p.Integ)
	if err != nil {
		return "", err
	}
	prf, err := prfToken(p.PRF)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{enc, integ, prf, dh}, "-"), nil
}

func espProposal(p ipsec.ESPProposal) (string, error) {
	enc, err := encToken(p.Enc)
	if err != nil {
		return "", err
	}
	parts := []string{enc}
	if !isGCM(p.Enc) {
		integ, err := integToken(p.Integ)
		if err != nil {
			return "", err
		}
		parts = append(parts, integ)
	}
	if p.PFS != ipsec.DHGroupNone {
		dh, err := dhToken(p.PFS)
		if err != nil {
			return "", err
		}
		parts = append(parts, dh)
	}
	return strings.Join(parts, "-"), nil
}

func isGCM(e ipsec.Encryption) bool {
	return e == ipsec.EncAES256GCM16 || e == ipsec.EncAES128GCM16
}

func encToken(e ipsec.Encryption) (string, error) {
	switch e {
	case ipsec.EncAES256GCM16:
		return "aes256gcm16", nil
	case ipsec.EncAES128GCM16:
		return "aes128gcm16", nil
	case ipsec.EncAES256CBC:
		return "aes256", nil
	case ipsec.EncAES128CBC:
		return "aes128", nil
	case ipsec.Enc3DES:
		return "3des", nil
	}
	return "", fmt.Errorf("opnsense: unsupported encryption %q", e)
}

func integToken(i ipsec.Integrity) (string, error) {
	switch i {
	case ipsec.IntegritySHA512:
		return "sha512", nil
	case ipsec.IntegritySHA384:
		return "sha384", nil
	case ipsec.IntegritySHA256:
		return "sha256", nil
	case ipsec.IntegritySHA1:
		return "sha1", nil
	}
	return "", fmt.Errorf("opnsense: unsupported integrity %q", i)
}

func prfToken(p ipsec.PRF) (string, error) {
	switch p {
	case ipsec.PRFSHA512:
		return "prfsha512", nil
	case ipsec.PRFSHA384:
		return "prfsha384", nil
	case ipsec.PRFSHA256:
		return "prfsha256", nil
	}
	return "", fmt.Errorf("opnsense: unsupported prf %q", p)
}

func dhToken(g ipsec.DHGroup) (string, error) {
	switch g {
	case ipsec.DHGroup21:
		return "ecp521", nil
	case ipsec.DHGroup20:
		return "ecp384", nil
	case ipsec.DHGroup19:
		return "ecp256", nil
	case ipsec.DHGroup16:
		return "modp4096", nil
	case ipsec.DHGroup15:
		return "modp3072", nil
	case ipsec.DHGroup14:
		return "modp2048", nil
	}
	return "", fmt.Errorf("opnsense: unsupported dh group %q", g)
}

func swanctlPreview(desc, ike, esp, localAddr, remoteAddr string, local, remote *ipsec.EndpointSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "connections.%s {\n", desc)
	fmt.Fprintf(&b, "  version = 2\n  proposals = %s\n", ike)
	fmt.Fprintf(&b, "  local_addrs = %s\n  remote_addrs = %s\n", localAddr, remoteAddr)
	fmt.Fprintf(&b, "  local { auth = psk; id = %s }\n", local.LocalID.Value)
	fmt.Fprintf(&b, "  remote { auth = psk; id = %s }\n", remote.LocalID.Value)
	fmt.Fprintf(&b, "  children.%s {\n", desc)
	fmt.Fprintf(&b, "    esp_proposals = %s\n    local_ts = 0.0.0.0/0\n    remote_ts = 0.0.0.0/0\n    reqid = %d\n    policies = no\n  }\n}", esp, local.Reqid)
	b.WriteString("\n# + pre-shared key (********), VTI, gateway, static route(s), firewall pass rule(s)")
	return b.String()
}
