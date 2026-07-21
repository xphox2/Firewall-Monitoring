// Package opnsense renders the vendor-neutral IPSec intent to OPNsense's
// swanctl-based "Connections" model via its REST API (os-ipsec, core in 26.1).
// The apply-plane is config.xml/REST — NEVER raw swanctl.conf — so every object
// is visible in the UI, captured by config.xml backup (keeping the mandatory-
// backup gate honest), and survives configd regeneration.
//
// Route-based (VTI): an IPsec VTI (/api/ipsec/vti) with a pinned reqid, a child
// with 0/0 selectors and "Install Policies" OFF; OPNsense auto-creates the
// routed `ipsec<reqid>` interface on IPsec reconfigure, and a gateway + static
// route (referencing it) steer the protected subnets. The VTI's `skip_fw` lets
// tunnel traffic bypass the firewall (so no automation pass-rule is needed —
// filtering rests on the peer end's policies). All objects carry a `fwm-t<ID>`
// description; endpoints/fields verified against a live OPNsense 26.1 box + the
// core API docs/models.
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

		MaxTunnelNameLen:       0,    // strongSwan connection names are unbounded
		RequiresFirewallPolicy: true, // satisfied via the VTI's skip_fw (not an explicit rule)
		AutoObjects:            []string{"vti_interface (skip_fw)", "gateway", "static_route"},
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
	// reqid links the child SA ↔ VTI; OPNsense then auto-creates the routed
	// interface "ipsec<reqid>" (e.g. reqid 7 → ipsec7) — deterministic, so the
	// gateway/route reference it without any read-back. gwName is the gateway's
	// unique name (routes reference the gateway BY NAME).
	reqid := itoa(local.Reqid)
	vtiIface := "ipsec" + reqid
	gwName := desc + "-gw"
	localAuth := jsonBody(map[string]any{
		"local": map[string]any{"enabled": "1", "description": desc, "connection": tokName(nameConn), "round": "0", "auth": "psk", "id": local.LocalID.Value},
	})
	remoteAuth := jsonBody(map[string]any{
		"remote": map[string]any{"enabled": "1", "description": desc, "connection": tokName(nameConn), "round": "0", "auth": "psk", "id": remote.LocalID.Value},
	})
	child := jsonBody(map[string]any{
		"child": map[string]any{
			"enabled":       "1",
			"description":   desc,
			"connection":    tokName(nameConn),
			"mode":          "tunnel",
			"policies":      "0", // route-based: Install Policies OFF
			"reqid":         reqid,
			"esp_proposals": espProp,
			"local_ts":      "0.0.0.0/0",
			"remote_ts":     "0.0.0.0/0",
			"rekey_time":    itoa(childLife),
			"start_action":  startAction(remote.Dynamic),
			"close_action":  "start",
			"dpd_action":    "restart",
		},
	})
	// PSK: fields per the OPNsense IPsec.xml model — ident (local id), remote_ident
	// (peer id), keyType, Key. Marshaled with the REAL key (never in the preview).
	pskStep := jsonBody(map[string]any{
		"preSharedKey": map[string]any{"description": desc, "keyType": "PSK", "ident": local.LocalID.Value, "remote_ident": remote.LocalID.Value, "Key": in.PSK},
	})
	// VTI (ipsec/vti/add): reqid links to the child; local/remote are the WAN
	// endpoints (omit local when this end is dynamic — not required); tunnel_local/
	// tunnel_remote are the inner VTI addresses; skip_fw lets tunnel traffic bypass
	// the firewall so no automation rule (against an unassigned iface) is needed.
	vtiFields := map[string]any{
		"enabled": "1", "reqid": reqid, "description": desc,
		"tunnel_local": local.InnerIP, "tunnel_remote": remote.InnerIP,
		"remote": remote.PeerIP, "skip_fw": "1",
	}
	// Set the outer local endpoint whenever we know this end's address. OPNsense
	// only brings the if_ipsec device up (ifconfig … tunnel <local> <remote>) when
	// BOTH endpoints are non-empty; omitting local (even for a Dynamic end that has
	// a known PeerIP) yields a configured-but-dead interface. Dynamic = "the peer
	// can't dial me", not "I don't know my own address".
	if local.PeerIP != "" {
		vtiFields["local"] = local.PeerIP
	}
	vti := jsonBody(map[string]any{"vti": vtiFields})
	// Gateway on the auto-created ipsec<reqid> interface; far-end = remote inner IP.
	gw := jsonBody(map[string]any{
		"gateway": map[string]any{"name": gwName, "descr": desc, "interface": vtiIface, "ipprotocol": "inet", "gateway": remote.InnerIP},
	})

	// Order is load-bearing (verified against OPNsense 26.1 internals): the IPsec
	// objects + VTI are created, then IPsec is RECONFIGURED — that is what
	// registers the auto-created `ipsec<reqid>` interface into the config, so the
	// gateway (validated against existing interfaces) must come AFTER it. Then the
	// gateway + routes, then the routing/routes applies. Every create step
	// CaptureAs-binds its device UUID; child bodies reference <uuid:conn>;
	// RenderRemove deletes by the same tokens (children explicitly, cascade-safe).
	steps := []ipsec.ApplyStep{
		apiCap("Create IPsec connection (IKE)", epConnAdd, conn, nameConn),
		apiCap("Add local auth (PSK identity)", epLocalAdd, localAuth, nameLocal),
		apiCap("Add remote auth (PSK identity)", epRemoteAdd, remoteAuth, nameRemote),
		apiCap("Add child SA (0/0 selectors, policies off, pinned reqid)", epChildAdd, child, nameChild),
		apiCap("Store pre-shared key", epPSKAdd, pskStep, namePSK),
		apiCap("Create VTI (Virtual Tunnel Interface)", epVTIAdd, vti, nameVTI),
		// Register ipsec<reqid> BEFORE the gateway that binds to it.
		api("Apply IPsec configuration (register ipsec"+reqid+")", "POST", epIPsecReconfigure, "{}"),
		apiCap("Create gateway on ipsec"+reqid, epGWAdd, gw, nameGW),
	}
	// A static route per remote subnet via the VTI gateway (referenced BY NAME).
	// No firewall automation rule is needed — the VTI carries skip_fw.
	for i, s := range remote.ProtectedSubnets {
		route := jsonBody(map[string]any{"route": map[string]any{"descr": desc, "network": s, "gateway": gwName}})
		steps = append(steps,
			apiCap("Static route "+s+" via "+gwName, epRouteAdd, route, nameRoute(i)),
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
		peerGwName := desc + "-peer-gw"
		pgw := jsonBody(map[string]any{"gateway": map[string]any{"name": peerGwName, "descr": peerDesc, "interface": local.EgressIface, "ipprotocol": "inet", "gateway": local.Gateway}})
		proute := jsonBody(map[string]any{"route": map[string]any{"descr": peerDesc, "network": remote.PeerIP + "/32", "gateway": peerGwName}})
		steps = append(steps,
			apiCap("Peer WAN gateway (self-lockout /32 next-hop)", epGWAdd, pgw, nameGWPeer),
			apiCap("Peer /32 host route via WAN (self-lockout guard)", epRouteAdd, proute, nameRoutePeer),
		)
	}
	// Tail: apply gateways then routes (IPsec was already reconfigured above).
	steps = append(steps, routingApplySteps()...)

	return ipsec.Artifact{
		Vendor:          "opnsense",
		Kind:            ipsec.ArtifactApply,
		Steps:           steps,
		Checksum:        ipsec.ChecksumSteps(steps),
		TemplateVersion: templateVersion,
		PreviewText:     swanctlPreview(desc, ikeProp, espProp, localAddr, remoteAddr, local, remote),
		AutoObjects:     []string{"VTI ipsec" + reqid + " (skip_fw)", "gateway", "static route(s)"},
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
	// Routes (reverse subnet order) before the gateway/VTI they reference.
	for i := len(remote.ProtectedSubnets) - 1; i >= 0; i-- {
		steps = append(steps,
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
		PreviewText: "Delete all fwm-t objects (connection, local/remote/child, PSK, VTI, gateway, route(s)) by captured UUID for " + desc,
	}, nil
}

func (d driver) StatusProbe(v ipsec.RenderView) []ipsec.ProbeStep {
	return []ipsec.ProbeStep{{Kind: ipsec.StepHTTPAPI, Method: "GET", Path: "/api/ipsec/sessions/searchPhase1"}}
}

// PreflightProbe emits read-only OPNsense REST GETs: firmware status (auth +
// product version) and a search over the footprint the deploy creates
// (connection, PSK, VTI, gateway, protected-subnet routes) — the collector
// matches the `fwm-t<ID>` description against each result to detect a collision
// before any write, and re-runs these post-write to VERIFY the objects exist.
// All GETs; nothing is mutated.
//
// The conditional peer objects (`fwm-t<ID>-peer`) are deliberately verify-EXEMPT:
// opnsenseRowsMatch is exact-equality on the tunnel description, so `-peer` rows
// won't match, and they're the auxiliary self-lockout guard, not the tunnel
// footprint — a create failure of a peer object is still caught by writeOK at
// apply time.
func (d driver) PreflightProbe(v ipsec.RenderView) []ipsec.PreflightStep {
	// Collision/verify anchors are the IPsec objects (connection/psk/vti) — these
	// are created together with the gateway/route, so a pre-existing fwm-t<ID>
	// connection is the authoritative "already deployed" signal. The gateway and
	// route searches are DELIBERATELY omitted: `routes/searchroute` loads the
	// Routes model whose gateway field triggers the configd `interface gateways
	// list` action, which caches for 20s; priming that (empty of our just-created
	// gateway) here would make the deploy's own `addroute` validation reject the
	// gateway. Not probing them keeps that cache cold so `addroute` sees a fresh,
	// correct list.
	return []ipsec.PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/core/firmware/status"},
		{Check: "connection", Method: "GET", Path: epConnSearch, ExpectAbsent: true},
		{Check: "psk", Method: "GET", Path: epPSKSearch, ExpectAbsent: true},
		{Check: "vti", Method: "GET", Path: epVTISearch, ExpectAbsent: true},
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

// OPNsense REST MVC endpoints (verified against a live 26.1 box + the core API
// docs). add*/del*/search* action names for the swanctl "connections",
// pre_shared_keys, routing, routes controllers; the VTI lives under its OWN
// controller `/api/ipsec/vti/{add,del/$uuid,search}` (NOT interfaces/vti_settings,
// which does not exist); IPsec apply is `ipsec/service/reconfigure`.
const (
	epConnAdd   = "/api/ipsec/connections/addConnection"
	epLocalAdd  = "/api/ipsec/connections/addLocal"
	epRemoteAdd = "/api/ipsec/connections/addRemote"
	epChildAdd  = "/api/ipsec/connections/addChild"
	epPSKAdd    = "/api/ipsec/pre_shared_keys/addItem"
	epVTIAdd    = "/api/ipsec/vti/add"
	epGWAdd     = "/api/routing/settings/addGateway"
	epRouteAdd  = "/api/routes/routes/addroute"

	epConnDel   = "/api/ipsec/connections/delConnection"
	epLocalDel  = "/api/ipsec/connections/delLocal"
	epRemoteDel = "/api/ipsec/connections/delRemote"
	epChildDel  = "/api/ipsec/connections/delChild"
	epPSKDel    = "/api/ipsec/pre_shared_keys/delItem"
	epVTIDel    = "/api/ipsec/vti/del"
	epGWDel     = "/api/routing/settings/delGateway"
	epRouteDel  = "/api/routes/routes/delroute"

	epConnSearch = "/api/ipsec/connections/searchConnection"
	epPSKSearch  = "/api/ipsec/pre_shared_keys/searchItem"
	epVTISearch  = "/api/ipsec/vti/search"

	epIPsecReconfigure   = "/api/ipsec/service/reconfigure"
	epRoutingReconfigure = "/api/routing/settings/reconfigure"
	epRoutesReconfigure  = "/api/routes/routes/reconfigure"
)

// routingApplySteps applies gateways then routes (Render runs the IPsec
// reconfigure inline, before the gateway, so the ipsec<reqid> interface exists).
func routingApplySteps() []ipsec.ApplyStep {
	return []ipsec.ApplyStep{
		api("Apply gateways", "POST", epRoutingReconfigure, "{}"),
		api("Apply static routes", "POST", epRoutesReconfigure, "{}"),
	}
}

// applySteps applies every subsystem (IPsec → gateways → routes). Used by
// RenderRemove, where ordering between them doesn't matter for teardown.
func applySteps() []ipsec.ApplyStep {
	return []ipsec.ApplyStep{
		api("Apply IPsec configuration", "POST", epIPsecReconfigure, "{}"),
		api("Apply gateways", "POST", epRoutingReconfigure, "{}"),
		api("Apply static routes", "POST", epRoutesReconfigure, "{}"),
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
	b.WriteString("\n# + pre-shared key (********), VTI (skip_fw), gateway, static route(s)")
	return b.String()
}
