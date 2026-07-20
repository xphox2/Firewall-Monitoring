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
		"local": map[string]any{"description": desc, "connection": "<conn-uuid>", "round": "0", "auth": "psk", "id": local.LocalID.Value},
	})
	remoteAuth := jsonBody(map[string]any{
		"remote": map[string]any{"description": desc, "connection": "<conn-uuid>", "round": "0", "auth": "psk", "id": remote.LocalID.Value},
	})
	child := jsonBody(map[string]any{
		"child": map[string]any{
			"description":   desc,
			"connection":    "<conn-uuid>",
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

	steps := []ipsec.ApplyStep{
		api("Create IPsec connection (IKE)", "POST", "/api/ipsec/connections/addConnection", conn),
		api("Add local auth (PSK identity)", "POST", "/api/ipsec/connections/addLocal", localAuth),
		api("Add remote auth (PSK identity)", "POST", "/api/ipsec/connections/addRemote", remoteAuth),
		api("Add child SA (0/0 selectors, policies off, pinned reqid)", "POST", "/api/ipsec/connections/addChild", child),
		api("Store pre-shared key", "POST", "/api/ipsec/pre_shared_keys/addItem", pskStep),
		api("Create VTI (Virtual Tunnel Interface)", "POST", "/api/interfaces/vti_settings/addItem", vti),
		api("Create gateway on the VTI", "POST", "/api/routing/settings/addGateway", gw),
	}
	// static routes + a firewall pass rule per remote subnet (traffic is dropped
	// without the rule — the classic OPNsense omission we auto-include).
	for _, s := range remote.ProtectedSubnets {
		route := jsonBody(map[string]any{"route": map[string]any{"description": desc, "network": s, "gateway": desc}})
		rule := jsonBody(map[string]any{"rule": map[string]any{"description": desc, "action": "pass", "interface": "vti_" + desc, "source_net": "any", "destination_net": s}})
		steps = append(steps,
			api("Static route "+s+" via VTI", "POST", "/api/routes/routes/addroute", route),
			api("Firewall pass rule for "+s, "POST", "/api/firewall/filter/addRule", rule),
		)
	}
	// Conditional peer /32: when a routed (remote) subnet contains the peer's own
	// WAN endpoint, pin a host route to it via the physical WAN so IKE/ESP to the
	// peer isn't swallowed by the tunnel (self-lockout). OPNsense routes reference
	// a gateway by NAME, so first create a WAN gateway object bound to the
	// operator-supplied next-hop IP (tagged desc-peer to disambiguate from the VTI
	// gateway), then the /32 route referencing it.
	if local.Gateway != "" && ipsec.SubnetContainsIP(remote.ProtectedSubnets, remote.PeerIP) {
		peerDesc := desc + "-peer"
		pgw := jsonBody(map[string]any{"gateway": map[string]any{"description": peerDesc, "interface": local.EgressIface, "gateway": local.Gateway}})
		proute := jsonBody(map[string]any{"route": map[string]any{"description": peerDesc, "network": remote.PeerIP + "/32", "gateway": peerDesc}})
		steps = append(steps,
			api("Peer WAN gateway (self-lockout /32 next-hop)", "POST", "/api/routing/settings/addGateway", pgw),
			api("Peer /32 host route via WAN (self-lockout guard)", "POST", "/api/routes/routes/addroute", proute),
		)
	}
	steps = append(steps, api("Apply IPsec configuration", "POST", "/api/ipsec/connections/reconfigure", "{}"))

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
	// Search-by-description then delete, reverse order. UUIDs are resolved live
	// by the collector; here we express intent by the fwm-t<ID> description.
	var steps []ipsec.ApplyStep
	// Peer /32 objects (tagged desc-peer) first, when Render would have created
	// them — a distinct description so this delete can't reap the VTI gateway.
	if local.Gateway != "" && ipsec.SubnetContainsIP(remote.ProtectedSubnets, remote.PeerIP) {
		peerDesc := desc + "-peer"
		steps = append(steps,
			api("Delete peer /32 route", "POST", "/api/routes/routes/delroute", byDesc(peerDesc)),
			api("Delete peer WAN gateway", "POST", "/api/routing/settings/delGateway", byDesc(peerDesc)),
		)
	}
	steps = append(steps,
		api("Delete firewall rule(s) by description "+desc, "POST", "/api/firewall/filter/delRule", byDesc(desc)),
		api("Delete static route(s) by description", "POST", "/api/routes/routes/delroute", byDesc(desc)),
		api("Delete gateway", "POST", "/api/routing/settings/delGateway", byDesc(desc)),
		api("Delete VTI", "POST", "/api/interfaces/vti_settings/delItem", byDesc(desc)),
		api("Delete child + connection", "POST", "/api/ipsec/connections/delConnection", byDesc(desc)),
		api("Delete pre-shared key", "POST", "/api/ipsec/pre_shared_keys/delItem", byDesc(desc)),
		api("Apply IPsec configuration", "POST", "/api/ipsec/connections/reconfigure", "{}"),
	)
	return ipsec.Artifact{
		Vendor: "opnsense", Kind: ipsec.ArtifactRemove, Steps: steps,
		Checksum: ipsec.ChecksumSteps(steps), TemplateVersion: templateVersion,
		PreviewText: "Delete all fwm-t objects (connection, child, PSK, VTI, gateway, route, rule) matching description " + desc,
	}, nil
}

func (d driver) StatusProbe(v ipsec.RenderView) []ipsec.ProbeStep {
	return []ipsec.ProbeStep{{Kind: ipsec.StepHTTPAPI, Method: "GET", Path: "/api/ipsec/sessions/searchPhase1"}}
}

// PreflightProbe emits read-only OPNsense REST GETs: firmware status (auth +
// product version) and an IPsec connection search — the collector matches the
// tunnel name/description against the results to detect a pre-existing
// connection (collision) before any write. All GETs; nothing is mutated.
func (d driver) PreflightProbe(v ipsec.RenderView) []ipsec.PreflightStep {
	return []ipsec.PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/core/firmware/status"},
		{Check: "connection", Method: "GET", Path: "/api/ipsec/connections/searchConnection", ExpectAbsent: true},
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

// ---- helpers ----

func api(desc, method, path, body string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepHTTPAPI, Description: desc, Method: method, Path: path, Body: body}
}

func jsonBody(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func byDesc(desc string) string { return jsonBody(map[string]any{"description": desc}) }

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
