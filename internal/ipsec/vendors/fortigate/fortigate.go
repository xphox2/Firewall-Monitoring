// Package fortigate renders the vendor-neutral IPSec intent to the FortiOS REST
// cmdb API (route-based / interface-mode IKEv2 site-to-site). A
// phase1-interface POST auto-creates the tunnel interface; phase2 uses 0/0
// selectors; static routes + firewall policies steer traffic. All objects are
// named/tagged `fwm-t<ID>` (and routes/policies use deterministic seq-num/
// policyid keys, see internal/ipsec/allocation.go) so RenderRemove deletes
// exactly what Render created and nothing else.
//
// Writes go over REST (POST to create a cmdb table object, PUT to update one by
// mkey, DELETE by mkey) — the same transport the preflight already proves
// against the live box. FortiGate constraints in the descriptor: phase1 names
// cap at 15 chars; GCM is IKEv2-only; the phase1 `proposal` appends the PRF for
// AEAD ciphers. Bodies are pinned to FortiOS 7.6.7 request shapes.
package fortigate

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"firewall-mon/internal/ipsec"
)

const templateVersion = "fortios-rest-v1"

type driver struct{}

func init() { ipsec.Register(driver{}) }

func (driver) Capabilities() ipsec.CapabilityDescriptor {
	return ipsec.CapabilityDescriptor{
		Vendor:      "fortigate",
		IKEVersions: []ipsec.IKEVersion{ipsec.IKEv2, ipsec.IKEv1},
		Modes:       []ipsec.Mode{ipsec.ModeRouteBased}, // v1 is route-based only (the driver renders VTI)
		Encryption:  []ipsec.Encryption{ipsec.EncAES256GCM16, ipsec.EncAES128GCM16, ipsec.EncAES256CBC, ipsec.EncAES128CBC},
		Integrity:   []ipsec.Integrity{ipsec.IntegritySHA512, ipsec.IntegritySHA384, ipsec.IntegritySHA256},
		PRF:         []ipsec.PRF{ipsec.PRFSHA512, ipsec.PRFSHA384, ipsec.PRFSHA256},
		DHGroups:    []ipsec.DHGroup{ipsec.DHGroup21, ipsec.DHGroup20, ipsec.DHGroup19, ipsec.DHGroup16, ipsec.DHGroup15, ipsec.DHGroup14},
		PFS:         true,
		MSSClamp:    true,

		MaxTunnelNameLen:       15,
		RequiresFirewallPolicy: true,
		AutoObjects:            []string{"tunnel_interface", "static_route", "blackhole_route", "firewall_policy"},
		SelectorModel:          ipsec.SelectorZero,
		IDTypes:                []ipsec.IDType{ipsec.IDTypeIP, ipsec.IDTypeFQDN, ipsec.IDTypeKeyID},
		PushTransport:          ipsec.PushREST,
		RendererName:           "fortios_rest",
		TemplateVersion:        templateVersion,
	}
}

const (
	cmdbPhase1 = "/api/v2/cmdb/vpn.ipsec/phase1-interface"
	cmdbPhase2 = "/api/v2/cmdb/vpn.ipsec/phase2-interface"
	cmdbIface  = "/api/v2/cmdb/system/interface"
	cmdbRoute  = "/api/v2/cmdb/router/static"
	cmdbPolicy = "/api/v2/cmdb/firewall/policy"
)

func (d driver) Render(v ipsec.RenderView) (ipsec.Artifact, error) {
	in := v.Intent
	local, remote := v.Local(), v.Remote()
	name := in.Name

	p1, err := phase1Proposal(in.IKE)
	if err != nil {
		return ipsec.Artifact{}, err
	}
	p2, err := phase2Proposal(in.ESP)
	if err != nil {
		return ipsec.Artifact{}, err
	}

	// phase1-interface. A dynamic remote peer (RFC1918/behind-NAT initiator) is
	// rendered as type=dynamic with no remote-gw; a static peer sets it. The PSK
	// rides the body via the %PSK% placeholder (injected into the real step,
	// masked in the preview) — validPSK guarantees it stays JSON-safe.
	p1body := map[string]any{
		"name":         name,
		"interface":    local.EgressIface,
		"ike-version":  ikeVer(in.IKEVersion),
		"net-device":   "disable",
		"proposal":     p1,
		"dhgrp":        string(in.IKE.DH),
		"peertype":     "one",
		"localid-type": idType(local.LocalID.Type),
		"localid":      local.LocalID.Value,
		"peerid":       remote.LocalID.Value,
		"add-route":    "disable",
		"psksecret":    "%PSK%",
	}
	if remote.Dynamic {
		p1body["type"] = "dynamic"
	} else {
		p1body["type"] = "static"
		p1body["remote-gw"] = remote.PeerIP
	}
	if in.IKELifetimeSecs > 0 {
		p1body["keylife"] = in.IKELifetimeSecs
	}
	if in.DPD.DelaySecs > 0 {
		p1body["dpd"] = "on-idle"
		p1body["dpd-retryinterval"] = in.DPD.DelaySecs
	}
	p1json := jsonBody(p1body)

	// phase2-interface (0/0 selectors; routing steers traffic).
	childLife := local.ChildLifetimeSecs
	if childLife <= 0 {
		childLife = 3600
	}
	p2body := map[string]any{
		"name":           name,
		"phase1name":     name,
		"proposal":       p2,
		"keylifeseconds": childLife,
		"src-subnet":     "0.0.0.0 0.0.0.0",
		"dst-subnet":     "0.0.0.0 0.0.0.0",
	}
	if in.ESP.PFS != ipsec.DHGroupNone {
		p2body["pfs"] = "enable"
		p2body["dhgrp"] = string(in.ESP.PFS)
	} else {
		p2body["pfs"] = "disable"
	}

	// VTI addressing + MSS clamp — the interface is auto-created by the phase1
	// POST, so PUT (update) it by name rather than POST.
	ifbody := map[string]any{
		"ip":          local.InnerIP + " 255.255.255.255",
		"remote-ip":   remote.InnerIP + " 255.255.255.252",
		"allowaccess": "ping",
	}
	if local.MSSClamp > 0 {
		ifbody["tcp-mss-sender"] = local.MSSClamp
		ifbody["tcp-mss-receiver"] = local.MSSClamp
	}

	steps := []ipsec.ApplyStep{
		fgAPI("phase1-interface (IKE gateway)", "POST", cmdbPhase1, inject(p1json, in.PSK)),
		fgAPI("phase2-interface (child SA, 0/0 selectors)", "POST", cmdbPhase2, jsonBody(p2body)),
		fgAPI("tunnel interface addressing"+mssNote(local.MSSClamp), "PUT", cmdbIface+"/"+name, jsonBody(ifbody)),
	}
	steps = append(steps, routeSteps(in.ID, name, local, remote)...)
	steps = append(steps, policySteps(in.ID, name, local.LANIface)...)

	// Preview: the phase1 body is masked (it carries the PSK); everything else is
	// shown verbatim (no secrets).
	preview := make([]string, 0, len(steps))
	for i, s := range steps {
		body := s.Body
		if i == 0 {
			body = redact(p1json)
		}
		preview = append(preview, s.Method+" "+s.Path+"\n"+body)
	}

	auto := []string{"tunnel interface " + name, "static route(s)", "blackhole route(s) (distance 254)", "2 firewall policies"}
	if peerRouteNeeded(local, remote) {
		auto = append(auto, "peer /32 host route (self-lockout guard)")
	}
	return ipsec.Artifact{
		Vendor:          "fortigate",
		Kind:            ipsec.ArtifactApply,
		Steps:           steps,
		Checksum:        ipsec.ChecksumSteps(steps),
		TemplateVersion: templateVersion,
		PreviewText:     strings.Join(preview, "\n\n"),
		AutoObjects:     auto,
	}, nil
}

func (d driver) RenderRemove(v ipsec.RenderView) (ipsec.Artifact, error) {
	in := v.Intent
	local, remote := v.Local(), v.Remote()
	name := in.Name

	// Reverse dependency order: policies → routes → phase2 → phase1. The tunnel
	// interface is owned by the phase1-interface and is reaped when phase1 is
	// deleted, so there is NO explicit interface DELETE (it would 404 after, or
	// be "in use" before). Deletes by the same deterministic mkeys Render used.
	var steps []ipsec.ApplyStep
	// policies (index 1 then 0 — reverse of create)
	steps = append(steps,
		fgDelete("delete firewall policy (tunnel→LAN)", cmdbPolicy+"/"+itoa(ipsec.FGPolicyKey(in.ID, 1))),
		fgDelete("delete firewall policy (LAN→tunnel)", cmdbPolicy+"/"+itoa(ipsec.FGPolicyKey(in.ID, 0))),
	)
	// routes (reverse creation order)
	for i := routeCount(local, remote) - 1; i >= 0; i-- {
		steps = append(steps, fgDelete("delete static route", cmdbRoute+"/"+itoa(ipsec.FGRouteKey(in.ID, i))))
	}
	steps = append(steps,
		fgDelete("delete phase2-interface", cmdbPhase2+"/"+name),
		fgDelete("delete phase1-interface (reaps the VTI)", cmdbPhase1+"/"+name),
	)

	preview := make([]string, 0, len(steps))
	for _, s := range steps {
		preview = append(preview, s.Method+" "+s.Path)
	}
	return ipsec.Artifact{
		Vendor: "fortigate", Kind: ipsec.ArtifactRemove, Steps: steps,
		Checksum: ipsec.ChecksumSteps(steps), TemplateVersion: templateVersion,
		PreviewText: strings.Join(preview, "\n\n"),
	}, nil
}

func (d driver) StatusProbe(v ipsec.RenderView) []ipsec.ProbeStep {
	return []ipsec.ProbeStep{{
		Kind:   ipsec.StepHTTPAPI,
		Method: "GET",
		Path:   "/api/v2/monitor/vpn/ipsec?vdom=root",
	}}
}

// PreflightProbe emits read-only FortiOS REST GETs: the monitor system-status
// (auth + FortiOS version) and the cmdb objects Render would create — all named
// after the tunnel — so a name/VTI collision is detected before any write. The
// cmdb GETs return 404 when the object is absent (the healthy pre-deploy state).
func (d driver) PreflightProbe(v ipsec.RenderView) []ipsec.PreflightStep {
	name := v.Intent.Name
	return []ipsec.PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
		{Check: "phase1", Method: "GET", Path: cmdbPhase1 + "/" + name, ExpectAbsent: true},
		{Check: "phase2", Method: "GET", Path: cmdbPhase2 + "/" + name, ExpectAbsent: true},
		{Check: "vti", Method: "GET", Path: cmdbIface + "/" + name, ExpectAbsent: true},
	}
}

func (d driver) ParseStatus(raw string) (ipsec.TunnelStatus, error) {
	low := strings.ToLower(raw)
	st := ipsec.TunnelStatus{IKE: ipsec.SAUnknown, Child: ipsec.SAUnknown}
	// FortiOS monitor/vpn/ipsec reports per-proxyid "status":"up"/"down" and a
	// gateway "connected"/"down".
	if strings.Contains(low, "\"connected\"") || strings.Contains(low, "\"status\":\"up\"") {
		st.IKE = ipsec.SAUp
	} else if strings.Contains(low, "\"down\"") {
		st.IKE = ipsec.SADown
	}
	if strings.Contains(low, "\"status\":\"up\"") {
		st.Child = ipsec.SAUp
	} else {
		st.Child = st.IKE
	}
	return st, nil
}

// ---- helpers ----

func fgAPI(desc, method, path, body string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepHTTPAPI, Description: desc, Method: method, Path: path, Body: body}
}

func fgDelete(desc, path string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepHTTPAPI, Description: desc, Method: "DELETE", Path: path}
}

// jsonBody marshals a cmdb request body. encoding/json sorts map keys, so the
// output is deterministic (stable checksum across renders).
func jsonBody(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func inject(block, psk string) string { return strings.ReplaceAll(block, "%PSK%", psk) }
func redact(block string) string      { return strings.ReplaceAll(block, "%PSK%", "********") }
func itoa(n int) string               { return strconv.Itoa(n) }
func mssNote(m int) string {
	if m > 0 {
		return " + MSS clamp"
	}
	return ""
}

// routeSteps builds the static-route POSTs: one per remote protected subnet via
// the VTI, a blackhole per subnet (distance 254 — drop, don't leak, when the
// tunnel is down), and the conditional peer /32 (see peerRouteNeeded). seq-nums
// are the deterministic keys RenderRemove deletes.
func routeSteps(tid uint, name string, local, remote *ipsec.EndpointSpec) []ipsec.ApplyStep {
	var steps []ipsec.ApplyStep
	idx := 0
	for _, s := range remote.ProtectedSubnets {
		steps = append(steps, fgAPI("static route "+s+" via tunnel", "POST", cmdbRoute, jsonBody(map[string]any{
			"seq-num": ipsec.FGRouteKey(tid, idx), "dst": cidrToFGT(s), "device": name, "comment": name,
		})))
		idx++
	}
	for _, s := range remote.ProtectedSubnets {
		steps = append(steps, fgAPI("blackhole route "+s+" (distance 254)", "POST", cmdbRoute, jsonBody(map[string]any{
			"seq-num": ipsec.FGRouteKey(tid, idx), "dst": cidrToFGT(s), "blackhole": "enable", "distance": 254, "comment": name,
		})))
		idx++
	}
	if peerRouteNeeded(local, remote) {
		steps = append(steps, fgAPI("peer /32 host route via WAN (self-lockout guard)", "POST", cmdbRoute, jsonBody(map[string]any{
			"seq-num": ipsec.FGRouteKey(tid, idx), "dst": remote.PeerIP + " 255.255.255.255",
			"gateway": local.Gateway, "device": local.EgressIface, "comment": name,
		})))
	}
	return steps
}

func policySteps(tid uint, name, lan string) []ipsec.ApplyStep {
	mkPolicy := func(id int, pname, srcintf, dstintf string) string {
		return jsonBody(map[string]any{
			"policyid": id, "name": pname,
			"srcintf": []map[string]string{{"name": srcintf}},
			"dstintf": []map[string]string{{"name": dstintf}},
			"srcaddr": []map[string]string{{"name": "all"}},
			"dstaddr": []map[string]string{{"name": "all"}},
			"action":  "accept", "schedule": "always",
			"service":  []map[string]string{{"name": "ALL"}},
			"comments": name,
		})
	}
	return []ipsec.ApplyStep{
		fgAPI("firewall policy (LAN → tunnel)", "POST", cmdbPolicy, mkPolicy(ipsec.FGPolicyKey(tid, 0), name+"-out", lan, name)),
		fgAPI("firewall policy (tunnel → LAN)", "POST", cmdbPolicy, mkPolicy(ipsec.FGPolicyKey(tid, 1), name+"-in", name, lan)),
	}
}

// peerRouteNeeded reports whether a peer /32 host route must be pinned: a local
// protected-subnet route would otherwise pull the peer's own WAN IP into the
// tunnel (self-lockout). Requires a Gateway to point the /32 at; without one the
// route can't be rendered (validation requires it in this case).
func peerRouteNeeded(local, remote *ipsec.EndpointSpec) bool {
	return local.Gateway != "" && ipsec.SubnetContainsIP(remote.ProtectedSubnets, remote.PeerIP)
}

func routeCount(local, remote *ipsec.EndpointSpec) int {
	n := len(remote.ProtectedSubnets) * 2
	if peerRouteNeeded(local, remote) {
		n++
	}
	return n
}

func ikeVer(v ipsec.IKEVersion) string {
	if v == ipsec.IKEv1 {
		return "1"
	}
	return "2"
}

func idType(t ipsec.IDType) string {
	switch t {
	case ipsec.IDTypeFQDN:
		return "fqdn"
	case ipsec.IDTypeKeyID:
		return "keyid"
	default:
		return "address"
	}
}

// phase1Proposal maps the neutral IKE proposal to a FortiOS phase1 proposal
// string. GCM (AEAD) appends the PRF; CBC appends the integrity hash.
func phase1Proposal(p ipsec.IKEProposal) (string, error) {
	enc, err := encToken(p.Enc)
	if err != nil {
		return "", err
	}
	if isGCM(p.Enc) {
		prf, err := prfToken(p.PRF)
		if err != nil {
			return "", err
		}
		return enc + "-" + prf, nil
	}
	integ, err := integToken(p.Integ)
	if err != nil {
		return "", err
	}
	return enc + "-" + integ, nil
}

func phase2Proposal(p ipsec.ESPProposal) (string, error) {
	enc, err := encToken(p.Enc)
	if err != nil {
		return "", err
	}
	if isGCM(p.Enc) {
		return enc, nil
	}
	integ, err := integToken(p.Integ)
	if err != nil {
		return "", err
	}
	return enc + "-" + integ, nil
}

func isGCM(e ipsec.Encryption) bool {
	return e == ipsec.EncAES256GCM16 || e == ipsec.EncAES128GCM16
}

func encToken(e ipsec.Encryption) (string, error) {
	switch e {
	case ipsec.EncAES256GCM16:
		return "aes256gcm", nil
	case ipsec.EncAES128GCM16:
		return "aes128gcm", nil
	case ipsec.EncAES256CBC:
		return "aes256", nil
	case ipsec.EncAES128CBC:
		return "aes128", nil
	case ipsec.Enc3DES:
		return "3des", nil
	}
	return "", fmt.Errorf("fortigate: unsupported encryption %q", e)
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
	return "", fmt.Errorf("fortigate: unsupported integrity %q", i)
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
	return "", fmt.Errorf("fortigate: unsupported prf %q", p)
}

// cidrToFGT turns "10.0.0.0/24" into FortiGate "10.0.0.0 255.255.255.0".
func cidrToFGT(cidr string) string {
	ip, mask, ok := splitCIDR(cidr)
	if !ok {
		return cidr
	}
	return ip + " " + mask
}
