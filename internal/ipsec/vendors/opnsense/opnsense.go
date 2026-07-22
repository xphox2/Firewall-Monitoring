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
	"net"
	"strings"

	"firewall-mon/internal/ipsec"
)

const templateVersion = "opnsense-swanctl-v2"

type driver struct{}

func init() { ipsec.Register(driver{}) }

func (driver) Capabilities() ipsec.CapabilityDescriptor {
	return ipsec.CapabilityDescriptor{
		Vendor:      "opnsense",
		IKEVersions: []ipsec.IKEVersion{ipsec.IKEv2, ipsec.IKEv1},
		// Policy-based ONLY: OPNsense 26.1 has no REST API to assign the VTI as a
		// firewall interface, which route-based gateways require — so the automatable
		// path is policy-based (kernel policies from specific selectors). Mode
		// negotiation (Intersect) then forces any OPNsense tunnel to policy-based.
		Modes:      []ipsec.Mode{ipsec.ModePolicyBased},
		Encryption: []ipsec.Encryption{ipsec.EncAES256GCM16, ipsec.EncAES128GCM16, ipsec.EncAES256CBC, ipsec.EncAES128CBC},
		Integrity:  []ipsec.Integrity{ipsec.IntegritySHA512, ipsec.IntegritySHA384, ipsec.IntegritySHA256},
		PRF:        []ipsec.PRF{ipsec.PRFSHA512, ipsec.PRFSHA384, ipsec.PRFSHA256},
		DHGroups:   []ipsec.DHGroup{ipsec.DHGroup21, ipsec.DHGroup20, ipsec.DHGroup19, ipsec.DHGroup16, ipsec.DHGroup15, ipsec.DHGroup14},
		PFS:        true,
		MSSClamp:   true,

		MaxTunnelNameLen: 0, // strongSwan connection names are unbounded
		// Policy-based installs kernel policies from the child selectors; decrypted
		// traffic surfaces on the IPsec (enc0) interface and is NOT auto-passed — an
		// explicit firewall rule may be needed for data-plane traffic (not for the
		// tunnel to come up). No VTI/gateway/route objects are created.
		RequiresFirewallPolicy: true,
		AutoObjects:            []string{"kernel IPsec policies (SPD)"},
		SelectorModel:          ipsec.SelectorEndpoint,
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
	// A dynamic end has no reachable static address. OPNsense's IKEAddressField
	// validates each entry as an IP/subnet/hostname and REJECTS the literal
	// "%any"; the field is not Required, so leave it EMPTY — strongSwan treats an
	// empty local/remote_addrs as %any.
	localAddr := local.PeerIP
	if local.Dynamic {
		localAddr = ""
	}
	remoteAddr := remote.PeerIP
	if remote.Dynamic {
		remoteAddr = ""
	}

	// POLICY-BASED (the only mode OPNsense supports here): one connection with
	// local/remote PSK auth + a child whose SPECIFIC traffic selectors (the
	// protected subnets) drive kernel-policy install (policies=1). No VTI, gateway,
	// static route, or interface assignment — OPNsense 26.1 has no REST API to
	// assign the VTI interface a route-based gateway would require, so policy-based
	// is the fully-automatable path.
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
		"local": map[string]any{"enabled": "1", "description": desc, "connection": tokName(nameConn), "round": "0", "auth": "psk", "id": local.LocalID.Value},
	})
	remoteAuth := jsonBody(map[string]any{
		"remote": map[string]any{"enabled": "1", "description": desc, "connection": tokName(nameConn), "round": "0", "auth": "psk", "id": remote.LocalID.Value},
	})
	// Traffic selectors = the protected subnets (comma-joined CIDR lists per the
	// OPNsense Swanctl.xml NetworkField AsList model). policies=1 makes strongSwan
	// install the kernel SPD, so no routed interface/gateway is needed. No reqid:
	// that only links a child to a routed VTI (route-based); a policy-based child
	// lets strongSwan allocate one dynamically.
	localTS := strings.Join(local.ProtectedSubnets, ",")
	remoteTS := strings.Join(remote.ProtectedSubnets, ",")
	child := jsonBody(map[string]any{
		"child": map[string]any{
			"enabled":       "1",
			"description":   desc,
			"connection":    tokName(nameConn),
			"mode":          "tunnel",
			"policies":      "1", // policy-based: install kernel IPsec policies
			"esp_proposals": espProp,
			"local_ts":      localTS,
			"remote_ts":     remoteTS,
			"rekey_time":    itoa(childLife),
			"start_action":  startAction(remote.Dynamic),
			"close_action":  "start",
			// dpd_action OptionField accepts only clear/trap/start (never strongSwan's
			// "restart"); "start" is OPNsense's re-initiate-on-DPD.
			"dpd_action": "start",
		},
	})
	// PSK: fields per the OPNsense IPsec.xml model — ident (local id), remote_ident
	// (peer id), keyType, Key. Marshaled with the REAL key (never in the preview).
	pskStep := jsonBody(map[string]any{
		"preSharedKey": map[string]any{"description": desc, "keyType": "PSK", "ident": local.LocalID.Value, "remote_ident": remote.LocalID.Value, "Key": in.PSK},
	})

	// Every create CaptureAs-binds its device UUID; child/local/remote reference
	// <uuid:conn>; RenderRemove deletes by the same tokens. The tail reconfigure
	// applies the swanctl config. NOTE: decrypted traffic surfaces on the IPsec
	// (enc0) interface and is NOT auto-passed — an explicit firewall pass rule may
	// be needed for DATA-PLANE traffic (not for the tunnel to come up).
	steps := []ipsec.ApplyStep{
		apiCap("Create IPsec connection (IKE)", epConnAdd, conn, nameConn),
		apiCap("Add local auth (PSK identity)", epLocalAdd, localAuth, nameLocal),
		apiCap("Add remote auth (PSK identity)", epRemoteAdd, remoteAuth, nameRemote),
		apiCap("Add child SA (policy-based: specific selectors, install policies)", epChildAdd, child, nameChild),
		apiCap("Store pre-shared key", epPSKAdd, pskStep, namePSK),
		api("Apply IPsec configuration", "POST", epIPsecReconfigure, "{}"),
	}

	return ipsec.Artifact{
		Vendor:          "opnsense",
		Kind:            ipsec.ArtifactApply,
		Steps:           steps,
		Checksum:        ipsec.ChecksumSteps(steps),
		TemplateVersion: templateVersion,
		PreviewText:     swanctlPreview(desc, ikeProp, espProp, localAddr, remoteAddr, localTS, remoteTS, local, remote),
		AutoObjects:     []string{"kernel IPsec policies (SPD)"},
	}, nil
}

func (d driver) RenderRemove(v ipsec.RenderView) (ipsec.Artifact, error) {
	desc := v.Intent.Name
	// Delete by CAPTURED UUID (POST del<X>/<uuid:NAME>), reverse dependency order.
	// The collector substitutes each <uuid:NAME> from the server-stored map.
	// Policy-based footprint = connection/local/remote/child/PSK only (no VTI,
	// gateway, or route to delete). Children before the connection (cascade
	// insurance). Idempotent: OPNsense returns 200 {"result":"not found"} for an
	// already-gone UUID, and a token with no stored UUID is skipped.
	steps := []ipsec.ApplyStep{
		delByUUID("Delete child SA", epChildDel, nameChild),
		delByUUID("Delete remote auth", epRemoteDel, nameRemote),
		delByUUID("Delete local auth", epLocalDel, nameLocal),
		delByUUID("Delete IPsec connection", epConnDel, nameConn),
		delByUUID("Delete pre-shared key", epPSKDel, namePSK),
	}
	steps = append(steps, api("Apply IPsec configuration", "POST", epIPsecReconfigure, "{}"))
	return ipsec.Artifact{
		Vendor: "opnsense", Kind: ipsec.ArtifactRemove, Steps: steps,
		Checksum: ipsec.ChecksumSteps(steps), TemplateVersion: templateVersion,
		PreviewText: "Delete fwm-t objects (connection, local/remote/child, PSK) by captured UUID for " + desc,
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
	// Policy-based collision/verify anchors are the IPsec objects that ARE created
	// (connection + psk); a pre-existing fwm-t<ID> connection is the authoritative
	// "already deployed" signal. No VTI/gateway/route is created, so no vti anchor
	// and none of the old configd-gateway-cache hazard applies.
	return []ipsec.PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/core/firmware/status"},
		{Check: "connection", Method: "GET", Path: epConnSearch, ExpectAbsent: true},
		{Check: "psk", Method: "GET", Path: epPSKSearch, ExpectAbsent: true},
	}
}

func (d driver) ParseStatus(raw string, v ipsec.RenderView) (ipsec.TunnelStatus, error) {
	st := ipsec.TunnelStatus{IKE: ipsec.SAUnknown, Child: ipsec.SAUnknown}
	// OPNsense sessions/searchPhase1 returns swanctl IKE-SA rows
	// ({"rows":[…], "rowCount":N}). swanctl rows don't carry the MVC
	// description, so name-matching isn't possible — the stable key for THIS
	// tunnel is the remote peer IP, matched tolerantly (a row may render it as
	// "1.2.3.4", "1.2.3.4[4500]", or "1.2.3.4/32" depending on version).
	var doc struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return st, fmt.Errorf("unparseable OPNsense sessions document: %w", err)
	}
	peer := v.Remote().PeerIP
	if net.ParseIP(peer) == nil {
		// A hostname/empty peer appears in session rows only in RESOLVED form —
		// we can't match it without guessing. Unknown, never a guessed down.
		st.RawError = "peer " + peer + " is not an IP literal — cannot match session rows"
		return st, nil
	}
	matched := false
	for _, row := range doc.Rows {
		if !rowHasPeer(row, peer) {
			continue
		}
		matched = true
		s := strings.ToLower(firstStringField(row, "status", "state", "ike-state", "phase1-state"))
		switch {
		case strings.Contains(s, "established"), strings.Contains(s, "connected"), s == "up":
			st.IKE = ipsec.SAUp
		case s != "" && st.IKE != ipsec.SAUp:
			st.IKE = ipsec.SADown // a reported state that isn't up
		}
	}
	if !matched {
		// We just deployed this tunnel; no session row referencing its peer is a
		// definitive not-established.
		st.IKE, st.Child = ipsec.SADown, ipsec.SADown
		st.RawError = "no IKE session to peer " + peer
		return st, nil
	}
	// Child mirrors IKE for policy-based: the phase1 search can't see child
	// SAs, and with policies=1 the established IKE SA is what installs the
	// kernel SPD. (A searchPhase2 step can refine this later — the collector
	// envelope already carries per-step bodies.)
	st.Child = st.IKE
	return st, nil
}

// rowHasPeer reports whether any string value in the (possibly nested) row
// matches the peer IP — exactly, or with a swanctl-style "[port]" or "/32"
// suffix. Exact matching (never substring) so "10.0.0.1" can't match
// "10.0.0.11".
func rowHasPeer(row map[string]any, peer string) bool {
	for _, val := range row {
		switch t := val.(type) {
		case string:
			if t == peer || strings.HasPrefix(t, peer+"[") || t == peer+"/32" {
				return true
			}
		case map[string]any:
			if rowHasPeer(t, peer) {
				return true
			}
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok && (s == peer || strings.HasPrefix(s, peer+"[") || s == peer+"/32") {
					return true
				}
				if m, ok := item.(map[string]any); ok && rowHasPeer(m, peer) {
					return true
				}
			}
		}
	}
	return false
}

// firstStringField returns the first non-empty string value among the named
// keys (OPNsense session-row field names vary across versions).
func firstStringField(row map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := row[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ---- UUID-chaining tokens + endpoints ----
//
// Each created object binds its device-assigned UUID to a base NAME (CaptureAs);
// bodies/paths reference it as the token <uuid:NAME>. Render captures and
// RenderRemove deletes by the SAME names (a parity test pins this).
const (
	nameConn   = "conn"
	nameLocal  = "local"
	nameRemote = "remote"
	nameChild  = "child"
	namePSK    = "psk"
)

func tokName(n string) string { return "<uuid:" + n + ">" }

// OPNsense REST MVC endpoints for the policy-based swanctl footprint (verified
// against a live 26.1 box): the swanctl "connections" + pre_shared_keys
// controllers, and IPsec apply via `ipsec/service/reconfigure`. Policy-based
// creates no VTI/gateway/route, so those controllers are not referenced.
const (
	epConnAdd   = "/api/ipsec/connections/addConnection"
	epLocalAdd  = "/api/ipsec/connections/addLocal"
	epRemoteAdd = "/api/ipsec/connections/addRemote"
	epChildAdd  = "/api/ipsec/connections/addChild"
	epPSKAdd    = "/api/ipsec/pre_shared_keys/addItem"

	epConnDel   = "/api/ipsec/connections/delConnection"
	epLocalDel  = "/api/ipsec/connections/delLocal"
	epRemoteDel = "/api/ipsec/connections/delRemote"
	epChildDel  = "/api/ipsec/connections/delChild"
	epPSKDel    = "/api/ipsec/pre_shared_keys/delItem"

	epConnSearch = "/api/ipsec/connections/searchConnection"
	epPSKSearch  = "/api/ipsec/pre_shared_keys/searchItem"

	epIPsecReconfigure = "/api/ipsec/service/reconfigure"
)

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
// (e.g. aes256gcm16-sha384-ecp384, aes256gcm16-ecp384).
//
// OPNsense's IPsecProposalField accepts ONLY a 3-part enc-<hash>-dh IKE token
// whose middle term is a BARE sha256/384/512 — never strongSwan's "prf" prefix,
// and never a separate integ+prf pair. For AEAD/GCM ciphers that middle hash is
// the PRF; for CBC it is the integrity algorithm.
func ikeProposal(p ipsec.IKEProposal) (string, error) {
	enc, err := encToken(p.Enc)
	if err != nil {
		return "", err
	}
	dh, err := dhToken(p.DH)
	if err != nil {
		return "", err
	}
	var hash string
	if isGCM(p.Enc) {
		hash, err = prfToken(p.PRF)
	} else {
		hash, err = integToken(p.Integ)
	}
	if err != nil {
		return "", err
	}
	return strings.Join([]string{enc, hash, dh}, "-"), nil
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

// prfToken maps a PRF to OPNsense's BARE hash token (sha256/384/512). OPNsense's
// proposal allow-list has no "prf"-prefixed variants — the middle term of an
// AEAD IKE proposal (e.g. aes256gcm16-sha384-ecp384) IS the PRF, written bare.
func prfToken(p ipsec.PRF) (string, error) {
	switch p {
	case ipsec.PRFSHA512:
		return "sha512", nil
	case ipsec.PRFSHA384:
		return "sha384", nil
	case ipsec.PRFSHA256:
		return "sha256", nil
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

func swanctlPreview(desc, ike, esp, localAddr, remoteAddr, localTS, remoteTS string, local, remote *ipsec.EndpointSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "connections.%s {\n", desc)
	fmt.Fprintf(&b, "  version = 2\n  proposals = %s\n", ike)
	fmt.Fprintf(&b, "  local_addrs = %s\n  remote_addrs = %s\n", localAddr, remoteAddr)
	fmt.Fprintf(&b, "  local { auth = psk; id = %s }\n", local.LocalID.Value)
	fmt.Fprintf(&b, "  remote { auth = psk; id = %s }\n", remote.LocalID.Value)
	fmt.Fprintf(&b, "  children.%s {\n", desc)
	fmt.Fprintf(&b, "    esp_proposals = %s\n    local_ts = %s\n    remote_ts = %s\n    policies = yes\n  }\n}", esp, localTS, remoteTS)
	b.WriteString("\n# + pre-shared key (********); policy-based (kernel SPD) — no VTI/gateway/route")
	return b.String()
}
