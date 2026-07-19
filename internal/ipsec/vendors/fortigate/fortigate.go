// Package fortigate renders the vendor-neutral IPSec intent to FortiOS CLI.
// Route-based (interface-mode) IKEv2 site-to-site: a phase1-interface auto-
// creates a tunnel interface, phase2 uses 0/0 selectors, and static routes +
// firewall policies steer traffic. All objects are named/tagged `fwm-t<ID>` so
// RenderRemove deletes exactly what Render created and nothing else.
//
// FortiGate constraints encoded in the descriptor: phase1-interface names are
// capped at 15 chars; GCM is IKEv2-only; the phase1 `proposal` appends the PRF
// for AEAD ciphers. Fixtures are re-pinned to real FortiOS 7.6.7 output at the
// PR-A exit gate.
package fortigate

import (
	"fmt"
	"strings"

	"firewall-mon/internal/ipsec"
)

const templateVersion = "fortios-v1"

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
		PushTransport:          ipsec.PushSSHCLI,
		RendererName:           "fortios_cli",
		TemplateVersion:        templateVersion,
	}
}

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
	// rendered as `set type dynamic` with no remote-gw; a static peer sets it.
	var p1b strings.Builder
	fmt.Fprintf(&p1b, "config vpn ipsec phase1-interface\n  edit \"%s\"\n", name)
	if remote.Dynamic {
		fmt.Fprintf(&p1b, "    set type dynamic\n")
	} else {
		fmt.Fprintf(&p1b, "    set type static\n    set remote-gw %s\n", remote.PeerIP)
	}
	fmt.Fprintf(&p1b, "    set interface \"%s\"\n", local.EgressIface)
	fmt.Fprintf(&p1b, "    set ike-version %s\n", ikeVer(in.IKEVersion))
	fmt.Fprintf(&p1b, "    set net-device disable\n")
	fmt.Fprintf(&p1b, "    set proposal %s\n    set dhgrp %s\n", p1, string(in.IKE.DH))
	fmt.Fprintf(&p1b, "    set peertype one\n")
	fmt.Fprintf(&p1b, "    set localid-type %s\n    set localid \"%s\"\n", idType(local.LocalID.Type), local.LocalID.Value)
	fmt.Fprintf(&p1b, "    set peerid \"%s\"\n", remote.LocalID.Value)
	if in.IKELifetimeSecs > 0 {
		fmt.Fprintf(&p1b, "    set keylife %d\n", in.IKELifetimeSecs)
	}
	if in.DPD.DelaySecs > 0 {
		fmt.Fprintf(&p1b, "    set dpd on-idle\n    set dpd-retryinterval %d\n", in.DPD.DelaySecs)
	}
	fmt.Fprintf(&p1b, "    set add-route disable\n")
	// Quote the PSK; validation guarantees no embedded quote/backslash.
	fmt.Fprintf(&p1b, "    set psksecret \"%s\"\n  next\nend", "%PSK%")
	p1Block := p1b.String()

	// phase2-interface (0/0 selectors; routing steers traffic).
	childLife := local.ChildLifetimeSecs
	if childLife <= 0 {
		childLife = 3600
	}
	var p2b strings.Builder
	fmt.Fprintf(&p2b, "config vpn ipsec phase2-interface\n  edit \"%s\"\n", name)
	fmt.Fprintf(&p2b, "    set phase1name \"%s\"\n    set proposal %s\n", name, p2)
	if in.ESP.PFS != ipsec.DHGroupNone {
		fmt.Fprintf(&p2b, "    set pfs enable\n    set dhgrp %s\n", string(in.ESP.PFS))
	} else {
		fmt.Fprintf(&p2b, "    set pfs disable\n")
	}
	fmt.Fprintf(&p2b, "    set keylifeseconds %d\n", childLife)
	fmt.Fprintf(&p2b, "    set src-subnet 0.0.0.0 0.0.0.0\n    set dst-subnet 0.0.0.0 0.0.0.0\n  next\nend")

	// tunnel-interface addressing + MSS clamp.
	var ifb strings.Builder
	fmt.Fprintf(&ifb, "config system interface\n  edit \"%s\"\n", name)
	fmt.Fprintf(&ifb, "    set ip %s 255.255.255.255\n    set remote-ip %s 255.255.255.252\n", local.InnerIP, remote.InnerIP)
	fmt.Fprintf(&ifb, "    set allowaccess ping\n")
	if local.MSSClamp > 0 {
		fmt.Fprintf(&ifb, "    set tcp-mss-sender %d\n    set tcp-mss-receiver %d\n", local.MSSClamp, local.MSSClamp)
	}
	fmt.Fprintf(&ifb, "  next\nend")

	// static + blackhole routes for the remote protected subnets.
	routes := routeBlock(name, remote.ProtectedSubnets)

	// firewall policies (LAN ⇄ tunnel).
	pol := policyBlock(name, local.LANIface)

	steps := []ipsec.ApplyStep{
		cli("phase1-interface (IKE gateway)", inject(p1Block, in.PSK)),
		cli("phase2-interface (child SA, 0/0 selectors)", p2b.String()),
		cli("tunnel interface addressing"+mssNote(local.MSSClamp), ifb.String()),
		cli("static + blackhole routes to remote subnets", routes),
		cli("firewall policies (LAN ⇄ tunnel)", pol),
	}
	preview := strings.Join([]string{redact(p1Block), p2b.String(), ifb.String(), routes, pol}, "\n\n")

	return ipsec.Artifact{
		Vendor:          "fortigate",
		Kind:            ipsec.ArtifactApply,
		Steps:           steps,
		Checksum:        ipsec.ChecksumSteps(steps),
		TemplateVersion: templateVersion,
		PreviewText:     preview,
		AutoObjects:     []string{"tunnel interface " + name, "static route(s)", "blackhole route(s) (distance 254)", "2 firewall policies"},
	}, nil
}

func (d driver) RenderRemove(v ipsec.RenderView) (ipsec.Artifact, error) {
	name := v.Intent.Name
	// Reverse dependency order: policies + routes first, then phase2, then
	// phase1 (FortiOS won't delete a referenced phase1), then the interface.
	blocks := []struct{ desc, cli string }{
		{"delete firewall policies", deletePolicies(name)},
		{"delete routes", fmt.Sprintf("config router static\n  # (delete fwm routes by comment %q)\nend", name)},
		{"delete phase2-interface", fmt.Sprintf("config vpn ipsec phase2-interface\n  delete \"%s\"\nend", name)},
		{"delete phase1-interface", fmt.Sprintf("config vpn ipsec phase1-interface\n  delete \"%s\"\nend", name)},
	}
	var steps []ipsec.ApplyStep
	var preview []string
	for _, b := range blocks {
		steps = append(steps, cli(b.desc, b.cli))
		preview = append(preview, b.cli)
	}
	return ipsec.Artifact{
		Vendor: "fortigate", Kind: ipsec.ArtifactRemove, Steps: steps,
		Checksum: ipsec.ChecksumSteps(steps), TemplateVersion: templateVersion,
		PreviewText: strings.Join(preview, "\n\n"),
	}, nil
}

func (d driver) StatusProbe(v ipsec.RenderView) []ipsec.ProbeStep {
	return []ipsec.ProbeStep{{
		Kind: ipsec.StepSSHCLI,
		CLI:  fmt.Sprintf("get vpn ipsec tunnel name %s", v.Intent.Name),
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
		{Check: "phase1", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/" + name, ExpectAbsent: true},
		{Check: "phase2", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase2-interface/" + name, ExpectAbsent: true},
		{Check: "vti", Method: "GET", Path: "/api/v2/cmdb/system/interface/" + name, ExpectAbsent: true},
	}
}

func (d driver) ParseStatus(raw string) (ipsec.TunnelStatus, error) {
	low := strings.ToLower(raw)
	st := ipsec.TunnelStatus{IKE: ipsec.SAUnknown, Child: ipsec.SAUnknown}
	// FortiGate `get vpn ipsec tunnel` reports "status: up/down" for the gateway
	// and per-selector "status=up".
	if strings.Contains(low, "status: up") || strings.Contains(low, "status=up") {
		st.IKE = ipsec.SAUp
	} else if strings.Contains(low, "status: down") || strings.Contains(low, "status=down") {
		st.IKE = ipsec.SADown
	}
	// A selector shown up implies a child SA.
	if strings.Contains(low, "sa: ") && strings.Contains(low, "up") {
		st.Child = ipsec.SAUp
	} else {
		st.Child = st.IKE
	}
	return st, nil
}

// ---- helpers ----

func cli(desc, text string) ipsec.ApplyStep {
	return ipsec.ApplyStep{Kind: ipsec.StepSSHCLI, Description: desc, CLI: text}
}

func inject(block, psk string) string { return strings.ReplaceAll(block, "%PSK%", psk) }
func redact(block string) string      { return strings.ReplaceAll(block, "%PSK%", "********") }
func mssNote(m int) string {
	if m > 0 {
		return " + MSS clamp"
	}
	return ""
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

func routeBlock(name string, subnets []string) string {
	var b strings.Builder
	b.WriteString("config router static\n")
	for _, s := range subnets {
		fmt.Fprintf(&b, "  edit 0\n    set dst %s\n    set device \"%s\"\n    set comment \"%s\"\n  next\n", cidrToFGT(s), name, name)
	}
	// blackhole (distance 254) so a tunnel-down state drops rather than leaks.
	for _, s := range subnets {
		fmt.Fprintf(&b, "  edit 0\n    set dst %s\n    set blackhole enable\n    set distance 254\n    set comment \"%s\"\n  next\n", cidrToFGT(s), name)
	}
	b.WriteString("end")
	return b.String()
}

func policyBlock(name, lan string) string {
	var b strings.Builder
	b.WriteString("config firewall policy\n")
	fmt.Fprintf(&b, "  edit 0\n    set name \"%s-out\"\n    set srcintf \"%s\"\n    set dstintf \"%s\"\n    set srcaddr all\n    set dstaddr all\n    set action accept\n    set schedule always\n    set service ALL\n  next\n", name, lan, name)
	fmt.Fprintf(&b, "  edit 0\n    set name \"%s-in\"\n    set srcintf \"%s\"\n    set dstintf \"%s\"\n    set srcaddr all\n    set dstaddr all\n    set action accept\n    set schedule always\n    set service ALL\n  next\n", name, name, lan)
	b.WriteString("end")
	return b.String()
}

func deletePolicies(name string) string {
	return fmt.Sprintf("config firewall policy\n  # (delete policies named %q-out / %q-in by name)\nend", name, name)
}

// cidrToFGT turns "10.0.0.0/24" into FortiGate "10.0.0.0 255.255.255.0".
func cidrToFGT(cidr string) string {
	ip, mask, ok := splitCIDR(cidr)
	if !ok {
		return cidr
	}
	return ip + " " + mask
}
