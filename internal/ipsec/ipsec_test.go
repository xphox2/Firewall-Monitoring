package ipsec_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors" // register fortigate + opnsense
)

// canonicalIntent builds a Modern-profile FortiGate⇄OPNsense route-based intent
// matching the lab pair (OPNsense private WAN → sole initiator; FortiGate public
// WAN → dynamic responder).
func canonicalIntent() *ipsec.TunnelIntent {
	_, innerA, innerB := ipsec.AllocateVTI(7)
	m, _ := ipsec.PresetByName(ipsec.ProfileModern)
	return &ipsec.TunnelIntent{
		ID: 7, Name: "fwm-t7", Enabled: true,
		IKEVersion:      m.IKEVersion,
		Mode:            ipsec.ModePolicyBased, // FortiGate⇄OPNsense: OPNsense supports policy-based only
		IKE:             m.IKE,
		ESP:             m.ESP,
		IKELifetimeSecs: m.IKELifetimeSecs,
		DPD:             ipsec.DPD{DelaySecs: 30},
		PSK:             "abcDEF012345678901234567890XYZ", // 30 chars, CLI-safe
		VTISubnet:       "169.254.1.28/30",
		Ends: [2]ipsec.EndpointSpec{
			{ // A = FortiGate, public WAN, dynamic responder (peer B is behind NAT)
				DeviceID: 1, Vendor: "fortigate", PeerIP: "66.179.9.155",
				EgressIface: "port1", LANIface: "port3",
				LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "fwm-t7-a"},
				ProtectedSubnets: []string{"10.10.10.0/24"},
				InnerIP:          innerA, Reqid: 7, MSSClamp: 1350, ChildLifetimeSecs: 7200,
			},
			{ // B = OPNsense, private WAN, sole initiator
				DeviceID: 2, Vendor: "opnsense", PeerIP: "192.168.5.107", Dynamic: true,
				EgressIface: "wan", LANIface: "lan",
				LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "fwm-t7-b"},
				ProtectedSubnets: []string{"192.168.50.0/24"},
				InnerIP:          innerB, Reqid: 7, MSSClamp: 1350, ChildLifetimeSecs: 3600,
			},
		},
	}
}

func caps(t *testing.T, vendor string) ipsec.CapabilityDescriptor {
	t.Helper()
	c, err := ipsec.Capabilities(vendor)
	if err != nil {
		t.Fatalf("caps %s: %v", vendor, err)
	}
	return c
}

// TestConformance_AllDriversRenderCanonicalIntent renders the canonical intent
// through every registered driver and checks the universal invariants: no error,
// non-empty steps, checksum matches the steps, and the PSK appears in the apply
// steps but NEVER in the human preview.
func TestConformance_AllDriversRenderCanonicalIntent(t *testing.T) {
	vendors := ipsec.Vendors()
	if len(vendors) < 2 {
		t.Fatalf("expected ≥2 registered drivers, got %v", vendors)
	}
	in := canonicalIntent()
	for self, want := range map[int]string{0: "fortigate", 1: "opnsense"} {
		d, ok := ipsec.Driver(want)
		if !ok {
			t.Fatalf("driver %s not registered", want)
		}
		art, err := d.Render(ipsec.ViewFor(in, self))
		if err != nil {
			t.Fatalf("%s render: %v", want, err)
		}
		if len(art.Steps) == 0 {
			t.Fatalf("%s render produced no steps", want)
		}
		if art.Checksum != ipsec.ChecksumSteps(art.Steps) {
			t.Errorf("%s checksum does not match its steps", want)
		}
		if !stepsContainPSK(art.Steps, in.PSK) {
			t.Errorf("%s apply steps must contain the PSK", want)
		}
		if strings.Contains(art.PreviewText, in.PSK) {
			t.Errorf("%s PREVIEW leaks the PSK", want)
		}
		// RenderRemove must also produce a valid, checksummed artifact.
		rm, err := d.RenderRemove(ipsec.ViewFor(in, self))
		if err != nil || len(rm.Steps) == 0 {
			t.Errorf("%s RenderRemove: steps=%d err=%v", want, len(rm.Steps), err)
		}
	}
}

func TestFortiGate_RendersModernProposal(t *testing.T) {
	in := canonicalIntent()
	d, _ := ipsec.Driver("fortigate")
	art, err := d.Render(ipsec.ViewFor(in, 0))
	if err != nil {
		t.Fatal(err)
	}
	// FortiGate now renders REST cmdb http_api steps (not SSH CLI): every step is
	// an http_api call and no step carries CLI text.
	sawPhase1POST := false
	for _, s := range art.Steps {
		if s.Kind != ipsec.StepHTTPAPI {
			t.Errorf("fortigate step %q is %q, want http_api", s.Description, s.Kind)
		}
		if s.CLI != "" {
			t.Errorf("fortigate step %q still has CLI text", s.Description)
		}
		if s.Method == "POST" && strings.Contains(s.Path, "/api/v2/cmdb/vpn.ipsec/phase1-interface") {
			sawPhase1POST = true
		}
	}
	if !sawPhase1POST {
		t.Error("fortigate render missing POST to cmdb phase1-interface")
	}
	// The neutral proposal/crypto must survive the conversion into the cmdb JSON
	// bodies (keys are json-sorted, values unquoted-spaces preserved).
	all := allBodies(art)
	for _, want := range []string{
		`"proposal":"aes256gcm-prfsha384"`, `"dhgrp":"20"`,
		// canonicalIntent is policy-based ⇒ phase2 carries the SPECIFIC selectors,
		// not 0/0 (end0 local subnet ↔ end1 remote subnet).
		`"src-subnet":"10.10.10.0 255.255.255.0"`, `"dst-subnet":"192.168.50.0 255.255.255.0"`,
		`"type":"dynamic"`, // peer B is dynamic
		`"tcp-mss-sender":1350`, `"localid":"fwm-t7-a"`, `"peerid":"fwm-t7-b"`,
		`"add-route":"disable"`, `"net-device":"disable"`, `"peertype":"one"`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("fortigate render missing %q\n--- bodies ---\n%s", want, all)
		}
	}
}

func TestOPNsense_RendersModernProposal(t *testing.T) {
	in := canonicalIntent()
	d, _ := ipsec.Driver("opnsense")
	art, err := d.Render(ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatal(err)
	}
	// OPNsense's IPsecProposalField accepts only the bare-hash 3-part IKE token
	// (aes256gcm16-sha384-ecp384) — NOT strongSwan's "prfsha384" form, which the
	// model rejects with result=failed.
	if !strings.Contains(art.PreviewText, "aes256gcm16-sha384-ecp384") {
		t.Errorf("opnsense preview missing modern IKE proposal; got:\n%s", art.PreviewText)
	}
	all := allBodies(art)
	// End B is the initiator but it dials a static peer A, so its remote_addrs is
	// A's public IP.
	if !strings.Contains(all, "66.179.9.155") {
		t.Errorf("opnsense render should dial peer A's public IP")
	}
	// This end (B) is dynamic → local_addrs must be EMPTY, never the literal
	// "%any" (IKEAddressField rejects %any). Guards the addConnection regression.
	if strings.Contains(all, "%any") || strings.Contains(art.PreviewText, "%any") {
		t.Errorf("opnsense render must not emit %%any for a dynamic end; got:\n%s", all)
	}
	if !strings.Contains(all, `"local_addrs":""`) {
		t.Errorf("opnsense dynamic end should render empty local_addrs; got:\n%s", all)
	}
	// The child dpd_action must be an OPNsense OptionField value (clear/trap/start),
	// never strongSwan's "restart" — which the model rejects with result=failed.
	if strings.Contains(all, `"dpd_action":"restart"`) {
		t.Errorf("opnsense child must not send dpd_action=restart; got:\n%s", all)
	}
	if !strings.Contains(all, `"dpd_action":"start"`) {
		t.Errorf("opnsense child should render dpd_action=start; got:\n%s", all)
	}
}

func TestResolveProfile_DemotesWhenUnsupported(t *testing.T) {
	fg := caps(t, "fortigate")
	// A vendor that can't do GCM / DH-20 forces a demotion to Compatible.
	weak := ipsec.CapabilityDescriptor{
		Vendor: "weak", IKEVersions: []ipsec.IKEVersion{ipsec.IKEv2},
		Encryption: []ipsec.Encryption{ipsec.EncAES256CBC},
		DHGroups:   []ipsec.DHGroup{ipsec.DHGroup14},
	}
	p, demoted, reason, err := ipsec.ResolveProfile(ipsec.ProfileModern, fg, weak)
	if err != nil {
		t.Fatal(err)
	}
	if !demoted || p.Name != ipsec.ProfileCompatible {
		t.Fatalf("expected demotion to Compatible, got %s demoted=%v", p.Name, demoted)
	}
	if reason == "" {
		t.Error("demotion should carry a human reason")
	}
	// Both strong → Modern stays.
	p2, demoted2, _, _ := ipsec.ResolveProfile(ipsec.ProfileModern, fg, caps(t, "opnsense"))
	if demoted2 || p2.Name != ipsec.ProfileModern {
		t.Fatalf("both support Modern; got %s demoted=%v", p2.Name, demoted2)
	}
}

func TestValidate_CatchesFootguns(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}

	// Clean canonical intent → no blocks.
	if fs := ipsec.Validate(canonicalIntent(), c); ipsec.HasBlock(fs) {
		t.Fatalf("canonical intent should have no blocks; got %+v", fs)
	}

	// Self-lockout: route a subnet that contains the peer's own endpoint. As of
	// v0.11.91 this is an acknowledgeable WARNING (safe with a pinned peer route),
	// not a hard block, so the operator can still save/deploy.
	lock := canonicalIntent()
	lock.Ends[0].ProtectedSubnets = []string{"66.179.9.0/24"} // contains A's peer IP 66.179.9.155
	lockFS := ipsec.Validate(lock, c)
	if !hasCode(lockFS, "self_lockout") {
		t.Error("expected self_lockout finding")
	}
	if sevOf(lockFS, "self_lockout") != ipsec.SeverityWarn {
		t.Errorf("self_lockout must be a warning, got %q", sevOf(lockFS, "self_lockout"))
	}
	if ipsec.HasBlock(lockFS) {
		t.Errorf("a specific self-lockout subnet must not hard-block; got %+v", lockFS)
	}

	// A default route (0/0) over the VTI is still a hard block.
	def := canonicalIntent()
	def.Ends[0].ProtectedSubnets = []string{"0.0.0.0/0"}
	defFS := ipsec.Validate(def, c)
	if !hasCode(defFS, "default_route_over_vti") || sevOf(defFS, "default_route_over_vti") != ipsec.SeverityBlock {
		t.Errorf("0.0.0.0/0 over the VTI must still block with default_route_over_vti; got %+v", defFS)
	}

	// The 0.0.0.0/1 + 128.0.0.0/1 full-tunnel split is a default-route equivalent
	// that also captures the peer — it must still hard-block, not slip through as a
	// self-lockout warning.
	split := canonicalIntent()
	split.Ends[0].ProtectedSubnets = []string{"0.0.0.0/1", "128.0.0.0/1"} // covers A's peer 66.179.9.155
	splitFS := ipsec.Validate(split, c)
	if !ipsec.HasBlock(splitFS) || !hasCode(splitFS, "default_route_over_vti") {
		t.Errorf("a /1+/1 full-tunnel split covering the peer must hard-block; got %+v", splitFS)
	}

	// Overlapping protected subnets.
	ov := canonicalIntent()
	ov.Ends[1].ProtectedSubnets = []string{"10.10.10.0/24"} // same as A
	if !hasCode(ipsec.Validate(ov, c), "subnet_overlap") {
		t.Error("expected subnet_overlap finding")
	}

	// Weak PSK.
	weakpsk := canonicalIntent()
	weakpsk.PSK = "short"
	if !hasCode(ipsec.Validate(weakpsk, c), "psk_invalid") {
		t.Error("expected psk_invalid finding")
	}

	// Both dynamic → no initiator.
	both := canonicalIntent()
	both.Ends[0].Dynamic = true
	if !hasCode(ipsec.Validate(both, c), "no_initiator") {
		t.Error("expected no_initiator finding")
	}
}

func TestGeneratePSK(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		psk, err := ipsec.GeneratePSK()
		if err != nil {
			t.Fatal(err)
		}
		if len(psk) < 40 {
			t.Fatalf("PSK too short: %d chars", len(psk))
		}
		if strings.ContainsAny(psk, "\"\\%#? \n") {
			t.Fatalf("PSK contains an escaping-unsafe char: %q", psk)
		}
		if seen[psk] {
			t.Fatal("GeneratePSK returned a duplicate")
		}
		seen[psk] = true
	}
}

func TestAllocateVTI_Deterministic(t *testing.T) {
	cidr, a, b := ipsec.AllocateVTI(7)
	cidr2, a2, b2 := ipsec.AllocateVTI(7)
	if cidr != cidr2 || a != a2 || b != b2 {
		t.Fatal("AllocateVTI must be deterministic for a tunnel ID")
	}
	if a == b {
		t.Fatal("the two inner IPs must differ")
	}
	if !strings.HasPrefix(cidr, "169.254.") {
		t.Fatalf("VTI subnet must be link-local, got %s", cidr)
	}
	// Different tunnels get different /30s.
	if c8, _, _ := ipsec.AllocateVTI(8); c8 == cidr {
		t.Fatal("distinct tunnels must get distinct /30s")
	}
}

// ---- helpers ----

func allBodies(a ipsec.Artifact) string {
	var b strings.Builder
	for _, s := range a.Steps {
		b.WriteString(s.Body)
		b.WriteByte('\n')
	}
	return b.String()
}

func stepsContainPSK(steps []ipsec.ApplyStep, psk string) bool {
	for _, s := range steps {
		if strings.Contains(s.CLI, psk) || strings.Contains(s.Body, psk) {
			return true
		}
	}
	return false
}

func hasCode(fs []ipsec.Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func sevOf(fs []ipsec.Finding, code string) ipsec.Severity {
	for _, f := range fs {
		if f.Code == code {
			return f.Severity
		}
	}
	return ""
}
