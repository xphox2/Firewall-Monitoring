package opnsense_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors/opnsense"
)

func opnPathIntent(disabled ...string) *ipsec.TunnelIntent {
	in := &ipsec.TunnelIntent{
		ID: 7, Name: "fwm-t7", Enabled: true,
		IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
		IKE:             ipsec.IKEProposal{Enc: ipsec.EncAES256GCM16, PRF: ipsec.PRFSHA384, DH: ipsec.DHGroup20},
		ESP:             ipsec.ESPProposal{Enc: ipsec.EncAES256GCM16, PFS: ipsec.DHGroup20},
		IKELifetimeSecs: 86400,
		PSK:             "unit_test_psk_value_long_enough_000000",
		DisabledPaths:   disabled,
	}
	in.Ends[0] = ipsec.EndpointSpec{
		DeviceID: 1, Vendor: "opnsense", PeerIP: "203.0.113.9", EgressIface: "wan",
		LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "a"},
		ProtectedSubnets: []string{"192.168.50.0/24", "192.168.5.0/24"},
	}
	in.Ends[1] = ipsec.EndpointSpec{
		DeviceID: 2, Vendor: "fortigate", PeerIP: "203.0.113.10", EgressIface: "port1",
		LANIfaces:        []string{"port2"},
		LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "b"},
		ProtectedSubnets: []string{"192.168.13.0/24", "192.168.25.0/24"},
		Dynamic:          true,
	}
	return in
}

func opnTokens(art ipsec.Artifact, prefix string) []string {
	var out []string
	for _, s := range art.Steps {
		if s.CaptureAs != "" && strings.HasPrefix(s.CaptureAs, prefix) {
			out = append(out, s.CaptureAs)
		}
	}
	return out
}

// OPNsense capture tokens are positional too, and they key the UUID map that
// rollback deletes by. Disabling a path must skip its token without shifting
// any other — child_3 stays child_3 whether or not child_1 was switched off.
func TestOPN_DisablingAPathDoesNotShiftTokens(t *testing.T) {
	d, ok := ipsec.Driver("opnsense")
	if !ok {
		t.Fatal("no opnsense driver")
	}
	render := func(in *ipsec.TunnelIntent) ipsec.Artifact {
		art, err := d.Render(ipsec.ViewFor(in, 0))
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		return art
	}

	full := opnTokens(render(opnPathIntent()), "child_")
	if len(full) != 4 {
		t.Fatalf("expected 4 children in the full mesh, got %v", full)
	}

	// Disable index 1 for END 0: local 50.0/24 × remote 25.0/24.
	// End 0 is tunnel A, so the key is already in A|B orientation.
	partial := opnTokens(render(opnPathIntent(ipsec.PathKey("192.168.50.0/24", "192.168.25.0/24"))), "child_")
	if len(partial) != 3 {
		t.Fatalf("expected 3 children with one path off, got %v", partial)
	}
	want := []string{"child_0", "child_2", "child_3"}
	for i := range want {
		if partial[i] != want[i] {
			t.Errorf("child token %d is %q, want %q — tokens shifted, so the captured UUID "+
				"map would bind a token to the wrong device object", i, partial[i], want[i])
		}
	}
}

// Unlike FortiGate, OPNsense's RenderRemove must skip the same pairs Render
// skipped: a token only means anything if Render captured a UUID for it, so
// emitting deletes for never-captured tokens breaks capture/delete parity.
func TestOPN_RemoveMatchesRenderExactly(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	in := opnPathIntent(ipsec.PathKey("192.168.50.0/24", "192.168.25.0/24"))

	art, err := d.Render(ipsec.ViewFor(in, 0))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	rem, err := d.RenderRemove(ipsec.ViewFor(in, 0))
	if err != nil {
		t.Fatalf("render remove: %v", err)
	}

	captured := map[string]bool{}
	for _, s := range art.Steps {
		if s.CaptureAs != "" {
			captured[s.CaptureAs] = true
		}
	}
	if len(captured) == 0 {
		t.Fatal("render captured no tokens")
	}

	// Every token the remove references must have been captured by the render.
	for _, s := range rem.Steps {
		if !strings.Contains(s.Path, "{{") {
			continue
		}
		start := strings.Index(s.Path, "{{")
		end := strings.Index(s.Path, "}}")
		if start < 0 || end < start {
			continue
		}
		tok := strings.TrimSpace(s.Path[start+2 : end])
		if !captured[tok] {
			t.Errorf("remove deletes token %q that render never captured — the disabled "+
				"path's objects do not exist, so this delete has nothing to resolve", tok)
		}
	}
}
