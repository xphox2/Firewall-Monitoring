package fortigate_test

import (
	"encoding/json"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors/fortigate"
)

func fgPathIntent(t *testing.T, disabled ...string) *ipsec.TunnelIntent {
	t.Helper()
	in := &ipsec.TunnelIntent{
		ID: 7, Name: "fwm-t7", Enabled: true,
		IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
		IKE:             ipsec.IKEProposal{Enc: ipsec.EncAES256GCM16, PRF: ipsec.PRFSHA384, DH: ipsec.DHGroup20},
		ESP:             ipsec.ESPProposal{Enc: ipsec.EncAES256GCM16, PFS: ipsec.DHGroup20},
		IKELifetimeSecs: 86400,
		VTISubnet:       "169.254.1.0/30",
		PSK:             "unit_test_psk_value_long_enough_000000",
		DisabledPaths:   disabled,
	}
	in.Ends[0] = ipsec.EndpointSpec{
		DeviceID: 1, Vendor: "fortigate", PeerIP: "203.0.113.9", EgressIface: "port1",
		LANIfaces: []string{"port2", "port3"}, InnerIP: "169.254.1.1", Reqid: 7,
		LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "a"},
		ProtectedSubnets: []string{"192.168.13.0/24", "192.168.25.0/24"},
	}
	in.Ends[1] = ipsec.EndpointSpec{
		DeviceID: 2, Vendor: "fortigate", PeerIP: "203.0.113.10", EgressIface: "port1",
		LANIfaces: []string{"port2"}, InnerIP: "169.254.1.2", Reqid: 7,
		LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "b"},
		ProtectedSubnets: []string{"192.168.50.0/24", "192.168.5.0/24"},
	}
	return in
}

func fgRender(t *testing.T, in *ipsec.TunnelIntent, self int) ipsec.Artifact {
	t.Helper()
	d, ok := ipsec.Driver("fortigate")
	if !ok {
		t.Fatal("no fortigate driver")
	}
	art, err := d.Render(ipsec.ViewFor(in, self))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return art
}

func fgRemove(t *testing.T, in *ipsec.TunnelIntent, self int) ipsec.Artifact {
	t.Helper()
	d, _ := ipsec.Driver("fortigate")
	art, err := d.RenderRemove(ipsec.ViewFor(in, self))
	if err != nil {
		t.Fatalf("render remove: %v", err)
	}
	return art
}

// phase2Keys pulls the phase2 mkeys out of an artifact. A CREATE is a POST to
// .../phase2-interface with the name in the BODY; a DELETE carries the mkey as
// the last path segment. Reading only the path would silently yield
// "phase2-interface" for every create and compare equal to itself.
func phase2Keys(art ipsec.Artifact) []string {
	var out []string
	for _, s := range art.Steps {
		if !strings.Contains(s.Path, "phase2-interface") {
			continue
		}
		if strings.HasSuffix(s.Path, "phase2-interface") {
			var body struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal([]byte(s.Body), &body); err == nil && body.Name != "" {
				out = append(out, body.Name)
			}
			continue
		}
		out = append(out, s.Path[strings.LastIndex(s.Path, "/")+1:])
	}
	return out
}

// Disabling a path must remove exactly that phase2 and leave every other mkey
// where it was. The suffix comes from the pair's index in the full cross
// product; if it compacted, fwm-t7-3 would become fwm-t7-2 and a live device
// object would silently start describing a different selector pair.
func TestFG_DisablingAPathLeavesTheOtherMkeysAlone(t *testing.T) {
	full := phase2Keys(fgRender(t, fgPathIntent(t), 0))
	if len(full) != 4 {
		t.Fatalf("expected 4 phase2s in the full mesh, got %v", full)
	}

	// index 1 == 13.0/24 ↔ 5.0/24, the MIDDLE of the enumeration
	partial := phase2Keys(fgRender(t, fgPathIntent(t, ipsec.PathKey("192.168.13.0/24", "192.168.5.0/24")), 0))
	if len(partial) != 3 {
		t.Fatalf("expected 3 phase2s with one path off, got %v", partial)
	}

	want := []string{full[0], full[2], full[3]} // fwm-t7, fwm-t7-2, fwm-t7-3
	for i := range want {
		if partial[i] != want[i] {
			t.Errorf("phase2 %d is %q, want %q — the surviving keys shifted, so a device "+
				"object now names a different selector pair", i, partial[i], want[i])
		}
	}
	for _, k := range partial {
		if k == full[1] {
			t.Errorf("%q was disabled but is still rendered", k)
		}
	}
}

// RenderRemove deliberately sweeps the WHOLE slot space, disabled paths
// included — unlike Render, which skips them.
//
// RunApply's remove loop is continue-on-error, so a rollback can fail on one
// phase2 DELETE and still delete phase1, leaving an orphan phase2 with no
// phase1. ForceResetIPSecDeploy then returns the tunnel to draft; if the
// operator disables that path and redeploys, preflight probes only ENABLED
// mkeys, misses the orphan, and recreates phase1 — whereupon the orphan binds
// to it by phase1name and the disabled path is back on the wire. Keeping every
// slot in the remove snapshot is what lets the next rollback reap it.
func TestFG_RemoveSweepsDisabledPathsToo(t *testing.T) {
	disabled := ipsec.PathKey("192.168.13.0/24", "192.168.5.0/24")
	in := fgPathIntent(t, disabled)

	rendered := phase2Keys(fgRender(t, in, 0))
	removed := phase2Keys(fgRemove(t, in, 0))

	if len(rendered) != 3 {
		t.Fatalf("expected 3 rendered phase2s, got %v", rendered)
	}
	if len(removed) != 4 {
		t.Fatalf("remove must sweep all 4 slots, got %v — an orphaned phase2 from a "+
			"partially failed rollback would become permanently invisible", removed)
	}

	orphanCandidate := "fwm-t7-1"
	found := false
	for _, k := range removed {
		if k == orphanCandidate {
			found = true
		}
	}
	if !found {
		t.Errorf("the disabled path's mkey %q is absent from the remove steps %v — "+
			"nothing would ever delete it", orphanCandidate, removed)
	}
	for _, k := range rendered {
		if k == orphanCandidate {
			t.Errorf("%q is disabled and must NOT be created", k)
		}
	}
}

// The preflight collision check probes only what the deploy will create.
// Probing a disabled mkey would demand it be ABSENT, and the collector re-runs
// these post-write expecting PRESENT.
func TestFG_PreflightProbesOnlyEnabledPhase2s(t *testing.T) {
	in := fgPathIntent(t, ipsec.PathKey("192.168.13.0/24", "192.168.5.0/24"))
	d, _ := ipsec.Driver("fortigate")

	n := 0
	for _, s := range d.PreflightProbe(ipsec.ViewFor(in, 0)) {
		if s.Check == "phase2" {
			n++
			if strings.HasSuffix(s.Path, "fwm-t7-1") {
				t.Error("preflight probes the disabled mkey; the collector's post-write " +
					"verify re-runs collision steps expecting PRESENT, so this would fail the apply")
			}
		}
	}
	if n != 3 {
		t.Errorf("expected 3 phase2 probes, got %d", n)
	}
}
