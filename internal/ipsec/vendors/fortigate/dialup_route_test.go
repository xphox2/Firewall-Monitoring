package fortigate

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// These tests pin the fix for the live fwm-t9 failure: a FortiGate ⇄ OPNsense
// tunnel came up with every SA installed and correct selectors, decrypted inbound
// traffic, and encrypted NOTHING outbound — so it silently carried no traffic.
//
// Cause: since FortiOS 7.0.1 a route binds to a tunnel by tun_id rather than by a
// route-tree search. A dialup (type dynamic) phase1 gives each peer a sub-tunnel
// carrying its own tun_id, while the parent interface keeps a different one. The
// driver's per-subnet static routes named the PARENT, so their tun_id matched no
// sub-tunnel and FortiOS could not choose an outgoing sub-tunnel — traffic died
// at IPsec egress. Verified on FortiOS 7.6.7: with these statics removed and
// phase1 add-route enabled, the RIB switched to the sub-tunnel (`iface fwm-t9_0
// gw <peer> dist 15`) and both subnet pairs passed traffic bidirectionally.
//
// The two halves are a matched pair: add-route's injected routes sit at distance
// 15 and LOSE to a distance-10 static, so leaving the statics in place does not
// merely duplicate them — it shadows them and reinstates the bug.

func dialupIntent(dynamic bool) *ipsec.TunnelIntent {
	in := t9Intent()
	in.Ends[1].Dynamic = dynamic
	if !dynamic {
		in.Ends[1].PeerIP = "198.51.100.9" // a routable peer for the static case
	}
	return in
}

func renderBodies(t *testing.T, in *ipsec.TunnelIntent) (ipsec.Artifact, string) {
	t.Helper()
	art, err := fgDriver(t).Render(ipsec.ViewFor(in, 0))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var b strings.Builder
	for _, s := range art.Steps {
		b.WriteString(s.Method + " " + s.Path + "\n" + s.Body + "\n")
	}
	return art, b.String()
}

// A dialup peer must get add-route=enable and NO parent-bound per-subnet routes.
func TestDialupPeer_AddRouteOn_NoParentBoundStatics(t *testing.T) {
	in := dialupIntent(true)
	_, all := renderBodies(t, in)

	if !strings.Contains(all, `"add-route":"enable"`) {
		t.Error("dialup phase1 must set add-route=enable — FortiOS has to inject the sub-tunnel routes itself")
	}
	if strings.Contains(all, `"device":"`+in.Name+`"`) {
		t.Errorf("dialup render must not bind a static route to the parent interface %q "+
			"(its tun_id matches no sub-tunnel; traffic drops at IPsec egress):\n%s", in.Name, all)
	}
	// The blackhole backstop MUST survive — it is what stops traffic leaking out
	// the default route while the tunnel is down.
	for _, s := range in.Ends[1].ProtectedSubnets {
		want := `"dst":"` + mustCIDR(t, s) + `"`
		if !strings.Contains(all, want) || !strings.Contains(all, `"blackhole":"enable"`) {
			t.Errorf("dialup render must still emit the distance-254 blackhole for %s:\n%s", s, all)
		}
	}
}

// A static peer is unaffected: its tunnel has a single tun_id equal to the remote
// gateway, so the driver's own routes bind correctly and FortiOS must not add
// competing ones.
func TestStaticPeer_KeepsOwnRoutes_AddRouteOff(t *testing.T) {
	in := dialupIntent(false)
	_, all := renderBodies(t, in)

	if !strings.Contains(all, `"add-route":"disable"`) {
		t.Error("static phase1 must keep add-route=disable — the driver owns its routes")
	}
	if !strings.Contains(all, `"device":"`+in.Name+`"`) {
		t.Errorf("static peer must still get its per-subnet routes via the tunnel interface:\n%s", all)
	}
}

// The seq-num slot space must not shift between the two cases, or RenderRemove
// against a tunnel deployed under the other shape would delete the wrong keys.
func TestRouteSlotSpace_StableAcrossPeerType(t *testing.T) {
	keys := func(dynamic bool) []string {
		in := dialupIntent(dynamic)
		art, err := fgDriver(t).RenderRemove(ipsec.ViewFor(in, 0))
		if err != nil {
			t.Fatalf("render remove: %v", err)
		}
		var out []string
		for _, s := range art.Steps {
			if strings.Contains(s.Path, "/router/static/") {
				out = append(out, s.Path)
			}
		}
		return out
	}
	dyn, sta := keys(true), keys(false)
	if len(dyn) != len(sta) {
		t.Fatalf("remove sweep must cover the same slot space for both peer types: dynamic=%v static=%v", dyn, sta)
	}
	for i := range dyn {
		if dyn[i] != sta[i] {
			t.Errorf("slot %d differs: dynamic=%s static=%s", i, dyn[i], sta[i])
		}
	}
}

// Preflight must probe exactly what Render creates: the collector re-runs these
// GETs after the write expecting PRESENT, so probing a never-created slot would
// fail verification and report a healthy deploy as unverified.
func TestDialupPreflight_SkipsUncreatedRouteSlots(t *testing.T) {
	in := dialupIntent(true)
	d := fgDriver(t)
	view := ipsec.ViewFor(in, 0)

	created := map[string]bool{}
	art, err := d.Render(view)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, s := range art.Steps {
		if s.Method == "POST" && strings.HasSuffix(s.Path, "/router/static") {
			created[s.Body] = true
		}
	}
	nCreated := len(created)

	probed := 0
	for _, s := range d.PreflightProbe(view) {
		if s.Check == "route" {
			probed++
		}
	}
	if probed != nCreated {
		t.Errorf("preflight probes %d route keys but Render creates %d — verify would miscount", probed, nCreated)
	}
	if probed == 0 {
		t.Error("preflight should still probe the blackhole routes")
	}
}

func mustCIDR(t *testing.T, cidr string) string {
	t.Helper()
	ip, mask, ok := splitCIDR(cidr)
	if !ok {
		t.Fatalf("bad fixture CIDR %q", cidr)
	}
	return ip + " " + mask
}
