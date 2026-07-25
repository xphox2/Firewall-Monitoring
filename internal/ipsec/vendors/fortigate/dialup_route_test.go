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

// Route-based + a dialup peer must be REFUSED, not rendered. add-route follows
// the negotiated selectors, and route-based negotiates 0.0.0.0/0 — so FortiOS
// would install a default route via the tunnel instead of per-subnet routes,
// which is both wrong and capable of capturing unrelated traffic. Policy-based
// negotiates the protected subnets, so it is fine.
func TestRouteBasedDialup_IsRefused(t *testing.T) {
	in := dialupIntent(true)
	in.Mode = ipsec.ModeRouteBased
	in.VTISubnet = "169.254.1.36/30"

	caps := [2]ipsec.CapabilityDescriptor{fgDriver(t).Capabilities(), fgDriver(t).Capabilities()}
	fs := ipsec.Validate(in, caps)
	var found bool
	for _, f := range fs {
		if f.Code == "routebased_dialup_unsupported" {
			found = true
			if f.Severity != ipsec.SeverityBlock {
				t.Errorf("route-based+dialup must BLOCK, got severity %q", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("route-based tunnel to a dynamic peer must be blocked; findings=%+v", fs)
	}

	// The same intent in policy-based mode must NOT raise it.
	in.Mode = ipsec.ModePolicyBased
	for _, f := range ipsec.Validate(in, caps) {
		if f.Code == "routebased_dialup_unsupported" {
			t.Error("policy-based + dialup is supported and must not be blocked")
		}
	}
}

// A dialup peer's tunnel routes come from FortiOS at distance 15, not from the
// driver at distance 10. The competing-route advisory must measure against the
// route that ACTUALLY carries the traffic — otherwise a pre-existing route at
// distance 11-15 beats the injected route and the advisory stays silent, a false
// all-clear on the very "tunnel up, zero outbound" failure it exists to catch.
func TestAdvisory_DialupUsesInjectedRouteDistance(t *testing.T) {
	d := fgDriver(t)
	// A pre-existing route at distance 12: harmless against a static peer's
	// distance-10 route, but it BEATS a dialup peer's distance-15 injected route.
	body := `{"results":[{"seq-num":7,"dst":"192.168.50.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":12,"blackhole":"disable","status":"enable"}]}`

	dyn := d.Advisories(ipsec.ViewFor(dialupIntent(true), 0), map[string]string{checkRouteTable: body})
	if len(dyn) != 1 {
		t.Fatalf("a distance-12 route BEATS the dialup peer's distance-15 injected route and must be advised; got %d", len(dyn))
	}
	if !strings.Contains(dyn[0].Title, "outranks") {
		t.Errorf("distance 12 vs 15 outranks the tunnel; got title %q", dyn[0].Title)
	}
	if !strings.Contains(dyn[0].Detail, "distance 15") {
		t.Errorf("detail must state the injected-route distance the operator has to beat; got %q", dyn[0].Detail)
	}
	if !strings.Contains(dyn[0].Remedy, "set distance 25") {
		t.Errorf("remedy must clear 15, not 10; got %q", dyn[0].Remedy)
	}

	// Same route against a STATIC peer: distance 12 loses to the driver's 10, so
	// there is genuinely nothing to report.
	if sta := d.Advisories(ipsec.ViewFor(dialupIntent(false), 0), map[string]string{checkRouteTable: body}); len(sta) != 0 {
		t.Errorf("distance 12 loses to a static peer's distance-10 route — no advisory expected, got %+v", sta)
	}
}

// The peer /32 "self-lockout guard" must NOT be rendered for a dialup peer. This
// FortiGate never dials such a peer, so its PeerIP is not an IKE endpoint that
// could be locked out — and a /32 out the WAN at distance 10 would beat the
// injected /24 at 15, sending traffic for a legitimate in-tunnel host out the
// WAN in cleartext.
func TestDialupPeer_NoPeerHostRoute(t *testing.T) {
	in := dialupIntent(true)
	// Arrange the exact trigger: a Gateway on this end, and the peer's address
	// sitting inside its own protected subnets.
	in.Ends[0].Gateway = "203.0.113.254"
	in.Ends[1].PeerIP = "192.168.5.107" // inside 192.168.5.0/24
	_, all := renderBodies(t, in)

	if strings.Contains(all, `"dst":"192.168.5.107 255.255.255.255"`) {
		t.Errorf("dialup render must not pin a /32 host route to the peer — it would "+
			"shadow the injected /24 and blackhole a legitimate in-tunnel host:\n%s", all)
	}

	// And validation must not nag about a lockout that cannot happen. Check with
	// the Gateway CLEARED: with one set, the pre-fix code also stayed silent (a
	// set Gateway was treated as auto-resolving the lockout), so only the
	// gateway-empty leg actually pins the validation change.
	caps := [2]ipsec.CapabilityDescriptor{fgDriver(t).Capabilities(), fgDriver(t).Capabilities()}
	in.Ends[0].Gateway = ""
	for _, f := range ipsec.Validate(in, caps) {
		if f.Code == "self_lockout" {
			t.Errorf("self_lockout is a false premise for a dialup peer: %+v", f)
		}
	}
	// The same shape with a STATIC peer must STILL warn — the gate must not have
	// disabled the check wholesale.
	sta := dialupIntent(false)
	sta.Ends[1].PeerIP = "192.168.5.107"
	sta.Ends[0].Gateway = ""
	var warned bool
	for _, f := range ipsec.Validate(sta, caps) {
		if f.Code == "self_lockout" {
			warned = true
		}
	}
	if !warned {
		t.Error("a STATIC peer whose endpoint sits inside its own protected subnet must still raise self_lockout")
	}
}

// REGRESSION GUARD: silencing the dialup self-lockout warning must NOT silence
// the broad-cover-prefix BLOCK. A prefix like 0.0.0.0/2 is longer than the
// device's default route, so it wins regardless of distance and can swallow the
// peer's real NAT address — and for a dialup peer there is no /32 pin remedy,
// because nobody knows the address to pin. It must block unconditionally.
func TestDialupPeer_BroadCoverPrefixStillBlocks(t *testing.T) {
	in := dialupIntent(true)
	// No overlap with the local side, so subnet_overlap stays silent and this
	// test can only pass via the broad-prefix block.
	in.Ends[1].ProtectedSubnets = []string{"0.0.0.0/2"}
	// 192.168.5.107 is OUTSIDE 0.0.0.0/2 (which covers 0.0.0.0-63.255.255.255), so
	// the n.Contains(peerIP) test is FALSE and only the unconditional dynamic-peer
	// clause can raise the block. (A PeerIP inside the prefix would pass even under
	// the old contains-gated code, and prove nothing.)
	in.Ends[1].PeerIP = "192.168.5.107"
	in.Ends[0].ProtectedSubnets = []string{"192.168.25.0/24"}

	caps := [2]ipsec.CapabilityDescriptor{fgDriver(t).Capabilities(), fgDriver(t).Capabilities()}
	var blocked bool
	for _, f := range ipsec.Validate(in, caps) {
		if f.Code == "default_route_over_vti" && f.Severity == ipsec.SeverityBlock {
			blocked = true
			if !strings.Contains(f.Message, "not known in advance") {
				t.Errorf("dialup broad-prefix block should explain why no pinned host route can help; got %q", f.Message)
			}
		}
	}
	if !blocked {
		t.Error("a broad-cover prefix toward a DYNAMIC peer must BLOCK even though PeerIP is outside it")
	}
}
