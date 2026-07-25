package fortigate

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// t9Intent mirrors the live fwm-t9 tunnel: a FortiGate end protecting
// 192.168.25.0/24 against an OPNsense end protecting 192.168.50.0/24 and
// 192.168.5.0/24. ViewFor(in, 0) therefore makes the OPNsense subnets "remote",
// which is what the route advisory reasons about.
func t9Intent() *ipsec.TunnelIntent {
	in := &ipsec.TunnelIntent{
		ID: 9, Name: "fwm-t9", Mode: ipsec.ModePolicyBased, PSK: "abcDEF012345678901234567890XYZ",
		IKE: ipsec.IKEProposal{Enc: "aes256gcm16", PRF: "prfsha384", DH: "20"},
		ESP: ipsec.ESPProposal{Enc: "aes256gcm16", PFS: "20"},
	}
	in.Ends[0] = ipsec.EndpointSpec{
		Vendor: "fortigate", PeerIP: "203.0.113.1", EgressIface: "port1", LANIface: "port3",
		LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "techlabs-fw-01"},
		ProtectedSubnets: []string{"192.168.25.0/24"}, InnerIP: "169.254.1.37",
	}
	in.Ends[1] = ipsec.EndpointSpec{
		Vendor: "opnsense", PeerIP: "198.51.100.1", EgressIface: "dtsec1", LANIface: "dtsec0",
		LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "opnsense"},
		ProtectedSubnets: []string{"192.168.50.0/24", "192.168.5.0/24"}, InnerIP: "169.254.1.38",
	}
	return in
}

func fgDriver(t *testing.T) ipsec.VendorDriver {
	t.Helper()
	d, ok := ipsec.Driver("fortigate")
	if !ok {
		t.Fatal("fortigate driver not registered")
	}
	return d
}

func advise(t *testing.T, body string) []ipsec.Advisory {
	t.Helper()
	return fgDriver(t).Advisories(ipsec.ViewFor(t9Intent(), 0), map[string]string{checkRouteTable: body})
}

// TestAdvisories_RealT9CompetingRoute is the case that motivated the check: the
// live FortiGate carries a hand-made route for 192.168.5.0/24 out port3 with no
// explicit distance (so FortiOS default 10 — the same distance the tunnel route
// gets). Both install and traffic ECMP-splits away from the tunnel, silently.
func TestAdvisories_RealT9CompetingRoute(t *testing.T) {
	// Captured verbatim from device 4's stored config revision, expressed in the
	// cmdb JSON shape the advisory GET returns.
	body := `{"results":[{"seq-num":1,"dst":"192.168.5.0 255.255.255.0","gateway":"192.168.25.254","device":"port3","distance":10,"priority":0,"blackhole":"disable","status":"enable","comment":""}]}`
	got := advise(t, body)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 advisory for the real t9 route table, got %d: %+v", len(got), got)
	}
	a := got[0]
	if a.Subject != "192.168.5.0/24" {
		t.Errorf("subject = %q, want the conflicting protected subnet 192.168.5.0/24", a.Subject)
	}
	if a.Check != checkRouteTable {
		t.Errorf("check = %q, want %q", a.Check, checkRouteTable)
	}
	// Equal distance is the ECMP case, not the outranked case — the operator acts
	// differently on each, so the copy must not blur them.
	if !strings.Contains(a.Title, "ties with") {
		t.Errorf("equal-distance advisory should describe a tie; got title %q", a.Title)
	}
	for _, want := range []string{"seq-num 1", "192.168.25.254 on port3", "ECMP"} {
		if !strings.Contains(a.Detail, want) {
			t.Errorf("detail should name %q so the operator can find the route; got %q", want, a.Detail)
		}
	}
	if !strings.Contains(a.Remedy, "set distance") {
		t.Errorf("remedy should give the concrete fix; got %q", a.Remedy)
	}
	t.Logf("REAL t9 advisory → %s | %s", a.Title, a.Remedy)
}

// A lower-distance route defeats the tunnel outright rather than splitting with
// it; that is a materially different failure and must read differently.
func TestAdvisories_LowerDistanceOutranksTunnel(t *testing.T) {
	body := `{"results":[{"seq-num":7,"dst":"192.168.50.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":5,"blackhole":"disable","status":"enable"}]}`
	got := advise(t, body)
	if len(got) != 1 {
		t.Fatalf("want 1 advisory, got %d", len(got))
	}
	if !strings.Contains(got[0].Title, "outranks") {
		t.Errorf("lower-distance advisory should say it outranks the tunnel; got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Detail, "never enter the tunnel") {
		t.Errorf("detail should state the consequence; got %q", got[0].Detail)
	}
}

// A supernet that covers a protected subnet steers it just as effectively as an
// exact match, so overlap — not equality — is the test.
func TestAdvisories_SupernetOverlapIsCaught(t *testing.T) {
	body := `{"results":[{"seq-num":3,"dst":"192.168.0.0 255.255.0.0","gateway":"10.0.0.1","device":"port2","distance":10,"blackhole":"disable","status":"enable"}]}`
	if got := advise(t, body); len(got) == 0 {
		t.Fatal("a /16 covering both protected /24s must raise an advisory")
	}
}

// Everything that is NOT a competing forwarding path must stay silent, or the
// advisory becomes noise the operator learns to ignore.
func TestAdvisories_NonCompetingRoutesAreSilent(t *testing.T) {
	cases := map[string]string{
		"higher distance loses to ours":  `{"results":[{"seq-num":3,"dst":"192.168.5.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":20,"blackhole":"disable","status":"enable"}]}`,
		"administratively disabled":      `{"results":[{"seq-num":3,"dst":"192.168.5.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":1,"blackhole":"disable","status":"disable"}]}`,
		"blackhole is not a path":        `{"results":[{"seq-num":3,"dst":"192.168.5.0 255.255.255.0","device":"","distance":1,"blackhole":"enable","status":"enable"}]}`,
		"unrelated prefix":               `{"results":[{"seq-num":3,"dst":"10.9.9.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":1,"blackhole":"disable","status":"enable"}]}`,
		"dstaddr object, prefix unknown": `{"results":[{"seq-num":3,"dst":"","dstaddr":"some-group","gateway":"10.0.0.1","device":"port2","distance":1,"blackhole":"disable","status":"enable"}]}`,
	}
	for name, body := range cases {
		if got := advise(t, body); len(got) != 0 {
			t.Errorf("%s: expected no advisory, got %+v", name, got)
		}
	}
}

// A re-run against a device this tunnel is already (partly) deployed on must not
// flag the tunnel's OWN routes — by deterministic seq-num, and by the comment /
// device tag Render stamps.
func TestAdvisories_OwnRoutesAreNotConflicts(t *testing.T) {
	own := ipsec.FGRouteKey(9, 0)
	body := `{"results":[` +
		`{"seq-num":` + itoa(own) + `,"dst":"192.168.50.0 255.255.255.0","device":"fwm-t9","distance":10,"blackhole":"disable","status":"enable","comment":"fwm-t9"},` +
		`{"seq-num":9001,"dst":"192.168.5.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":10,"blackhole":"disable","status":"enable","comment":"fwm-t9"}` +
		`]}`
	if got := advise(t, body); len(got) != 0 {
		t.Errorf("routes owned by this tunnel must never be advisories, got %+v", got)
	}
}

// The advisory must only ever assert what it positively observed. Anything it
// cannot read yields NO finding — never an invented warning, and equally never a
// reassuring all-clear, since absence of an advisory is not rendered as "clear".
func TestAdvisories_UnreadableInputYieldsNothing(t *testing.T) {
	d := fgDriver(t)
	v := ipsec.ViewFor(t9Intent(), 0)
	cases := map[string]map[string]string{
		"no bodies at all (older collector)": {},
		"empty body":                         {checkRouteTable: ""},
		"not JSON":                           {checkRouteTable: "<html>login</html>"},
		"JSON but not a cmdb list":           {checkRouteTable: `{"status":"error"}`},
		"body under a different check":       {"phase1": `{"results":[{"seq-num":1,"dst":"192.168.5.0 255.255.255.0","distance":1,"status":"enable"}]}`},
	}
	for name, bodies := range cases {
		if got := d.Advisories(v, bodies); len(got) != 0 {
			t.Errorf("%s: expected no advisory, got %+v", name, got)
		}
	}
}

// FortiOS quotes numerics inconsistently across builds; a string "10" must be
// read as a distance, not silently dropped.
func TestAdvisories_StringNumericsParse(t *testing.T) {
	body := `{"results":[{"seq-num":"1","dst":"192.168.5.0 255.255.255.0","gateway":"10.0.0.1","device":"port2","distance":"5","blackhole":"disable","status":"enable"}]}`
	got := advise(t, body)
	if len(got) != 1 {
		t.Fatalf("string-quoted numerics must parse, got %d advisories", len(got))
	}
	if !strings.Contains(got[0].Detail, "seq-num 1") {
		t.Errorf("string seq-num should be reported as 1; got %q", got[0].Detail)
	}
}

// STRUCTURAL non-blocking guarantee. PreflightProbe's steps are reused verbatim
// as the deploy saga's collision precheck, where an ExpectAbsent hit ABORTS the
// write. Advisory reads therefore live on AdvisoryProbe and must never leak into
// PreflightProbe, and must never carry ExpectAbsent themselves — so no advisory
// can stop a deploy no matter what the device returns.
func TestAdvisoryProbe_CannotBlockADeploy(t *testing.T) {
	d := fgDriver(t)
	v := ipsec.ViewFor(t9Intent(), 0)
	for _, s := range d.PreflightProbe(v) {
		if s.ReturnBody {
			t.Errorf("PreflightProbe must emit no ReturnBody step (it feeds the deploy's abort-on-hit precheck): %+v", s)
		}
		if s.Check == checkRouteTable {
			t.Errorf("the advisory read must not appear in PreflightProbe: %+v", s)
		}
	}
	steps := d.AdvisoryProbe(v)
	if len(steps) == 0 {
		t.Fatal("FortiGate should emit a route-table advisory read when the peer has protected subnets")
	}
	for _, s := range steps {
		if s.ExpectAbsent {
			t.Errorf("an advisory step must never be ExpectAbsent (that is what aborts an apply): %+v", s)
		}
		if s.Method != "GET" {
			t.Errorf("advisory steps must be read-only GETs, got %s %s", s.Method, s.Path)
		}
		if !s.ReturnBody {
			t.Errorf("advisory step %q must ask for its body, or the server can never analyse it", s.Check)
		}
	}
}

// fgTunnelRouteDistance asserts FortiOS's default because routeSteps leaves
// `distance` unset. If Render ever starts setting it, that constant becomes a
// lie and every advisory verdict shifts — so pin the omission here.
func TestRenderTunnelRouteOmitsDistance(t *testing.T) {
	art, err := fgDriver(t).Render(ipsec.ViewFor(t9Intent(), 0))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var sawTunnelRoute bool
	for _, s := range art.Steps {
		if s.Path != cmdbRoute || !strings.Contains(s.Description, "via tunnel") {
			continue
		}
		sawTunnelRoute = true
		if strings.Contains(s.Body, `"distance"`) {
			t.Errorf("tunnel route now sets an explicit distance — update fgTunnelRouteDistance (%d) to match: %s",
				fgTunnelRouteDistance, s.Body)
		}
	}
	if !sawTunnelRoute {
		t.Fatal("expected at least one 'static route ... via tunnel' step to pin")
	}
}
