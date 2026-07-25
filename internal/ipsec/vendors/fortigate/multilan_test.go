package fortigate

import (
	"encoding/json"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// A tunnel endpoint protects a LIST of subnets but used to name ONE LAN
// interface, so policies covered one port while the phase2 selectors covered
// every subnet — traffic on the other ports was silently dropped.
//
// The fix keeps TWO policies and makes srcintf/dstintf member tables, which
// FortiOS supports natively (verified live: firewall/policy?action=schema
// reports "category":"table","member_table":true). Per-interface policies would
// have collided on FortiOS's unique-policy-name rule, every copy wanting
// "<tunnel>-out".

// policyBodies returns the decoded bodies of the two firewall-policy POSTs.
func policyBodies(t *testing.T, in *ipsec.TunnelIntent) []map[string]any {
	t.Helper()
	art, err := fgDriver(t).Render(ipsec.ViewFor(in, 0))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var out []map[string]any
	for _, s := range art.Steps {
		if s.Method != "POST" || !strings.HasSuffix(s.Path, "/firewall/policy") {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(s.Body), &body); err != nil {
			t.Fatalf("policy body is not JSON: %v\n%s", err, s.Body)
		}
		out = append(out, body)
	}
	return out
}

func memberNames(t *testing.T, v any) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("interface field is not an array: %#v", v)
	}
	names := make([]string, 0, len(arr))
	for _, m := range arr {
		mm, ok := m.(map[string]any)
		if !ok {
			t.Fatalf("member is not an object: %#v", m)
		}
		n, _ := mm["name"].(string)
		if n == "" {
			t.Errorf(`empty interface member {"name": ""} would be accepted by conformance and rejected by the device mid-apply`)
		}
		names = append(names, n)
	}
	return names
}

// Several LAN interfaces render as MEMBERS of the same two policies — not as
// extra policies, which would collide on policy name.
func TestPolicy_MultipleLANIfacesAreMembersNotExtraPolicies(t *testing.T) {
	in := t9Intent()
	in.Ends[0].LANIfaces = []string{"port2", "port3"}

	bodies := policyBodies(t, in)
	if len(bodies) != 2 {
		t.Fatalf("want exactly 2 policies regardless of interface count, got %d", len(bodies))
	}

	out, inb := bodies[0], bodies[1]
	if got := memberNames(t, out["srcintf"]); len(got) != 2 || got[0] != "port2" || got[1] != "port3" {
		t.Errorf("LAN→tunnel srcintf members = %v, want [port2 port3]", got)
	}
	if got := memberNames(t, out["dstintf"]); len(got) != 1 || got[0] != in.Name {
		t.Errorf("LAN→tunnel dstintf members = %v, want [%s]", got, in.Name)
	}
	if got := memberNames(t, inb["srcintf"]); len(got) != 1 || got[0] != in.Name {
		t.Errorf("tunnel→LAN srcintf members = %v, want [%s]", got, in.Name)
	}
	if got := memberNames(t, inb["dstintf"]); len(got) != 2 {
		t.Errorf("tunnel→LAN dstintf members = %v, want both LAN interfaces", got)
	}

	// Ids and names must be identical to the single-interface case, or the
	// preflight/remove key space and the unique-name rule both break.
	single := policyBodies(t, t9Intent())
	for i := range bodies {
		if bodies[i]["policyid"] != single[i]["policyid"] {
			t.Errorf("policy %d id changed with multiple interfaces: %v vs %v", i, bodies[i]["policyid"], single[i]["policyid"])
		}
		if bodies[i]["name"] != single[i]["name"] {
			t.Errorf("policy %d name changed with multiple interfaces: %v vs %v", i, bodies[i]["name"], single[i]["name"])
		}
	}
}

// Multiple subnets on ONE interface, and multiple interfaces, are independent
// axes — the policies are all→all across the interface set and the subnets ride
// the phase2 selectors, so N subnets on 1 port renders exactly like 1 on 1.
func TestPolicy_ManySubnetsOneInterface(t *testing.T) {
	in := t9Intent()
	in.Ends[0].LANIfaces = []string{"port3"}
	in.Ends[0].ProtectedSubnets = []string{"192.168.13.0/24", "192.168.14.0/24", "192.168.15.0/24"}

	bodies := policyBodies(t, in)
	if len(bodies) != 2 {
		t.Fatalf("subnet count must not change the policy count, got %d", len(bodies))
	}
	if got := memberNames(t, bodies[0]["srcintf"]); len(got) != 1 || got[0] != "port3" {
		t.Errorf("srcintf members = %v, want just [port3]", got)
	}
}

// Blank and duplicate entries must never reach the device: a {"name": ""} member
// passes conformance (which models only `action`) and then fails mid-apply.
func TestPolicy_BlankAndDuplicateMembersAreDropped(t *testing.T) {
	in := t9Intent()
	in.Ends[0].LANIfaces = []string{" port3 ", "", "port3", "   ", "port2"}

	got := memberNames(t, policyBodies(t, in)[0]["srcintf"])
	if len(got) != 2 || got[0] != "port3" || got[1] != "port2" {
		t.Errorf("members = %v, want [port3 port2] — trimmed, deduped, blanks dropped", got)
	}
}

// THE COMPATIBILITY CANARY. A tunnel persisted before LANIfaces existed carries
// only "lan_iface". The deploy path unmarshals intent_json straight into the
// intent and NEVER calls hydrateDerived, so a driver reading the slice directly
// would render policies with no interface members against a live tunnel.
//
// This deliberately goes raw JSON -> Render, not through any normalizer: a test
// that hydrated first would pass while exactly that regression shipped.
func TestPolicy_LegacyIntentJSONStillRendersItsInterface(t *testing.T) {
	legacy := t9Intent()
	legacy.Ends[0].LANIfaces = nil
	legacy.Ends[0].LANIface = "port3"
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"lan_ifaces":[`) {
		t.Fatal("fixture is not the legacy shape — it carries a populated lan_ifaces")
	}

	var revived ipsec.TunnelIntent
	if err := json.Unmarshal(raw, &revived); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(revived.Ends[0].LANIfaces) != 0 {
		t.Fatal("fixture invalid: lan_ifaces should be empty after the round trip")
	}

	got := memberNames(t, policyBodies(t, &revived)[0]["srcintf"])
	if len(got) != 1 || got[0] != "port3" {
		t.Errorf("legacy intent rendered srcintf %v, want [port3] — a persisted tunnel must "+
			"not lose its interface on the deploy path", got)
	}
}

// Render must refuse rather than emit "srcintf": [] — conformance models only
// `action`, so an empty member array would pass every local check and die on the
// device. Validation blocks this before deploy, but preview renders without that
// gate, so the invariant has to be local to Render too.
func TestRender_FailsFastWithNoLANInterface(t *testing.T) {
	in := t9Intent()
	in.Ends[0].LANIface, in.Ends[0].LANIfaces = "", nil

	_, err := fgDriver(t).Render(ipsec.ViewFor(in, 0))
	if err == nil {
		t.Fatal("render must fail fast with no LAN interface, not emit an empty srcintf")
	}
	if !strings.Contains(err.Error(), "LAN interface") {
		t.Errorf("error should name the cause; got %v", err)
	}
}
