package ipsec_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestChecksumSteps_ParityWithCollector pins the exact hash for a fixed step set.
// The collector's fwapi package has an IDENTICAL pin (same input → same hash); if
// either side's serialization drifts, one of the two tests fails — the collector
// must recompute the same checksum the server sent or every write is refused.
func TestChecksumSteps_ParityWithCollector(t *testing.T) {
	steps := []ipsec.ApplyStep{
		{Kind: ipsec.StepHTTPAPI, Method: "POST", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface", Body: `{"name":"fwm-t7"}`},
		{Kind: ipsec.StepHTTPAPI, Method: "DELETE", Path: "/api/v2/cmdb/router/static/40000"},
	}
	const want = "c55b02d2f55baad85110bd051d22a479dd2402e9ec8fd0191cdee90996c6b820"
	if got := ipsec.ChecksumSteps(steps); got != want {
		t.Fatalf("checksum = %s, want %s (server/collector serialization drifted)", got, want)
	}
}

// TestPreflightProbeKeys_MatchRenderKeys verifies the FortiGate PreflightProbe's
// route/policy collision GETs read EXACTLY the deterministic mkeys Render creates
// (and RenderRemove deletes). If they diverge, the collision precheck would miss
// a real conflict or the post-write verify would miscount.
func TestPreflightProbeKeys_MatchRenderKeys(t *testing.T) {
	in := canonicalIntent()
	d, ok := ipsec.Driver("fortigate")
	if !ok {
		t.Fatal("fortigate driver not registered")
	}
	view := ipsec.ViewFor(in, 0)

	// Collect the route/policy paths PreflightProbe reads.
	pf := d.PreflightProbe(view)
	preRoutes, prePolicies := map[string]bool{}, map[string]bool{}
	for _, s := range pf {
		switch s.Check {
		case "route":
			preRoutes[s.Path] = true
			if !s.ExpectAbsent {
				t.Errorf("route collision GET %s must be ExpectAbsent", s.Path)
			}
		case "policy":
			prePolicies[s.Path] = true
		}
	}

	// Collect the route keys Render actually POSTs. This — not the remove sweep —
	// is what preflight must mirror: the collector re-runs the preflight GETs
	// after the write expecting each object to be PRESENT, so probing a key
	// Render never creates would fail verification.
	art, err := d.Render(view)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	createdRoutes := map[string]bool{}
	for _, s := range art.Steps {
		if s.Method != "POST" || !strings.HasSuffix(s.Path, "/router/static") {
			continue
		}
		m := regexp.MustCompile(`"seq-num":(\d+)`).FindStringSubmatch(s.Body)
		if m == nil {
			t.Fatalf("route POST body has no seq-num: %s", s.Body)
		}
		createdRoutes["/api/v2/cmdb/router/static/"+m[1]] = true
	}

	rem, err := d.RenderRemove(view)
	if err != nil {
		t.Fatalf("render remove: %v", err)
	}
	remRoutes, remPolicies := map[string]bool{}, map[string]bool{}
	for _, s := range rem.Steps {
		switch {
		case strings.Contains(s.Path, "/router/static/"):
			remRoutes[s.Path] = true
		case strings.Contains(s.Path, "/firewall/policy/"):
			remPolicies[s.Path] = true
		}
	}

	if len(preRoutes) == 0 || len(prePolicies) != 2 {
		t.Fatalf("preflight should read ≥1 route + exactly 2 policy keys, got routes=%d policies=%d", len(preRoutes), len(prePolicies))
	}
	if !sameKeys(preRoutes, createdRoutes) {
		t.Errorf("preflight route keys != the keys Render creates\n preflight=%v\n created=%v", preRoutes, createdRoutes)
	}
	if !sameKeys(prePolicies, remPolicies) {
		t.Errorf("preflight policy keys != render policy keys\n preflight=%v\n render=%v", prePolicies, remPolicies)
	}

	// RenderRemove must be able to reap everything Render created. It sweeps the
	// whole key SLOT SPACE — a superset — so that a slot left filled by a tunnel
	// deployed under an older render (e.g. the parent-bound statics a dialup peer
	// no longer gets) is still cleaned up. A DELETE of an absent key is success.
	for k := range createdRoutes {
		if !remRoutes[k] {
			t.Errorf("RenderRemove does not delete created route %s", k)
		}
	}
	if len(remRoutes) < len(createdRoutes) {
		t.Errorf("remove sweep (%d) must cover at least the created routes (%d)", len(remRoutes), len(createdRoutes))
	}

	// Explicit spot-check against the allocation formula. canonicalIntent's peer B
	// is DYNAMIC, so slot 0 (the per-subnet tunnel route) is deliberately reserved
	// but never created — FortiOS injects that route itself via phase1 add-route,
	// and a parent-bound static would shadow it and break egress. The blackhole
	// slot IS always created; pin that instead.
	nSub := len(in.Ends[1].ProtectedSubnets)
	blackhole0 := "/api/v2/cmdb/router/static/" + strconv.Itoa(ipsec.FGRouteKey(in.ID, nSub))
	if !preRoutes[blackhole0] {
		t.Errorf("preflight missing blackhole route key %s", blackhole0)
	}
	if preRoutes["/api/v2/cmdb/router/static/"+strconv.Itoa(ipsec.FGRouteKey(in.ID, 0))] {
		t.Error("preflight must NOT probe the per-subnet tunnel-route slot for a dynamic peer — it is never created")
	}
	for _, off := range []int{0, 1} {
		if !prePolicies["/api/v2/cmdb/firewall/policy/"+strconv.Itoa(ipsec.FGPolicyKey(in.ID, off))] {
			t.Errorf("preflight missing policy id %d", ipsec.FGPolicyKey(in.ID, off))
		}
	}
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
