package ipsec_test

import (
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

	// Collect the route/policy paths Render creates (POST bodies carry the keys;
	// RenderRemove DELETEs by the mkey path, which is what we compare against).
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
	if !sameKeys(preRoutes, remRoutes) {
		t.Errorf("preflight route keys != render route keys\n preflight=%v\n render=%v", preRoutes, remRoutes)
	}
	if !sameKeys(prePolicies, remPolicies) {
		t.Errorf("preflight policy keys != render policy keys\n preflight=%v\n render=%v", prePolicies, remPolicies)
	}

	// Explicit spot-check against the allocation formula.
	if !preRoutes["/api/v2/cmdb/router/static/"+strconv.Itoa(ipsec.FGRouteKey(in.ID, 0))] {
		t.Errorf("preflight missing route seq-num %d", ipsec.FGRouteKey(in.ID, 0))
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
