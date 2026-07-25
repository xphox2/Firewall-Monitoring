package ipsec_test

import (
	"regexp"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestOPNsense_Children_FanOutPerPair pins the cross-vendor interop fix: the OPNsense
// driver renders ONE strongSwan child per (local × remote) subnet pair, each with a
// SINGLE local_ts/remote_ts. A comma-joined multi-TS child is narrowed by a FortiGate
// peer to a single pair (strongSwan won't re-spawn children for the narrowed-away
// selectors), so the extra subnets never install — the fwm-t9 "5.0/24 can't tunnel".
// child_<i> must line up with fwRuleSpecs pair index i so children and firewall rules
// can never desynchronize.
func TestOPNsense_Children_FanOutPerPair(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	in := canonicalIntent()                                                     // end 1 = OPNsense (local), end 0 = FortiGate (remote 10.10.10.0/24)
	in.Ends[1].ProtectedSubnets = []string{"192.168.50.0/24", "192.168.5.0/24"} // 2 local × 1 remote = 2 pairs
	art, err := d.Render(ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	tsRe := regexp.MustCompile(`"(?:local_ts|remote_ts)":"([^"]*)"`)
	children := map[string]string{}
	var names []string
	for _, s := range art.Steps {
		if s.Path != "/api/ipsec/connections/addChild" {
			continue
		}
		children[s.CaptureAs] = s.Body
		names = append(names, s.CaptureAs)
		// Each traffic selector must be a SINGLE network, never a comma-joined list.
		for _, m := range tsRe.FindAllStringSubmatch(s.Body, -1) {
			if strings.Contains(m[1], ",") {
				t.Errorf("child %q ts must be a single network, not a list: %q", s.CaptureAs, m[1])
			}
		}
		// Every child body must reference the connection token, not a literal.
		if !strings.Contains(s.Body, "<uuid:conn>") {
			t.Errorf("child %q body must reference <uuid:conn>: %s", s.CaptureAs, s.Body)
		}
	}
	if len(children) != 2 {
		t.Fatalf("2 local × 1 remote = 2 children, got %d: %v", len(children), names)
	}

	// child_<i> orientation must match fwRuleSpecs pair index i: pair 0 = (50 ↔ 10),
	// pair 1 = (5 ↔ 10). local_ts = local subnet, remote_ts = the remote subnet.
	c0, c1 := children["child_0"], children["child_1"]
	if c0 == "" || c1 == "" {
		t.Fatalf("expected child_0 and child_1 captures, got %v", names)
	}
	if !strings.Contains(c0, `"local_ts":"192.168.50.0/24"`) || !strings.Contains(c0, `"remote_ts":"10.10.10.0/24"`) {
		t.Errorf("child_0 orientation wrong: %s", c0)
	}
	if !strings.Contains(c1, `"local_ts":"192.168.5.0/24"`) || !strings.Contains(c1, `"remote_ts":"10.10.10.0/24"`) {
		t.Errorf("child_1 orientation wrong: %s", c1)
	}

	// RenderRemove must delete BOTH children (capture/delete parity for rollback).
	rem, err := d.RenderRemove(ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatalf("render remove: %v", err)
	}
	var delChild int
	for _, s := range rem.Steps {
		if strings.Contains(s.Path, "/api/ipsec/connections/delChild/") {
			delChild++
		}
	}
	if delChild != 2 {
		t.Errorf("want 2 delChild steps, got %d", delChild)
	}
}

// TestOPNsense_Children_SingleSubnet is the regression guard: a 1×1 tunnel renders
// exactly one child, captured child_0 — behaviorally identical to the pre-fan-out child.
func TestOPNsense_Children_SingleSubnet(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	art, err := d.Render(ipsec.ViewFor(canonicalIntent(), 1))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var caps []string
	for _, s := range art.Steps {
		if s.Path == "/api/ipsec/connections/addChild" {
			caps = append(caps, s.CaptureAs)
		}
	}
	if len(caps) != 1 || caps[0] != "child_0" {
		t.Errorf("single-subnet tunnel must render exactly one child_0, got %v", caps)
	}
}
