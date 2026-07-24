package ipsec_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestOPNsense_FirewallRules_Rendered pins the data-plane fix: the OPNsense driver
// renders two floating PASS rules (one per traffic-origin direction) scoped to the
// protected subnets, plus a separate filter/apply — without them the SA comes up
// but no packet forwards (the fwm-t9 outage).
func TestOPNsense_FirewallRules_Rendered(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	in := canonicalIntent() // end 1 = OPNsense (192.168.50.0/24), end 0 = FortiGate (10.10.10.0/24)
	art, err := d.Render(ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	type ruleView struct{ body, capture string }
	var rules []ruleView
	reconfigureIdx, applyIdx := -1, -1
	for i, s := range art.Steps {
		switch {
		case s.Path == "/api/firewall/filter/addRule":
			rules = append(rules, ruleView{s.Body, s.CaptureAs})
		case s.Path == "/api/ipsec/service/reconfigure":
			reconfigureIdx = i
		case s.Path == "/api/firewall/filter/apply":
			applyIdx = i
		}
	}

	if len(rules) != 2 {
		t.Fatalf("want 2 firewall addRule steps, got %d", len(rules))
	}
	// filter/apply must exist AND run after the ipsec reconfigure (pf ruleset is a
	// separate reload; the rule does nothing until filter/apply).
	if applyIdx < 0 {
		t.Fatal("missing /api/firewall/filter/apply step — rules would save but never load into pf")
	}
	if reconfigureIdx < 0 || applyIdx < reconfigureIdx {
		t.Errorf("filter/apply (idx %d) must come after ipsec reconfigure (idx %d)", applyIdx, reconfigureIdx)
	}

	for _, r := range rules {
		for _, want := range []string{`"action":"pass"`, `"interface":""`, `"direction":"in"`, `"quick":"1"`, `"ipprotocol":"inet"`, `"description":"` + in.Name + `"`} {
			if !strings.Contains(r.body, want) {
				t.Errorf("rule %q body missing %s: %s", r.capture, want, r.body)
			}
		}
	}

	// Orientation: OUT-leg source=local(50)/dest=remote(10); IN-leg swapped.
	byCap := map[string]string{}
	for _, r := range rules {
		byCap[r.capture] = r.body
	}
	out, in2 := byCap["rule_out"], byCap["rule_in"]
	if out == "" || in2 == "" {
		t.Fatalf("expected rule_out and rule_in captures, got %v", byCap)
	}
	if !strings.Contains(out, `"source_net":"192.168.50.0/24"`) || !strings.Contains(out, `"destination_net":"10.10.10.0/24"`) {
		t.Errorf("rule_out orientation wrong: %s", out)
	}
	if !strings.Contains(in2, `"source_net":"10.10.10.0/24"`) || !strings.Contains(in2, `"destination_net":"192.168.50.0/24"`) {
		t.Errorf("rule_in orientation wrong: %s", in2)
	}
}

// TestOPNsense_FirewallRules_MultiSubnet: multiple protected subnets per end
// comma-join into ONE rule pair (the filter source_net/destination_net are
// Multiple=Y on OPNsense 26.1 — verified live), not a per-pair explosion.
func TestOPNsense_FirewallRules_MultiSubnet(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	in := canonicalIntent()
	in.Ends[1].ProtectedSubnets = []string{"192.168.50.0/24", "192.168.51.0/24"} // OPNsense = local
	art, err := d.Render(ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var addRules int
	for _, s := range art.Steps {
		if s.Path == "/api/firewall/filter/addRule" {
			addRules++
			if s.CaptureAs == "rule_out" && !strings.Contains(s.Body, `"source_net":"192.168.50.0/24,192.168.51.0/24"`) {
				t.Errorf("multi-subnet source_net should comma-join: %s", s.Body)
			}
		}
	}
	if addRules != 2 {
		t.Errorf("multi-subnet must still be 2 rules (comma-joined), got %d", addRules)
	}
}

// TestOPNsense_Preflight_IncludesRuleAnchor pins the collision/verify anchor for
// the firewall rule (searchPhrase-pinned so a rule-heavy box can't paginate it away).
func TestOPNsense_Preflight_IncludesRuleAnchor(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	in := canonicalIntent()
	found := false
	for _, s := range d.PreflightProbe(ipsec.ViewFor(in, 1)) {
		if strings.Contains(s.Path, "/api/firewall/filter/searchRule") {
			found = true
			if !s.ExpectAbsent {
				t.Error("rule preflight anchor must be ExpectAbsent (a present fwm rule is a collision)")
			}
			if !strings.Contains(s.Path, "searchPhrase="+in.Name) {
				t.Errorf("rule anchor should pin ?searchPhrase=%s to avoid pagination: %s", in.Name, s.Path)
			}
		}
	}
	if !found {
		t.Error("PreflightProbe missing the firewall/filter/searchRule anchor")
	}
}

// TestOPNsense_RenderRemove_DeletesRulesAndApplies: rollback removes both rules and
// reloads pf.
func TestOPNsense_RenderRemove_DeletesRulesAndApplies(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	rem, err := d.RenderRemove(ipsec.ViewFor(canonicalIntent(), 1))
	if err != nil {
		t.Fatalf("render remove: %v", err)
	}
	var delRules, filterApply int
	for _, s := range rem.Steps {
		if strings.HasPrefix(s.Path, "/api/firewall/filter/delRule/") {
			delRules++
		}
		if s.Path == "/api/firewall/filter/apply" {
			filterApply++
		}
	}
	if delRules != 2 {
		t.Errorf("want 2 delRule steps, got %d", delRules)
	}
	if filterApply != 1 {
		t.Errorf("want 1 filter/apply on remove, got %d", filterApply)
	}
}

// TestOPNsense_MixedFamily_FailsLoud: a mixed IPv4/IPv6 protected footprint can't be
// one rule pair (single ipprotocol) — fail loud rather than silently drop a family.
func TestOPNsense_MixedFamily_FailsLoud(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	in := canonicalIntent()
	in.Ends[1].ProtectedSubnets = []string{"192.168.50.0/24", "2001:db8::/64"}
	if _, err := d.Render(ipsec.ViewFor(in, 1)); err == nil {
		t.Fatal("mixed IPv4/IPv6 protected subnets must fail the render (documented dual-stack follow-up)")
	}
	// RenderRemove must STILL render (rollback of a partially-created tunnel must
	// never be blocked by a fail-fast intent).
	if _, err := d.RenderRemove(ipsec.ViewFor(in, 1)); err != nil {
		t.Errorf("RenderRemove must render even for a fail-fast intent: %v", err)
	}
}
