package alerts

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// v48 suggester profile targeting: WHERE a suggested suppress lands decides
// whether it can win (layer beats priority).

func TestSuggest_ClassSuppressTargetsGoverningProfile(t *testing.T) {
	r := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeDeviceOffline, DeviceID: 7, DeviceName: "fw",
		GoverningProfileID: 3, GoverningProfileName: "Branch",
		DefaultProfileID: 1, DefaultProfileName: "Default",
	})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("expected supported suggestion, got %+v", r)
	}
	if r.Rule.ProfileID != 3 || r.Rule.ProfileName != "Branch" {
		t.Errorf("class suppress must target the governing profile (chain head), got %d %q", r.Rule.ProfileID, r.Rule.ProfileName)
	}
}

func TestSuggest_RuleNameAlertTargetsFiringRulesProfile(t *testing.T) {
	pri := 40
	rid := uint(9)
	r := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeLogRuleMatch, DeviceID: 7, DeviceName: "fw",
		Vendor: "fortigate", MetricName: "My syslog rule",
		Message:            "[My syslog rule] fw: type=event subtype=system logid=0100032002 msg=x",
		FiringRulePriority: &pri, ExistingRuleID: &rid,
		FiringRuleProfileID: 5, FiringRuleProfileName: "SiteProf",
		GoverningProfileID: 3, GoverningProfileName: "Branch",
		DefaultProfileID: 1, DefaultProfileName: "Default",
	})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("expected supported suggestion, got %+v", r)
	}
	if r.Rule.ProfileID != 5 || r.Rule.ProfileName != "SiteProf" {
		t.Errorf("rule-name suppress must land in the FIRING rule's profile (same-layer priority-1 out-ranking), got %d %q", r.Rule.ProfileID, r.Rule.ProfileName)
	}
	if r.Rule.Priority != 39 {
		t.Errorf("priority must sort one above the firing rule, got %d", r.Rule.Priority)
	}
}

func TestSuggest_GlobalSourceMuteTargetsDefaultWithWarning(t *testing.T) {
	r := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeSFlowSecurity, DeviceID: 7, SourceAddr: "203.0.113.7",
		GoverningProfileID: 3, GoverningProfileName: "Branch",
		DefaultProfileID: 1, DefaultProfileName: "Default",
		ScopeWarnFlowSec: true,
	})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("expected supported suggestion, got %+v", r)
	}
	if r.Rule.ProfileID != 1 || r.Rule.ProfileName != "Default" {
		t.Errorf("global source mute must land in Default (a device/site profile would narrow it), got %d %q", r.Rule.ProfileID, r.Rule.ProfileName)
	}
	if r.Rule.DeviceID != nil || r.Rule.SiteID != nil {
		t.Error("global mute must stay unscoped")
	}
	if !strings.Contains(r.ScopeWarning, "flow-security alert rules") {
		t.Errorf("scope warning expected when non-default profiles carry flow_security alert rules, got %q", r.ScopeWarning)
	}

	// No shadowing profiles → no warning.
	r = SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeSFlowSecurity, DeviceID: 7, SourceAddr: "203.0.113.7",
		DefaultProfileID: 1, DefaultProfileName: "Default",
	})
	if r.ScopeWarning != "" {
		t.Errorf("no warning expected without shadowing profiles, got %q", r.ScopeWarning)
	}
}

// EffectiveEventConfig mirrors the fire path: chain, per-type decided_by, and
// rules in evaluation order with layer labels.
func TestEffectiveEventConfig(t *testing.T) {
	am, db := newTestManager(t)
	installChainRulesDB(t, am, db) // device 1 → DevProf; site 40; Default has a suppress rule

	// Toggle: VPN off at Default.
	def, _ := db.GetDefaultEventRuleProfile()
	if err := db.ReplaceProfileToggles(def.ID, []models.EventRuleProfileToggle{
		{AlertType: models.AlertTypeVPNTunnelDown, Enabled: false},
	}); err != nil {
		t.Fatal(err)
	}
	am.RefreshPolicyCache(db)

	chain, toggles, rules := am.EffectiveEventConfig(1, nil)
	if len(chain) != 2 || chain[0].Layer != "device" || chain[0].ProfileName != "DevProf" || chain[1].Layer != "default" {
		t.Fatalf("chain wrong: %+v", chain)
	}
	var vpn, cpu *EffectiveEventToggle
	for i := range toggles {
		switch toggles[i].AlertType {
		case models.AlertTypeVPNTunnelDown:
			vpn = &toggles[i]
		case models.AlertTypeCPUHigh:
			cpu = &toggles[i]
		}
	}
	if vpn == nil || vpn.Enabled || vpn.DecidedBy != "default" {
		t.Errorf("VPN toggle: want Off decided by default, got %+v", vpn)
	}
	if cpu == nil || !cpu.Enabled || cpu.DecidedBy != "implicit" {
		t.Errorf("CPU toggle: want implicit ON, got %+v", cpu)
	}
	if len(toggles) != len(models.AllAlertTypes()) {
		t.Errorf("effective view must cover the full registry: %d vs %d", len(toggles), len(models.AllAlertTypes()))
	}
	// Rules: device layer first (dev-alert), then Default (default-mute-all).
	if len(rules) != 2 || rules[0].Layer != "device" || rules[0].Name != "dev-alert" ||
		rules[1].Layer != "default" || rules[1].Name != "default-mute-all" {
		t.Fatalf("rules order/labels wrong: %+v", rules)
	}
}
