package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

func TestCompileAndEval(t *testing.T) {
	fields := map[string]string{
		"subtype": "vpn", "level": "error", "severity": "3",
		"srcintf": "internal", "msg": "IPsec phase 1 error",
	}
	tests := []struct {
		name string
		json string
		want bool
	}{
		{"eq match", `{"op":"eq","field":"subtype","value":"vpn"}`, true},
		{"eq case-insensitive", `{"op":"eq","field":"subtype","value":"VPN"}`, true},
		{"eq miss", `{"op":"eq","field":"subtype","value":"forward"}`, false},
		{"neq", `{"op":"neq","field":"level","value":"warning"}`, true},
		{"contains", `{"op":"contains","field":"msg","value":"ipsec"}`, true},
		{"not_contains", `{"op":"not_contains","field":"msg","value":"bgp"}`, true},
		{"regex", `{"op":"regex","field":"msg","value":"phase \\d error"}`, true},
		{"in", `{"op":"in","field":"subtype","values":["vpn","user"]}`, true},
		{"exists", `{"op":"exists","field":"srcintf"}`, true},
		{"exists miss", `{"op":"exists","field":"dstintf"}`, false},
		{"gt numeric", `{"op":"gt","field":"severity","value":"2"}`, true},
		{"lt numeric", `{"op":"lt","field":"severity","value":"2"}`, false},
		{"and both", `{"op":"and","conditions":[{"op":"eq","field":"subtype","value":"vpn"},{"op":"eq","field":"level","value":"error"}]}`, true},
		{"and one fails", `{"op":"and","conditions":[{"op":"eq","field":"subtype","value":"vpn"},{"op":"eq","field":"level","value":"warning"}]}`, false},
		{"or one passes", `{"op":"or","conditions":[{"op":"eq","field":"subtype","value":"forward"},{"op":"eq","field":"level","value":"error"}]}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules := compileRules([]models.EventRule{{ID: 1, Name: tc.name, MatchJSON: tc.json}})
			if len(rules) != 1 {
				t.Fatalf("expected 1 compiled rule, got %d", len(rules))
			}
			if got := rules[0].match.eval(fields); got != tc.want {
				t.Errorf("eval(%s) = %v, want %v", tc.json, got, tc.want)
			}
		})
	}
}

func TestCompileRulesBadJSONSkipped(t *testing.T) {
	rules := compileRules([]models.EventRule{
		{ID: 1, Name: "good", MatchJSON: `{"op":"eq","field":"a","value":"b"}`},
		{ID: 2, Name: "bad", MatchJSON: `{not json`},
		{ID: 3, Name: "defaults", MatchJSON: `{"op":"exists","field":"x"}`},
	})
	if len(rules) != 2 {
		t.Fatalf("bad JSON rule should be skipped: got %d rules", len(rules))
	}
	// defaults applied
	r := rules[1]
	if r.source != "syslog" || r.action != "alert" || r.alertType != models.AlertTypeLogRuleMatch {
		t.Errorf("defaults wrong: source=%q action=%q type=%q", r.source, r.action, r.alertType)
	}
}

func TestAppliesTo(t *testing.T) {
	site1 := uint(1)
	dev5 := uint(5)
	r := compiledRule{source: "syslog", vendor: "fortigate", deviceID: &dev5, siteID: &site1}
	if !r.appliesTo("syslog", "fortigate", 5, &site1) {
		t.Error("exact match should apply")
	}
	if r.appliesTo("flow", "fortigate", 5, &site1) {
		t.Error("wrong source must not apply")
	}
	if r.appliesTo("syslog", "opnsense", 5, &site1) {
		t.Error("wrong vendor must not apply")
	}
	if r.appliesTo("syslog", "fortigate", 6, &site1) {
		t.Error("wrong device must not apply")
	}
	if r.appliesTo("syslog", "fortigate", 5, nil) {
		t.Error("nil site must not match a site-scoped rule")
	}
	// any-scope rule
	open := compiledRule{source: "any", vendor: "", deviceID: nil, siteID: nil}
	if !open.appliesTo("flow", "anything", 99, nil) {
		t.Error("open rule should apply to anything")
	}
}
