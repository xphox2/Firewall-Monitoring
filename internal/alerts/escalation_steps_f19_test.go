package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestParseEscalationSteps_Validation pins the save-time contract.
func TestParseEscalationSteps_Validation(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantN   int
		wantErr bool
	}{
		{"empty = legacy", "", 0, false},
		{"empty array = legacy", "[]", 0, false},
		{"valid two-step", `[{"after_minutes":5,"channels":["slack"]},{"after_minutes":15,"channels":["pagerduty","email"],"recipients":"t2@x"}]`, 2, false},
		{"bad json", `{nope`, 0, true},
		{"unknown channel", `[{"after_minutes":5,"channels":["sms"]}]`, 0, true},
		{"no channels", `[{"after_minutes":5,"channels":[]}]`, 0, true},
		{"zero minutes", `[{"after_minutes":0,"channels":["email"]}]`, 0, true},
		{"not ascending", `[{"after_minutes":15,"channels":["email"]},{"after_minutes":5,"channels":["slack"]}]`, 0, true},
		{"duplicate minutes", `[{"after_minutes":5,"channels":["email"]},{"after_minutes":5,"channels":["slack"]}]`, 0, true},
	}
	for _, tc := range cases {
		steps, err := ParseEscalationSteps(tc.raw)
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.wantErr && len(steps) != tc.wantN {
			t.Errorf("%s: got %d steps, want %d", tc.name, len(steps), tc.wantN)
		}
	}
}

// TestStepNotifyConfig_ExactChannelTargeting: a step routes to exactly its
// channels — nothing inherited from the policy's own notify flags — and the
// recipients override lands on SMTPTo.
func TestStepNotifyConfig_ExactChannelTargeting(t *testing.T) {
	resolved := ResolvedAlertConfig{
		NotifyEmail: true, NotifySlack: true, NotifyDiscord: true, // policy-level flags must NOT leak through
		EmailRecipients: "noc@x",
	}
	global := notifier.NotifyConfig{
		EmailEnabled: true, SMTPTo: "noc@x",
		SlackWebhookURL: "https://slack", DiscordWebhookURL: "https://discord",
		WebHookURL: "https://hook", PagerDutyRoutingKey: "rk",
		OpsgenieAPIKey: "gk", TeamsWebhookURL: "https://teams",
	}

	step := EscalationStep{AfterMinutes: 15, Channels: []string{"pagerduty", "email"}, Recipients: "tier2@x"}
	nc := stepNotifyConfig(step, resolved, global)

	if !nc.EnablePagerDuty || !nc.EnableEmail {
		t.Errorf("step channels not enabled: %+v", nc)
	}
	if nc.EnableSlack || nc.EnableDiscord || nc.EnableWebhook || nc.EnableOpsgenie || nc.EnableTeams {
		t.Errorf("non-step channels leaked through: %+v", nc)
	}
	if nc.SMTPTo != "tier2@x" {
		t.Errorf("recipients override not applied: %q", nc.SMTPTo)
	}
	if !nc.PolicyActive {
		t.Error("step config must be policy-active (hard gating)")
	}
}

// TestCheckEscalations_StepChain: an unacked alert on a step-chain policy
// fires the due steps once each — EscalationCount tracks steps completed and
// never re-fires a completed step.
func TestCheckEscalations_StepChain(t *testing.T) {
	am, db := newTestManager(t)

	policy := models.AlertPolicy{
		ID: 1, Name: "chain", IsDefault: true,
		EscalationSteps: `[{"after_minutes":5,"channels":["slack"]},{"after_minutes":15,"channels":["email"]},{"after_minutes":600,"channels":["teams"]}]`,
	}
	am.policyCache = PolicyCache{
		policies:      []models.AlertPolicy{policy},
		policyByID:    map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		defaultPolicy: &policy,
		loaded:        true,
	}

	// Unacked alert 20 minutes old: steps 1 (5m) and 2 (15m) are due,
	// step 3 (600m) is not.
	pid := uint(1)
	alert := models.Alert{
		Timestamp: time.Now().Add(-20 * time.Minute),
		DeviceID:  5, AlertType: "CPU_HIGH", Severity: "warning",
		Message: "cpu high", MetricName: "cpu_usage", PolicyID: &pid,
	}
	seedAlert(t, db, &alert)

	am.CheckEscalations()

	got := getAlert(t, db, alert.ID)
	if got.EscalationCount != 2 {
		t.Fatalf("EscalationCount = %d, want 2 (two steps due)", got.EscalationCount)
	}

	// A second pass must not re-fire completed steps (count stays 2).
	am.CheckEscalations()
	got = getAlert(t, db, alert.ID)
	if got.EscalationCount != 2 {
		t.Fatalf("completed steps re-fired: count = %d, want 2", got.EscalationCount)
	}
}
