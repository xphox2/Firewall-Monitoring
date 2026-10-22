package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// The simulator must report which notification channels are on without ever
// serialising the credentials behind them (webhook URLs, recipients).
func TestEffectiveAlertConfigPayload_ChannelsWithoutCredentials(t *testing.T) {
	policyID := uint(7)
	resolved := alerts.ResolvedAlertConfig{
		PolicyID:          &policyID,
		AlertEnabled:      true,
		InMaintenance:     true,
		Threshold:         80,
		ClearThreshold:    75,
		CooldownMinutes:   15,
		Severity:          models.SeverityCritical,
		StormSources:      5,
		NotifyEmail:       true,
		NotifySlack:       true,
		NotifyTeams:       true,
		EmailRecipients:   "noc@example.test",
		SlackURL:          "https://hooks.slack.example/services/SECRET",
		DiscordURL:        "https://discord.example/api/webhooks/SECRET",
		WebhookURL:        "https://webhook.example/SECRET",
		EscalationEnabled: true,
		EscalationMinutes: 30,
		EscalationRepeat:  10,
	}
	prov := alerts.ConfigProvenance{Threshold: "global", Cooldown: "policy"}

	payload := effectiveAlertConfigPayload("CPU_HIGH", resolved, prov)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := string(encoded)
	for _, secret := range []string{"hooks.slack", "discord.example", "webhook.example", "noc@example.test"} {
		if strings.Contains(body, secret) {
			t.Errorf("payload leaked %q: %s", secret, body)
		}
	}

	effective, ok := payload["effective"].(map[string]any)
	if !ok {
		if h, isH := payload["effective"].(gin.H); isH {
			effective = h
		} else {
			t.Fatalf("effective is %T", payload["effective"])
		}
	}
	if effective["notify_email"] != true || effective["notify_slack"] != true || effective["notify_teams"] != true {
		t.Errorf("enabled channels missing: %+v", effective)
	}
	if effective["notify_discord"] != false || effective["notify_webhook"] != false {
		t.Errorf("disabled channels must be false: %+v", effective)
	}
	if effective["escalation_enabled"] != true || effective["escalation_minutes"] != 30 {
		t.Errorf("escalation fields wrong: %+v", effective)
	}
	if effective["in_maintenance"] != true {
		t.Errorf("in_maintenance must reach the simulator: %+v", effective)
	}
	gotPolicy, ok := effective["policy_id"].(*uint)
	if !ok || gotPolicy == nil || *gotPolicy != policyID {
		t.Errorf("policy_id wrong: %+v", effective["policy_id"])
	}
	if effective["threshold"] != float64(80) {
		t.Errorf("threshold/policy wrong: %+v", effective)
	}

	provenance, ok := payload["provenance"].(gin.H)
	if !ok {
		t.Fatalf("provenance is %T", payload["provenance"])
	}
	if provenance["threshold"] != "global" || provenance["cooldown"] != "policy" {
		t.Errorf("provenance wrong: %+v", provenance)
	}
}
