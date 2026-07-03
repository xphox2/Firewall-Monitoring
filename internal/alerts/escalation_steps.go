package alerts

import (
	"encoding/json"
	"fmt"
	"sort"

	"firewall-mon/internal/notifier"
)

// F19 escalation chains: a policy may define ordered steps, each firing once
// when an alert stays unacknowledged past its after_minutes, to exactly that
// step's channels/recipients ("first 5 min Slack, after 15 min PagerDuty +
// email tier-2"). Alert.EscalationCount doubles as "steps completed".

// EscalationStep is one tier of an escalation chain.
type EscalationStep struct {
	AfterMinutes int      `json:"after_minutes"`
	Channels     []string `json:"channels"`
	// Recipients optionally overrides the email recipient list for this step.
	Recipients string `json:"recipients,omitempty"`
}

var validEscalationChannels = map[string]bool{
	"email": true, "slack": true, "discord": true, "webhook": true,
	"pagerduty": true, "opsgenie": true, "teams": true,
}

// ParseEscalationSteps parses and validates the policy JSON. "" ⇒ (nil, nil)
// — legacy escalation. Steps must be 1..10, each with after_minutes ≥ 1 in
// strictly ascending order and at least one known channel.
func ParseEscalationSteps(raw string) ([]EscalationStep, error) {
	if raw == "" {
		return nil, nil
	}
	var steps []EscalationStep
	if err := json.Unmarshal([]byte(raw), &steps); err != nil {
		return nil, fmt.Errorf("escalation_steps: invalid JSON: %w", err)
	}
	if len(steps) == 0 {
		return nil, nil
	}
	if len(steps) > 10 {
		return nil, fmt.Errorf("escalation_steps: at most 10 steps (got %d)", len(steps))
	}
	if !sort.SliceIsSorted(steps, func(i, j int) bool { return steps[i].AfterMinutes < steps[j].AfterMinutes }) {
		return nil, fmt.Errorf("escalation_steps: after_minutes must be strictly ascending")
	}
	for i, st := range steps {
		if st.AfterMinutes < 1 {
			return nil, fmt.Errorf("escalation_steps[%d]: after_minutes must be ≥ 1", i)
		}
		if i > 0 && steps[i-1].AfterMinutes == st.AfterMinutes {
			return nil, fmt.Errorf("escalation_steps: after_minutes must be strictly ascending")
		}
		if len(st.Channels) == 0 {
			return nil, fmt.Errorf("escalation_steps[%d]: at least one channel required", i)
		}
		for _, ch := range st.Channels {
			if !validEscalationChannels[ch] {
				return nil, fmt.Errorf("escalation_steps[%d]: unknown channel %q", i, ch)
			}
		}
	}
	return steps, nil
}

// stepNotifyConfig builds a NotifyConfig that routes to EXACTLY the step's
// channels: global credentials, policy URLs where set, and only the step's
// enables on. PolicyActive=true makes the eligibility checks honor the
// explicit routing (including the hard-gated incident channels).
func stepNotifyConfig(step EscalationStep, resolved ResolvedAlertConfig, globalNC notifier.NotifyConfig) notifier.NotifyConfig {
	// Start from the policy-shaped config (URLs/recipients/creds threaded),
	// then override the channel enables with the step's exact set.
	nc := BuildNotifyConfigFromResolved(resolved, globalNC)
	nc.PolicyActive = true
	nc.EnableEmail, nc.EnableSlack, nc.EnableDiscord, nc.EnableWebhook = false, false, false, false
	nc.EnablePagerDuty, nc.EnableOpsgenie, nc.EnableTeams = false, false, false
	for _, ch := range step.Channels {
		switch ch {
		case "email":
			nc.EnableEmail = true
		case "slack":
			nc.EnableSlack = true
		case "discord":
			nc.EnableDiscord = true
		case "webhook":
			nc.EnableWebhook = true
		case "pagerduty":
			nc.EnablePagerDuty = true
		case "opsgenie":
			nc.EnableOpsgenie = true
		case "teams":
			nc.EnableTeams = true
		}
	}
	if step.Recipients != "" {
		nc.SMTPTo = step.Recipients
	}
	return nc
}
