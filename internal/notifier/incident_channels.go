package notifier

import (
	"fmt"
	"strings"

	"firewall-mon/internal/models"
)

// Incident-management channels (v0.11 Tranche 2, T2-5): PagerDuty Events API
// v2, Opsgenie Alerts API, and Microsoft Teams incoming webhooks. All three
// post through the same SSRF-guarded client and host-redacted error paths as
// the existing channels. PagerDuty and Opsgenie are STATEFUL: alerts carry a
// deterministic dedup key, and the companion *_RESOLVED events resolve/close
// the incident instead of opening a new one.

const (
	pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"
	opsgenieAlertsURL  = "https://api.opsgenie.com/v2/alerts"
)

// alertDedupKey identifies one alert condition across fire and resolve.
func alertDedupKey(a *models.Alert) string {
	t := strings.TrimSuffix(string(a.AlertType), "_RESOLVED")
	return fmt.Sprintf("fwmon-%d-%s-%s", a.DeviceID, t, a.MetricName)
}

// isRecovery reports whether this alert is the companion recovery record.
func isRecovery(a *models.Alert) bool {
	return strings.HasSuffix(string(a.AlertType), "_RESOLVED")
}

// pagerDutySeverity maps our severities onto PD's {critical,error,warning,info}.
func pagerDutySeverity(sev models.Severity) string {
	switch sev {
	case "critical":
		return "critical"
	case "warning":
		return "warning"
	default:
		return "info"
	}
}

func buildPagerDutyPayload(alert *models.Alert, routingKey string) map[string]interface{} {
	action := "trigger"
	if isRecovery(alert) {
		action = "resolve"
	}
	p := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": action,
		"dedup_key":    alertDedupKey(alert),
	}
	if action == "trigger" {
		p["payload"] = map[string]interface{}{
			"summary":  fmt.Sprintf("[%s] %s", alert.AlertType, alert.Message),
			"source":   fmt.Sprintf("firewall-mon/device-%d", alert.DeviceID),
			"severity": pagerDutySeverity(alert.Severity),
			"class":    string(alert.AlertType),
			"custom_details": map[string]interface{}{
				"metric":        alert.MetricName,
				"threshold":     alert.Threshold,
				"current_value": alert.CurrentValue,
				"device_id":     alert.DeviceID,
			},
		}
	}
	return p
}

func (n *Notifier) sendPagerDuty(alert *models.Alert, nc NotifyConfig) error {
	return n.PostJSONSigned(pagerDutyEventsURL, buildPagerDutyPayload(alert, nc.PagerDutyRoutingKey), "")
}

// opsgeniePriority maps severity onto Opsgenie P1..P5.
func opsgeniePriority(sev models.Severity) string {
	switch sev {
	case "critical":
		return "P1"
	case "warning":
		return "P3"
	default:
		return "P5"
	}
}

func buildOpsgeniePayload(alert *models.Alert) map[string]interface{} {
	return map[string]interface{}{
		"message":  fmt.Sprintf("[%s] %s", alert.AlertType, alert.Message),
		"alias":    alertDedupKey(alert),
		"priority": opsgeniePriority(alert.Severity),
		"source":   "firewall-mon",
		"details": map[string]string{
			"metric":        alert.MetricName,
			"threshold":     fmt.Sprintf("%.2f", alert.Threshold),
			"current_value": fmt.Sprintf("%.2f", alert.CurrentValue),
			"device_id":     fmt.Sprintf("%d", alert.DeviceID),
		},
	}
}

func (n *Notifier) sendOpsgenie(alert *models.Alert, nc NotifyConfig) error {
	url := opsgenieAlertsURL
	var payload interface{}
	if isRecovery(alert) {
		// Close by alias: POST /v2/alerts/:alias/close?identifierType=alias
		url = fmt.Sprintf("%s/%s/close?identifierType=alias", opsgenieAlertsURL, alertDedupKey(alert))
		payload = map[string]string{"source": "firewall-mon", "note": alert.Message}
	} else {
		payload = buildOpsgeniePayload(alert)
	}
	return n.postJSONWithHeaders(url, payload, map[string]string{
		"Authorization": "GenieKey " + nc.OpsgenieAPIKey,
	})
}

// teamsColor maps severity to the MessageCard theme colour.
func teamsColor(sev models.Severity) string {
	switch sev {
	case "critical":
		return "E81123"
	case "warning":
		return "FFB900"
	default:
		return "107C10"
	}
}

func buildTeamsPayload(alert *models.Alert) map[string]interface{} {
	title := fmt.Sprintf("Firewall-Mon: %s", alert.AlertType)
	if isRecovery(alert) {
		title = fmt.Sprintf("Firewall-Mon: %s (resolved)", strings.TrimSuffix(string(alert.AlertType), "_RESOLVED"))
	}
	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": teamsColor(alert.Severity),
		"summary":    title,
		"title":      title,
		"text":       alert.Message,
		"sections": []map[string]interface{}{{
			"facts": []map[string]string{
				{"name": "Severity", "value": string(alert.Severity)},
				{"name": "Metric", "value": alert.MetricName},
				{"name": "Value", "value": fmt.Sprintf("%.2f (threshold %.2f)", alert.CurrentValue, alert.Threshold)},
				{"name": "Device", "value": fmt.Sprintf("%d", alert.DeviceID)},
			},
		}},
	}
}

func (n *Notifier) sendTeams(alert *models.Alert, nc NotifyConfig) error {
	return n.PostJSONSigned(nc.TeamsWebhookURL, buildTeamsPayload(alert), "")
}
