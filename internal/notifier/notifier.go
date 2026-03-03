package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// NotifyConfig is a snapshot of notification-related configuration fields.
// It is passed by value to avoid data races with concurrent config updates.
type NotifyConfig struct {
	EmailEnabled      bool
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTo            string
	SlackWebhookURL   string
	DiscordWebhookURL string
	WebHookURL        string
}

type Notifier struct {
	client *http.Client
}

func NewNotifier(cfg *config.Config) *Notifier {
	_ = cfg // retained for API compat; config is now passed per-call via NotifyConfig
	return &Notifier{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SnapshotConfig creates a NotifyConfig snapshot from the given alerts config.
// The caller must hold any necessary locks when reading cfg.
func SnapshotConfig(cfg *config.AlertsConfig) NotifyConfig {
	return NotifyConfig{
		EmailEnabled:      cfg.EmailEnabled,
		SMTPHost:          cfg.SMTPHost,
		SMTPPort:          cfg.SMTPPort,
		SMTPUsername:      cfg.SMTPUsername,
		SMTPPassword:      cfg.SMTPPassword,
		SMTPFrom:          cfg.SMTPFrom,
		SMTPTo:            cfg.SMTPTo,
		SlackWebhookURL:   cfg.SlackWebhookURL,
		DiscordWebhookURL: cfg.DiscordWebhookURL,
		WebHookURL:        cfg.WebHookURL,
	}
}

func (n *Notifier) SendAlert(alert *models.Alert, nc NotifyConfig) error {
	var errs []error

	if nc.EmailEnabled {
		if err := n.sendEmail(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("email failed: %w", err))
		}
	}

	if nc.SlackWebhookURL != "" {
		if err := n.sendSlack(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("slack failed: %w", err))
		}
	}

	if nc.DiscordWebhookURL != "" {
		if err := n.sendDiscord(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("discord failed: %w", err))
		}
	}

	if nc.WebHookURL != "" {
		if err := n.sendWebhook(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("webhook failed: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}

	return nil
}

func (n *Notifier) sendEmail(alert *models.Alert, nc NotifyConfig) error {
	if nc.SMTPHost == "" {
		return nil
	}

	// Sanitize header values to prevent email header injection
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", "")
		return s
	}
	subject := fmt.Sprintf("[%s] Firewall Alert: %s", sanitize(alert.Severity), sanitize(alert.AlertType))
	body := fmt.Sprintf(`
Firewall Monitoring Alert
===========================

Type: %s
Severity: %s
Time: %s
Message: %s

Metric: %s
Current Value: %.2f
Threshold: %.2f

This is an automated alert from your Firewall monitoring system.
`, alert.AlertType, alert.Severity, alert.Timestamp.Format(time.RFC3339),
		alert.Message, alert.MetricName, alert.CurrentValue, alert.Threshold)

	addr := fmt.Sprintf("%s:%d", nc.SMTPHost, nc.SMTPPort)

	var auth smtp.Auth
	if nc.SMTPUsername != "" {
		auth = smtp.PlainAuth("", nc.SMTPUsername, nc.SMTPPassword, nc.SMTPHost)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		nc.SMTPFrom, nc.SMTPTo, subject, body)

	err := smtp.SendMail(addr, auth, nc.SMTPFrom,
		[]string{nc.SMTPTo}, []byte(msg))

	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (n *Notifier) sendSlack(alert *models.Alert, nc NotifyConfig) error {
	color := "#36a64f"
	if alert.Severity == "warning" {
		color = "#ff9800"
	} else if alert.Severity == "critical" {
		color = "#f44336"
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  fmt.Sprintf("Firewall Alert: %s", alert.AlertType),
				"text":   alert.Message,
				"footer": "Firewall Monitor",
				"ts":     alert.Timestamp.Unix(),
				"fields": []map[string]interface{}{
					{"title": "Severity", "value": alert.Severity, "short": true},
					{"title": "Time", "value": alert.Timestamp.Format(time.RFC3339), "short": true},
				},
			},
		},
	}

	return n.postJSON(nc.SlackWebhookURL, payload)
}

// postJSON marshals payload to JSON and POSTs it to url, returning an error on
// non-2xx status codes.
func (n *Notifier) postJSON(url string, payload interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s returned status %d", url, resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendDiscord(alert *models.Alert, nc NotifyConfig) error {
	color := 3066993
	if alert.Severity == "warning" {
		color = 15105570
	} else if alert.Severity == "critical" {
		color = 15158332
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("Firewall Alert: %s", alert.AlertType),
				"description": alert.Message,
				"color":       color,
				"timestamp":   alert.Timestamp.Format(time.RFC3339),
				"footer": map[string]interface{}{
					"text": "Firewall Monitor",
				},
				"fields": []map[string]interface{}{
					{"name": "Severity", "value": alert.Severity, "inline": true},
				},
			},
		},
	}

	return n.postJSON(nc.DiscordWebhookURL, payload)
}

func (n *Notifier) sendWebhook(alert *models.Alert, nc NotifyConfig) error {
	payload := map[string]interface{}{
		"alert_type":    alert.AlertType,
		"severity":      alert.Severity,
		"message":       alert.Message,
		"timestamp":     alert.Timestamp.Format(time.RFC3339),
		"metric_name":   alert.MetricName,
		"threshold":     alert.Threshold,
		"current_value": alert.CurrentValue,
	}

	return n.postJSON(nc.WebHookURL, payload)
}
