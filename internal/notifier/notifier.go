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

type Notifier struct {
	config *config.Config
	client *http.Client
}

func NewNotifier(cfg *config.Config) *Notifier {
	return &Notifier{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) SendAlert(alert *models.Alert) error {
	var errs []error

	if n.config.Alerts.EmailEnabled {
		if err := n.sendEmail(alert); err != nil {
			errs = append(errs, fmt.Errorf("email failed: %w", err))
		}
	}

	if n.config.Alerts.SlackWebhookURL != "" {
		if err := n.sendSlack(alert); err != nil {
			errs = append(errs, fmt.Errorf("slack failed: %w", err))
		}
	}

	if n.config.Alerts.DiscordWebhookURL != "" {
		if err := n.sendDiscord(alert); err != nil {
			errs = append(errs, fmt.Errorf("discord failed: %w", err))
		}
	}

	if n.config.Alerts.WebHookURL != "" {
		if err := n.sendWebhook(alert); err != nil {
			errs = append(errs, fmt.Errorf("webhook failed: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}

	return nil
}

func (n *Notifier) sendEmail(alert *models.Alert) error {
	if n.config.Alerts.SMTPHost == "" {
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

	addr := fmt.Sprintf("%s:%d", n.config.Alerts.SMTPHost, n.config.Alerts.SMTPPort)

	var auth smtp.Auth
	if n.config.Alerts.SMTPUsername != "" {
		auth = smtp.PlainAuth("", n.config.Alerts.SMTPUsername, n.config.Alerts.SMTPPassword, n.config.Alerts.SMTPHost)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		n.config.Alerts.SMTPFrom, n.config.Alerts.SMTPTo, subject, body)

	err := smtp.SendMail(addr, auth, n.config.Alerts.SMTPFrom,
		[]string{n.config.Alerts.SMTPTo}, []byte(msg))

	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (n *Notifier) sendSlack(alert *models.Alert) error {
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

	return n.sendToSlackWebhook(payload)
}

func (n *Notifier) sendToSlackWebhook(payload map[string]interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", n.config.Alerts.SlackWebhookURL, bytes.NewBuffer(jsonData))
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
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (n *Notifier) sendDiscord(alert *models.Alert) error {
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

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", n.config.Alerts.DiscordWebhookURL, bytes.NewBuffer(jsonData))
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
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (n *Notifier) sendWebhook(alert *models.Alert) error {
	payload := map[string]interface{}{
		"alert_type":    alert.AlertType,
		"severity":      alert.Severity,
		"message":       alert.Message,
		"timestamp":     alert.Timestamp.Format(time.RFC3339),
		"metric_name":   alert.MetricName,
		"threshold":     alert.Threshold,
		"current_value": alert.CurrentValue,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", n.config.Alerts.WebHookURL, bytes.NewBuffer(jsonData))
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
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
