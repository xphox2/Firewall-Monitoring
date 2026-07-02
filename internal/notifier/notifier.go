package notifier

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/textproto"
	neturl "net/url"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
)

// Attachment represents an inline image for HTML emails.
type Attachment struct {
	ContentID string // e.g. "chart1" — referenced as cid:chart1 in HTML
	Data      []byte
	MIMEType  string // e.g. "image/png"
}

// SanitizeHeader strips CR and LF characters from a value so it cannot be
// folded into another SMTP/HTTP header. AUDIT-014 — every caller that
// constructs a header value from user/device-controlled input must run it
// through this helper. Strips bytes; does not encode. Callers that need
// non-ASCII (RFC 2047) should encode first, then sanitize.
func SanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

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
	// Per-channel enable flags from alert policy resolution.
	// When all are false and no policy is active, SendAlert falls through to
	// the legacy behaviour (check EmailEnabled / webhook URL presence).
	EnableEmail   bool
	EnableSlack   bool
	EnableDiscord bool
	EnableWebhook bool
	// PolicyActive indicates whether these flags came from a resolved policy.
	// When false, SendAlert uses the legacy global-config behaviour.
	PolicyActive bool
}

type Notifier struct {
	client *http.Client
}

func NewNotifier(cfg *config.Config) *Notifier {
	_ = cfg // retained for API compat; config is now passed per-call via NotifyConfig
	// AUDIT-020: webhooks dial an operator-supplied URL. Pin the dial to a
	// validated IP (SafeDialContext) so DNS rebinding can't redirect the
	// connection to a private/loopback/link-local target after the pre-flight
	// check passed. Clone DefaultTransport so proxy/TLS/idle-pool defaults are
	// preserved — we only override DialContext.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = httputil.SafeDialContext(10 * time.Second)
	return &Notifier{
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tr,
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

// channelEligibility decides which channels an alert should fan out to, given a
// config snapshot. A channel fires when its destination is configured (email
// enabled / webhook URL present) AND — when a policy is active — that policy
// enables the channel. With no active policy the legacy global-config behaviour
// applies (destination presence alone). Pure: extracted from SendAlert so the
// routing matrix is unit-testable without performing any sends.
func channelEligibility(nc NotifyConfig) (email, slack, discord, webhook bool) {
	email = nc.EmailEnabled && (!nc.PolicyActive || nc.EnableEmail)
	slack = nc.SlackWebhookURL != "" && (!nc.PolicyActive || nc.EnableSlack)
	discord = nc.DiscordWebhookURL != "" && (!nc.PolicyActive || nc.EnableDiscord)
	webhook = nc.WebHookURL != "" && (!nc.PolicyActive || nc.EnableWebhook)
	return
}

func (n *Notifier) SendAlert(alert *models.Alert, nc NotifyConfig) error {
	var errs []error

	sendEmail, sendSlack, sendDiscord, sendWebhook := channelEligibility(nc)

	if sendEmail {
		if err := n.sendEmail(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("email failed: %w", err))
		}
	}
	if sendSlack {
		if err := n.sendSlack(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("slack failed: %w", err))
		}
	}
	if sendDiscord {
		if err := n.sendDiscord(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("discord failed: %w", err))
		}
	}
	if sendWebhook {
		if err := n.sendWebhook(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("webhook failed: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}

	return nil
}

// buildEmailSubjectBody renders the plain-text alert email. Header-bound values
// (severity, alert type) are run through SanitizeHeader so a device-controlled
// string can't fold a new header into the Subject line (AUDIT-014). Pure —
// extracted from sendEmail for unit testing.
func buildEmailSubjectBody(alert *models.Alert) (subject, body string) {
	subject = fmt.Sprintf("[%s] Firewall Alert: %s",
		SanitizeHeader(string(alert.Severity)), SanitizeHeader(string(alert.AlertType)))
	body = fmt.Sprintf(`
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
	return subject, body
}

func (n *Notifier) sendEmail(alert *models.Alert, nc NotifyConfig) error {
	if nc.SMTPHost == "" {
		return nil
	}

	subject, body := buildEmailSubjectBody(alert)

	addr := fmt.Sprintf("%s:%d", nc.SMTPHost, nc.SMTPPort)

	var auth smtp.Auth
	if nc.SMTPUsername != "" {
		// CompoundAuth picks PLAIN or LOGIN based on server-advertised
		// AUTH mechanisms (v0.10.222, bundle J). Works against both
		// PLAIN-only and LOGIN-only submission servers.
		auth = CompoundAuth(nc.SMTPUsername, nc.SMTPPassword, nc.SMTPHost)
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

// severityToSlackColor maps an alert severity to the Slack attachment bar
// colour (hex). Unknown/info severities fall back to green.
func severityToSlackColor(sev models.Severity) string {
	switch sev {
	case "warning":
		return "#ff9800"
	case "critical":
		return "#f44336"
	default:
		return "#36a64f"
	}
}

// buildSlackPayload constructs the Slack incoming-webhook JSON body for an
// alert. Pure — extracted from sendSlack so the wire shape is locked by tests.
func buildSlackPayload(alert *models.Alert) map[string]interface{} {
	return map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  severityToSlackColor(alert.Severity),
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
}

func (n *Notifier) sendSlack(alert *models.Alert, nc NotifyConfig) error {
	return n.postJSON(nc.SlackWebhookURL, buildSlackPayload(alert))
}

// webhookHost extracts scheme://host from a webhook URL for safe logging.
//
// M14 of the 2026-07-01 audit: Slack incoming-webhook and Discord webhook URLs
// carry their AUTH TOKEN in the PATH (e.g. hooks.slack.com/services/T…/B…/<secret>,
// discord.com/api/webhooks/<id>/<token>). Any error that embeds the full URL —
// the non-2xx error below AND Go's *url.Error from client.Do, which stringifies
// the whole request URL — writes that secret to container logs on every failed
// send (hundreds of lines during an alert storm). We only ever log the host.
func webhookHost(rawURL string) string {
	if u, err := neturl.Parse(rawURL); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "webhook"
}

// postJSON marshals payload to JSON and POSTs it to url, returning an error on
// non-2xx status codes. Errors never include the full URL (M14) — only the host.
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
		// A *url.Error stringifies the full request URL (token and all) — redact
		// to the host and surface only the underlying cause.
		var uerr *neturl.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("webhook %s: %w", webhookHost(url), uerr.Err)
		}
		return fmt.Errorf("webhook %s: %w", webhookHost(url), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s returned status %d", webhookHost(url), resp.StatusCode)
	}
	return nil
}

// severityToDiscordColor maps an alert severity to the Discord embed colour
// (decimal RGB). Unknown/info severities fall back to green (3066993).
func severityToDiscordColor(sev models.Severity) int {
	switch sev {
	case "warning":
		return 15105570
	case "critical":
		return 15158332
	default:
		return 3066993
	}
}

// buildDiscordPayload constructs the Discord webhook JSON body for an alert.
// Pure — extracted from sendDiscord so the wire shape is locked by tests.
func buildDiscordPayload(alert *models.Alert) map[string]interface{} {
	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("Firewall Alert: %s", alert.AlertType),
				"description": alert.Message,
				"color":       severityToDiscordColor(alert.Severity),
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
}

func (n *Notifier) sendDiscord(alert *models.Alert, nc NotifyConfig) error {
	return n.postJSON(nc.DiscordWebhookURL, buildDiscordPayload(alert))
}

// buildWebhookPayload constructs the generic webhook JSON body for an alert.
// Pure — extracted from sendWebhook so the wire shape is locked by tests.
func buildWebhookPayload(alert *models.Alert) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":    alert.AlertType,
		"severity":      alert.Severity,
		"message":       alert.Message,
		"timestamp":     alert.Timestamp.Format(time.RFC3339),
		"metric_name":   alert.MetricName,
		"threshold":     alert.Threshold,
		"current_value": alert.CurrentValue,
	}
}

func (n *Notifier) sendWebhook(alert *models.Alert, nc NotifyConfig) error {
	return n.postJSON(nc.WebHookURL, buildWebhookPayload(alert))
}

// SendHTMLEmail sends an HTML email with optional inline image attachments.
// Builds a multipart/related MIME message with Content-ID references for images.
// If recipients is empty, falls back to nc.SMTPTo.
func (n *Notifier) SendHTMLEmail(subject, htmlBody string, attachments []Attachment, nc NotifyConfig, recipients string) error {
	if nc.SMTPHost == "" {
		return nil
	}
	if !nc.EmailEnabled {
		return nil
	}

	if recipients == "" {
		recipients = nc.SMTPTo
	}
	if recipients == "" {
		return fmt.Errorf("no recipients configured")
	}

	// Sanitize header values via the package-level SanitizeHeader so the
	// same rule applies to every caller (see also report.BuildCriticalAlertEmail).
	sanitize := SanitizeHeader

	var buf bytes.Buffer

	if len(attachments) == 0 {
		// No inline images → send a single text/html message instead of an
		// empty multipart/related wrapper. Compliant clients then show one
		// clean message with zero attachments (v0.10.236). UTF-8 HTML is sent
		// 8bit, which every modern submission server (8BITMIME) accepts.
		fmt.Fprintf(&buf, "From: %s\r\n", sanitize(nc.SMTPFrom))
		fmt.Fprintf(&buf, "To: %s\r\n", sanitize(recipients))
		fmt.Fprintf(&buf, "Subject: %s\r\n", sanitize(subject))
		fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
		fmt.Fprintf(&buf, "Content-Type: text/html; charset=UTF-8\r\n")
		fmt.Fprintf(&buf, "Content-Transfer-Encoding: 8bit\r\n")
		fmt.Fprintf(&buf, "\r\n")
		buf.WriteString(htmlBody)
	} else {
		writer := multipart.NewWriter(&buf)
		boundary := writer.Boundary()

		// Write top-level headers
		buf.Reset()
		fmt.Fprintf(&buf, "From: %s\r\n", sanitize(nc.SMTPFrom))
		fmt.Fprintf(&buf, "To: %s\r\n", sanitize(recipients))
		fmt.Fprintf(&buf, "Subject: %s\r\n", sanitize(subject))
		fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
		fmt.Fprintf(&buf, "Content-Type: multipart/related; boundary=%q\r\n", boundary)
		fmt.Fprintf(&buf, "\r\n")

		// HTML part
		htmlHeader := make(textproto.MIMEHeader)
		htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
		htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")
		htmlPart, err := writer.CreatePart(htmlHeader)
		if err != nil {
			return fmt.Errorf("failed to create HTML part: %w", err)
		}
		htmlPart.Write([]byte(htmlBody))

		// Inline image attachments
		for _, att := range attachments {
			attHeader := make(textproto.MIMEHeader)
			attHeader.Set("Content-Type", att.MIMEType)
			attHeader.Set("Content-Transfer-Encoding", "base64")
			attHeader.Set("Content-ID", "<"+att.ContentID+">")
			attHeader.Set("Content-Disposition", "inline")
			part, err := writer.CreatePart(attHeader)
			if err != nil {
				return fmt.Errorf("failed to create attachment part: %w", err)
			}
			encoded := base64.StdEncoding.EncodeToString(att.Data)
			// Write in 76-char lines per RFC 2045
			for i := 0; i < len(encoded); i += 76 {
				end := i + 76
				if end > len(encoded) {
					end = len(encoded)
				}
				part.Write([]byte(encoded[i:end]))
				part.Write([]byte("\r\n"))
			}
		}

		writer.Close()
	}

	addr := fmt.Sprintf("%s:%d", nc.SMTPHost, nc.SMTPPort)
	var auth smtp.Auth
	if nc.SMTPUsername != "" {
		// CompoundAuth picks PLAIN or LOGIN based on server-advertised
		// AUTH mechanisms (v0.10.222, bundle J). Works against both
		// PLAIN-only and LOGIN-only submission servers.
		auth = CompoundAuth(nc.SMTPUsername, nc.SMTPPassword, nc.SMTPHost)
	}

	recipientList := strings.Split(recipients, ",")
	for i := range recipientList {
		recipientList[i] = strings.TrimSpace(recipientList[i])
	}

	if err := smtp.SendMail(addr, auth, nc.SMTPFrom, recipientList, buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send HTML email: %w", err)
	}
	return nil
}
