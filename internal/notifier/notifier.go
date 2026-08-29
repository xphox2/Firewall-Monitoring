package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
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
	// WebhookSecret signs generic-webhook payloads (F18). Empty = unsigned.
	WebhookSecret string
	// Incident channels (T2-5): global credentials; presence = configured.
	PagerDutyRoutingKey string
	OpsgenieAPIKey      string
	TeamsWebhookURL     string
	EnablePagerDuty     bool
	EnableOpsgenie      bool
	EnableTeams         bool
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
	// BaseURL is the externally-reachable base URL (PUBLIC_BASE_URL) used to build
	// clickable "view alert" deep-links in notifications. Empty = omit the link.
	BaseURL string
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
		EmailEnabled:        cfg.EmailEnabled,
		SMTPHost:            cfg.SMTPHost,
		SMTPPort:            cfg.SMTPPort,
		SMTPUsername:        cfg.SMTPUsername,
		SMTPPassword:        cfg.SMTPPassword,
		SMTPFrom:            cfg.SMTPFrom,
		SMTPTo:              cfg.SMTPTo,
		SlackWebhookURL:     cfg.SlackWebhookURL,
		DiscordWebhookURL:   cfg.DiscordWebhookURL,
		WebHookURL:          cfg.WebHookURL,
		WebhookSecret:       cfg.WebhookSecret,
		PagerDutyRoutingKey: cfg.PagerDutyRoutingKey,
		OpsgenieAPIKey:      cfg.OpsgenieAPIKey,
		TeamsWebhookURL:     cfg.TeamsWebhookURL,
		BaseURL:             cfg.PublicBaseURL,
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

// incidentChannelEligibility mirrors channelEligibility for the T2-5 channels.
// The incident channels are policy-gated HARD: with no active policy they stay
// off (unlike the legacy channels' presence-only fallback) — paging a human is
// an explicit routing decision, not a default.
func incidentChannelEligibility(nc NotifyConfig) (pagerduty, opsgenie, teams bool) {
	pagerduty = nc.PagerDutyRoutingKey != "" && nc.PolicyActive && nc.EnablePagerDuty
	opsgenie = nc.OpsgenieAPIKey != "" && nc.PolicyActive && nc.EnableOpsgenie
	teams = nc.TeamsWebhookURL != "" && nc.PolicyActive && nc.EnableTeams
	return
}

func (n *Notifier) SendAlert(alert *models.Alert, nc NotifyConfig) error {
	var errs []error

	sendEmail, sendSlack, sendDiscord, sendWebhook := channelEligibility(nc)
	sendPD, sendOG, sendTeams := incidentChannelEligibility(nc)

	if sendPD {
		if err := n.sendPagerDuty(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("pagerduty failed: %w", err))
		}
	}
	if sendOG {
		if err := n.sendOpsgenie(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("opsgenie failed: %w", err))
		}
	}
	if sendTeams {
		if err := n.sendTeams(alert, nc); err != nil {
			errs = append(errs, fmt.Errorf("teams failed: %w", err))
		}
	}

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

// alertContextLines returns the "Device: <name> @ Site: <site>" and
// "View: <url>" lines for an alert, omitting whatever isn't populated. Shared by
// the text-oriented channels so every alert says WHERE it came from and links to
// its detail view.
func alertContextLines(alert *models.Alert) []string {
	var out []string
	switch {
	case alert.DeviceName != "" && alert.SiteName != "":
		out = append(out, "Device: "+alert.DeviceName+" @ Site: "+alert.SiteName)
	case alert.DeviceName != "":
		out = append(out, "Device: "+alert.DeviceName)
	case alert.SiteName != "":
		out = append(out, "Site: "+alert.SiteName)
	}
	if alert.DetailURL != "" {
		out = append(out, "View: "+alert.DetailURL)
	}
	return out
}

// buildEmailSubjectBody renders the plain-text alert email. Header-bound values
// (severity, alert type, and the device/site names appended to the Subject) are
// run through SanitizeHeader so a device-controlled string can't fold a new
// header into the Subject line (AUDIT-014). Pure — extracted for unit testing.
func buildEmailSubjectBody(alert *models.Alert) (subject, body string) {
	subject = fmt.Sprintf("[%s] Firewall Alert: %s",
		SanitizeHeader(string(alert.Severity)), SanitizeHeader(string(alert.AlertType)))
	if alert.DeviceName != "" {
		who := SanitizeHeader(alert.DeviceName)
		if alert.SiteName != "" {
			who += " @ " + SanitizeHeader(alert.SiteName)
		}
		subject += " — " + who
	}
	var ctx string
	for _, l := range alertContextLines(alert) {
		ctx += l + "\n"
	}
	body = fmt.Sprintf(`
Firewall Monitoring Alert
===========================

Type: %s
Severity: %s
Time: %s
%sMessage: %s

Metric: %s
Current Value: %.2f
Threshold: %.2f

This is an automated alert from your Firewall monitoring system.
`, alert.AlertType, alert.Severity, alert.Timestamp.Format(time.RFC3339),
		ctx, alert.Message, alert.MetricName, alert.CurrentValue, alert.Threshold)
	return subject, body
}

// smtpSendTimeout bounds the ENTIRE SMTP conversation (dial + greeting + EHLO +
// STARTTLS + AUTH + DATA + QUIT). AUDIT C1/AL-H1: net/smtp.SendMail sets no I/O
// deadline, and every alert email is sent synchronously on the poller's single
// monitoring goroutine — an SMTP host that accepts the TCP connection then
// stalls (half-open NAT, hung MTA, blackhole) would otherwise wedge the whole
// monitoring loop forever (the supervisor only restarts on panic, not on hang).
// A var (not const) so tests can shorten it.
var smtpSendTimeout = 30 * time.Second

// sendMailWithDeadline is a drop-in replacement for smtp.SendMail that bounds
// the whole exchange with an absolute deadline. It replicates the stdlib's
// dial→hello→STARTTLS(if advertised)→AUTH(if configured)→MAIL→RCPT→DATA→QUIT
// sequence exactly (so STARTTLS/CompoundAuth behaviour is unchanged); the only
// difference is the dial timeout and the connection deadline.
// dialFunc matches net.Dialer.DialContext and httputil.SafeDialContext's return.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// sendMailWithDeadline sends over TCP with a single absolute deadline. dial is
// optional: nil dials the host directly (a plain net.Dialer) — the correct
// behaviour for the alert/scheduled-report paths, which legitimately target an
// admin-configured internal-relay IP. AUDIT M1: the guarded, admin-triggered
// endpoints (test-email, manual send-report) pass an SSRF-pinning dialer so a
// DNS-rebinding host can't be redirected to an internal address after the
// isValidExternalIP pre-check.
func sendMailWithDeadline(addr, host string, auth smtp.Auth, from string, to []string, msg []byte, dial dialFunc) error {
	// One absolute deadline covers the whole exchange — dial AND every
	// subsequent read/write — so the total is bounded by smtpSendTimeout (not
	// dial-timeout + separate I/O-timeout).
	deadline := time.Now().Add(smtpSendTimeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	if dial == nil {
		var dialer net.Dialer
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Any subsequent read/write that stalls past the deadline fails instead of
	// blocking indefinitely.
	_ = conn.SetDeadline(deadline)

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Hello("firewall-mon"); err != nil {
		return err
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return err
			}
		} else {
			return errors.New("smtp: server doesn't support AUTH")
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// splitRecipients splits a comma-separated recipient list into trimmed,
// non-empty addresses. Shared by the alert email path and the HTML/report path
// so the two cannot drift (AUDIT-209): sendEmail used to hand the RAW comma
// string to the envelope as a single RCPT TO, which multi-recipient relays
// reject outright — every alert email to more than one address failed while
// the scheduled reports (which always split) kept delivering.
func splitRecipients(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (n *Notifier) sendEmail(alert *models.Alert, nc NotifyConfig) error {
	if nc.SMTPHost == "" {
		return nil
	}
	rcpts := splitRecipients(nc.SMTPTo)
	if len(rcpts) == 0 {
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

	// The To: HEADER deliberately keeps the raw comma-separated string — a
	// valid RFC 5322 address-list; only the ENVELOPE recipients are split.
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		nc.SMTPFrom, nc.SMTPTo, subject, body)

	err := sendMailWithDeadline(addr, nc.SMTPHost, auth, nc.SMTPFrom,
		rcpts, []byte(msg), nil)

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
	fields := []map[string]interface{}{
		{"title": "Severity", "value": alert.Severity, "short": true},
		{"title": "Time", "value": alert.Timestamp.Format(time.RFC3339), "short": true},
	}
	if alert.DeviceName != "" {
		fields = append(fields, map[string]interface{}{"title": "Device", "value": alert.DeviceName, "short": true})
	}
	if alert.SiteName != "" {
		fields = append(fields, map[string]interface{}{"title": "Site", "value": alert.SiteName, "short": true})
	}
	text := alert.Message
	if alert.DetailURL != "" {
		text += "\n<" + alert.DetailURL + "|View alert>"
	}
	return map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  severityToSlackColor(alert.Severity),
				"title":  fmt.Sprintf("Firewall Alert: %s", alert.AlertType),
				"text":   text,
				"footer": "Firewall Monitor",
				"ts":     alert.Timestamp.Unix(),
				"fields": fields,
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
	// Drain to EOF before Close (LIFO defer order) so the keep-alive connection
	// returns to the idle pool instead of re-dialing per alert (AUDIT C2).
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()

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
	fields := []map[string]interface{}{
		{"name": "Severity", "value": alert.Severity, "inline": true},
	}
	if alert.DeviceName != "" {
		fields = append(fields, map[string]interface{}{"name": "Device", "value": alert.DeviceName, "inline": true})
	}
	if alert.SiteName != "" {
		fields = append(fields, map[string]interface{}{"name": "Site", "value": alert.SiteName, "inline": true})
	}
	desc := alert.Message
	if alert.DetailURL != "" {
		desc += "\n[View alert](" + alert.DetailURL + ")"
	}
	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("Firewall Alert: %s", alert.AlertType),
				"description": desc,
				"color":       severityToDiscordColor(alert.Severity),
				"timestamp":   alert.Timestamp.Format(time.RFC3339),
				"footer": map[string]interface{}{
					"text": "Firewall Monitor",
				},
				"fields": fields,
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
		// Identity + deep link so downstream automation knows WHERE and can link.
		"device_id":   alert.DeviceID,
		"device_name": alert.DeviceName,
		"site_name":   alert.SiteName,
		"url":         alert.DetailURL,
	}
}

func (n *Notifier) sendWebhook(alert *models.Alert, nc NotifyConfig) error {
	return n.PostJSONSigned(nc.WebHookURL, buildWebhookPayload(alert), nc.WebhookSecret)
}

// SignWebhookPayload computes the F18 signature headers over ts+"."+body:
// receivers verify with hmac.Equal(hex(HMAC-SHA256(secret, ts+"."+body)), sig).
// Binding the timestamp into the MAC (and sending it in a header) lets the
// receiver reject replays older than its tolerance window.
func SignWebhookPayload(body []byte, secret, ts string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// PostJSONSigned posts payload like postJSON and, when secret is non-empty,
// adds X-FirewallMon-Timestamp + X-FirewallMon-Signature (F18). Exported so
// the settings test-webhook endpoint sends exactly what production sends.
func (n *Notifier) PostJSONSigned(url string, payload interface{}, secret string) error {
	var headers map[string]string
	if secret != "" {
		headers = map[string]string{"__sign__": secret}
	}
	return n.postJSONWithHeaders(url, payload, headers)
}

// postJSONWithHeaders is the shared POST core: JSON body, optional extra
// headers (the reserved "__sign__" pseudo-header triggers F18 signing), SSRF-
// guarded client, host-only error redaction (M14).
func (n *Notifier) postJSONWithHeaders(url string, payload interface{}, headers map[string]string) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if k == "__sign__" {
			ts := fmt.Sprintf("%d", time.Now().Unix())
			req.Header.Set("X-FirewallMon-Timestamp", ts)
			req.Header.Set("X-FirewallMon-Signature", SignWebhookPayload(jsonData, v, ts))
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		var uerr *neturl.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("webhook %s: %w", webhookHost(url), uerr.Err)
		}
		return fmt.Errorf("webhook %s: %w", webhookHost(url), err)
	}
	defer resp.Body.Close()
	// Drain to EOF before Close (LIFO defer order) for keep-alive reuse (AUDIT C2).
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s returned status %d", webhookHost(url), resp.StatusCode)
	}
	return nil
}

// writeQPPart adds one quoted-printable text part to a multipart writer.
func writeQPPart(w *multipart.Writer, contentType, body string) error {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", contentType)
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := w.CreatePart(h)
	if err != nil {
		return fmt.Errorf("create %s part: %w", contentType, err)
	}
	qp := quotedprintable.NewWriter(part)
	if _, err := qp.Write([]byte(body)); err != nil {
		return fmt.Errorf("write %s part: %w", contentType, err)
	}
	return qp.Close()
}

// writeAlternative adds a nested multipart/alternative (plaintext BEFORE
// html — last child is the preferred rendering per RFC 2046).
func writeAlternative(w *multipart.Writer, textBody, htmlBody string) error {
	inner := multipart.NewWriter(io.Discard)
	boundary := inner.Boundary()
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", boundary))
	part, err := w.CreatePart(h)
	if err != nil {
		return fmt.Errorf("create alternative part: %w", err)
	}
	alt := multipart.NewWriter(part)
	if err := alt.SetBoundary(boundary); err != nil {
		return err
	}
	if err := writeQPPart(alt, "text/plain; charset=UTF-8", textBody); err != nil {
		return err
	}
	if err := writeQPPart(alt, "text/html; charset=UTF-8", htmlBody); err != nil {
		return err
	}
	return alt.Close()
}

// writeInlineImages appends the CID image siblings under a multipart/related.
func writeInlineImages(w *multipart.Writer, attachments []Attachment) error {
	for _, att := range attachments {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", att.MIMEType)
		h.Set("Content-Transfer-Encoding", "base64")
		// Sanitized: CIDs are currently hardcoded, but if one is ever derived
		// from a device/interface name a CRLF must not forge part headers.
		cid := SanitizeHeader(att.ContentID)
		// Angle brackets in the header, none in the HTML's cid: reference —
		// the exact-match pair every client requires.
		h.Set("Content-ID", "<"+cid+">")
		h.Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", cid+".png"))
		part, err := w.CreatePart(h)
		if err != nil {
			return fmt.Errorf("create attachment part: %w", err)
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
	return nil
}

// buildMIMEMessage assembles the complete message bytes. The canonical tree
// (RFC 2387; what Gmail's own composer emits):
//
//	with images:                          without images:
//	multipart/related;                    multipart/alternative
//	  type="multipart/alternative"          ├─ text/plain (QP)
//	  ├─ multipart/alternative              └─ text/html  (QP)
//	  │   ├─ text/plain (QP)
//	  │   └─ text/html  (QP)
//	  └─ image/png… (base64, Content-ID, inline)
//
// A blank textBody degrades to the pre-plaintext shapes (bare text/html, or
// related-over-html). Both text parts are quoted-printable — the previous
// no-attachment 8bit path (v0.10.236) is retired deliberately: uniform QP
// removes the >998-char raw-line risk and matches the attachment path that
// carried the L7 audit fix. Pure function; unit-tested by parsing the output.
func buildMIMEMessage(from, to, subject, textBody, htmlBody string, attachments []Attachment) ([]byte, error) {
	sanitize := SanitizeHeader
	var buf bytes.Buffer
	writeTop := func(contentType string) {
		fmt.Fprintf(&buf, "From: %s\r\n", sanitize(from))
		fmt.Fprintf(&buf, "To: %s\r\n", sanitize(to))
		// Sanitize (strip CR/LF) THEN RFC 2047 Q-encode: subjects carry
		// non-ASCII (em dashes, device names) which is 5322-non-conformant
		// raw; QEncoding passes pure-ASCII strings through unchanged.
		fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", sanitize(subject)))
		fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
		fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	}

	switch {
	case len(attachments) == 0 && textBody == "":
		writeTop("text/html; charset=UTF-8")
		fmt.Fprintf(&buf, "Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		qp := quotedprintable.NewWriter(&buf)
		if _, err := qp.Write([]byte(htmlBody)); err != nil {
			return nil, fmt.Errorf("write html body: %w", err)
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}

	case len(attachments) == 0:
		w := multipart.NewWriter(&buf)
		writeTop(fmt.Sprintf("multipart/alternative; boundary=%q", w.Boundary()))
		fmt.Fprintf(&buf, "\r\n")
		if err := writeQPPart(w, "text/plain; charset=UTF-8", textBody); err != nil {
			return nil, err
		}
		if err := writeQPPart(w, "text/html; charset=UTF-8", htmlBody); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}

	default:
		w := multipart.NewWriter(&buf)
		if textBody == "" {
			// Legacy shape: related directly over html + images.
			writeTop(fmt.Sprintf("multipart/related; boundary=%q; type=\"text/html\"", w.Boundary()))
			fmt.Fprintf(&buf, "\r\n")
			if err := writeQPPart(w, "text/html; charset=UTF-8", htmlBody); err != nil {
				return nil, err
			}
			if err := writeInlineImages(w, attachments); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			break
		}
		writeTop(fmt.Sprintf("multipart/related; boundary=%q; type=\"multipart/alternative\"", w.Boundary()))
		fmt.Fprintf(&buf, "\r\n")
		if err := writeAlternative(w, textBody, htmlBody); err != nil {
			return nil, err
		}
		if err := writeInlineImages(w, attachments); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// SendHTMLEmail sends an HTML email with a plaintext alternative and optional
// inline CID image attachments (multipart/related > multipart/alternative —
// see buildMIMEMessage). textBody may be blank (legacy HTML-only shape).
// If recipients is empty, falls back to nc.SMTPTo.
func (n *Notifier) SendHTMLEmail(subject, textBody, htmlBody string, attachments []Attachment, nc NotifyConfig, recipients string) error {
	// nil dialer = plain net.Dialer: alert + scheduled-report sends legitimately
	// reach an admin-configured (possibly internal-relay) SMTP host.
	return n.sendHTMLEmail(subject, textBody, htmlBody, attachments, nc, recipients, nil)
}

// SendHTMLEmailPinned is SendHTMLEmail with SSRF-pinned dialing (AUDIT M1): the
// resolved SMTP IP is validated and dialed directly so a DNS-rebinding host
// can't be redirected to an internal address between the caller's
// isValidExternalIP pre-check and the send. Only the guarded, admin-triggered
// "send report now" endpoint uses this.
func (n *Notifier) SendHTMLEmailPinned(subject, textBody, htmlBody string, attachments []Attachment, nc NotifyConfig, recipients string) error {
	return n.sendHTMLEmail(subject, textBody, htmlBody, attachments, nc, recipients, httputil.SafeDialContext(smtpSendTimeout))
}

func (n *Notifier) sendHTMLEmail(subject, textBody, htmlBody string, attachments []Attachment, nc NotifyConfig, recipients string, dial dialFunc) error {
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

	msg, err := buildMIMEMessage(nc.SMTPFrom, recipients, subject, textBody, htmlBody, attachments)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", nc.SMTPHost, nc.SMTPPort)
	var auth smtp.Auth
	if nc.SMTPUsername != "" {
		// CompoundAuth picks PLAIN or LOGIN based on server-advertised
		// AUTH mechanisms (v0.10.222, bundle J). Works against both
		// PLAIN-only and LOGIN-only submission servers.
		auth = CompoundAuth(nc.SMTPUsername, nc.SMTPPassword, nc.SMTPHost)
	}

	recipientList := splitRecipients(recipients)

	if err := sendMailWithDeadline(addr, nc.SMTPHost, auth, nc.SMTPFrom, recipientList, msg, dial); err != nil {
		return fmt.Errorf("failed to send HTML email: %w", err)
	}
	return nil
}
