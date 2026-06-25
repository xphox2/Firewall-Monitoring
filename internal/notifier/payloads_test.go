package notifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

func sampleAlert() *models.Alert {
	return &models.Alert{
		Timestamp:    time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC),
		AlertType:    models.AlertType("CPU_HIGH"),
		Severity:     models.Severity("critical"),
		Message:      "CPU at 95%",
		MetricName:   "cpu",
		Threshold:    90,
		CurrentValue: 95,
	}
}

func TestSeverityToSlackColor(t *testing.T) {
	cases := map[models.Severity]string{
		"info":     "#36a64f",
		"warning":  "#ff9800",
		"critical": "#f44336",
		"unknown":  "#36a64f", // fallback
		"":         "#36a64f",
	}
	for sev, want := range cases {
		if got := severityToSlackColor(sev); got != want {
			t.Errorf("severityToSlackColor(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestSeverityToDiscordColor(t *testing.T) {
	cases := map[models.Severity]int{
		"info":     3066993,
		"warning":  15105570,
		"critical": 15158332,
		"unknown":  3066993, // fallback
	}
	for sev, want := range cases {
		if got := severityToDiscordColor(sev); got != want {
			t.Errorf("severityToDiscordColor(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestBuildSlackPayload(t *testing.T) {
	p := buildSlackPayload(sampleAlert())
	atts, ok := p["attachments"].([]map[string]interface{})
	if !ok || len(atts) != 1 {
		t.Fatalf("expected 1 attachment, got %#v", p["attachments"])
	}
	a := atts[0]
	if a["color"] != "#f44336" {
		t.Errorf("color = %v, want #f44336", a["color"])
	}
	if a["title"] != "Firewall Alert: CPU_HIGH" {
		t.Errorf("title = %v", a["title"])
	}
	if a["text"] != "CPU at 95%" {
		t.Errorf("text = %v", a["text"])
	}
	if want := sampleAlert().Timestamp.Unix(); a["ts"] != want {
		t.Errorf("ts = %v, want unix %d", a["ts"], want)
	}
	// Marshals to valid JSON (Slack incoming-webhook contract).
	if _, err := json.Marshal(p); err != nil {
		t.Fatalf("slack payload not JSON-marshalable: %v", err)
	}
}

func TestBuildDiscordPayload(t *testing.T) {
	p := buildDiscordPayload(sampleAlert())
	embeds, ok := p["embeds"].([]map[string]interface{})
	if !ok || len(embeds) != 1 {
		t.Fatalf("expected 1 embed, got %#v", p["embeds"])
	}
	e := embeds[0]
	if e["color"] != 15158332 {
		t.Errorf("color = %v, want 15158332", e["color"])
	}
	if e["description"] != "CPU at 95%" {
		t.Errorf("description = %v", e["description"])
	}
	if e["timestamp"] != "2026-06-25T12:00:00Z" {
		t.Errorf("timestamp = %v", e["timestamp"])
	}
	if _, err := json.Marshal(p); err != nil {
		t.Fatalf("discord payload not JSON-marshalable: %v", err)
	}
}

func TestBuildWebhookPayload(t *testing.T) {
	p := buildWebhookPayload(sampleAlert())
	if p["alert_type"] != models.AlertType("CPU_HIGH") {
		t.Errorf("alert_type = %v", p["alert_type"])
	}
	if p["timestamp"] != "2026-06-25T12:00:00Z" {
		t.Errorf("timestamp = %v", p["timestamp"])
	}
	if p["threshold"] != float64(90) {
		t.Errorf("threshold = %v", p["threshold"])
	}
	if p["current_value"] != float64(95) {
		t.Errorf("current_value = %v", p["current_value"])
	}
	if _, err := json.Marshal(p); err != nil {
		t.Fatalf("webhook payload not JSON-marshalable: %v", err)
	}
}

func TestBuildEmailSubjectBody(t *testing.T) {
	// Header-injection attempt in the alert type must not survive into Subject.
	a := sampleAlert()
	a.AlertType = models.AlertType("CPU_HIGH\r\nBcc: evil@example.com")
	subject, body := buildEmailSubjectBody(a)
	if strings.ContainsAny(subject, "\r\n") {
		t.Errorf("subject contains CR/LF (header injection): %q", subject)
	}
	if !strings.HasPrefix(subject, "[critical] Firewall Alert: CPU_HIGH") {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{"Current Value: 95.00", "Threshold: 90.00", "Metric: cpu"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n---\n%s", want, body)
		}
	}
}

func TestChannelEligibility(t *testing.T) {
	cases := []struct {
		name                        string
		nc                          NotifyConfig
		email, slack, disc, webhook bool
	}{
		{
			name:  "legacy: presence alone enables",
			nc:    NotifyConfig{EmailEnabled: true, SlackWebhookURL: "u", DiscordWebhookURL: "u", WebHookURL: "u"},
			email: true, slack: true, disc: true, webhook: true,
		},
		{
			name: "legacy: missing destinations stay off",
			nc:   NotifyConfig{EmailEnabled: false, SlackWebhookURL: ""},
		},
		{
			name:  "policy active gates each channel",
			nc:    NotifyConfig{PolicyActive: true, EmailEnabled: true, EnableEmail: false, SlackWebhookURL: "u", EnableSlack: true, DiscordWebhookURL: "u", EnableDiscord: false, WebHookURL: "u", EnableWebhook: true},
			email: false, slack: true, disc: false, webhook: true,
		},
		{
			name: "policy active but destination absent → off even if enabled",
			nc:   NotifyConfig{PolicyActive: true, SlackWebhookURL: "", EnableSlack: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, s, d, w := channelEligibility(tc.nc)
			if e != tc.email || s != tc.slack || d != tc.disc || w != tc.webhook {
				t.Errorf("got (e=%v s=%v d=%v w=%v), want (e=%v s=%v d=%v w=%v)",
					e, s, d, w, tc.email, tc.slack, tc.disc, tc.webhook)
			}
		})
	}
}

func TestSnapshotConfig(t *testing.T) {
	cfg := &config.AlertsConfig{
		EmailEnabled:      true,
		SMTPHost:          "smtp.example.com",
		SMTPPort:          587,
		SMTPUsername:      "u",
		SMTPPassword:      "p",
		SMTPFrom:          "from@example.com",
		SMTPTo:            "to@example.com",
		SlackWebhookURL:   "https://slack",
		DiscordWebhookURL: "https://discord",
		WebHookURL:        "https://hook",
	}
	nc := SnapshotConfig(cfg)
	if nc.SMTPHost != "smtp.example.com" || nc.SMTPPort != 587 || !nc.EmailEnabled {
		t.Errorf("snapshot did not copy SMTP fields: %+v", nc)
	}
	if nc.SlackWebhookURL != "https://slack" || nc.DiscordWebhookURL != "https://discord" || nc.WebHookURL != "https://hook" {
		t.Errorf("snapshot did not copy webhook URLs: %+v", nc)
	}
	// Snapshot is a value copy — mutating the source must not affect it.
	cfg.SMTPHost = "changed"
	if nc.SMTPHost != "smtp.example.com" {
		t.Error("snapshot aliased the source config")
	}
}

// TestSendAlertFanout drives the full SendAlert → sendX → postJSON path against
// an httptest server. A plain http.Client is injected (NewNotifier's
// SafeDialContext would refuse the loopback test server by design, AUDIT-020).
func TestSendAlertFanout(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing JSON content-type")
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body not JSON: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{client: srv.Client()}
	nc := NotifyConfig{
		SlackWebhookURL:   srv.URL,
		DiscordWebhookURL: srv.URL,
		WebHookURL:        srv.URL,
	}
	if err := n.SendAlert(sampleAlert(), nc); err != nil {
		t.Fatalf("SendAlert: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("expected 3 webhook POSTs (slack+discord+webhook), got %d", got)
	}
}

// TestSendAlertWebhookErrorPropagates confirms a non-2xx response surfaces as an
// error from SendAlert.
func TestSendAlertWebhookErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := &Notifier{client: srv.Client()}
	err := n.SendAlert(sampleAlert(), NotifyConfig{WebHookURL: srv.URL})
	if err == nil {
		t.Fatal("expected error from non-2xx webhook response")
	}
	if !strings.Contains(err.Error(), "webhook failed") {
		t.Errorf("error = %v, want it to mention webhook failure", err)
	}
}
