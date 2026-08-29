package handlers

import (
	"net/http"
	"strings"
	"testing"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
)

// AUDIT-249: per-policy Slack/Discord/generic webhook URLs are postable bearer
// credentials, yet the alert-policy GETs (viewer-visible) returned them in
// cleartext. Reads now mask them — and because the admin UI round-trips every
// field into a full-column Save, the write path must treat an incoming
// "********" as "unchanged", or the first save after masking landed would wipe
// every stored webhook (the documented mask-overwrite bug class).

// TestRedactAlertPolicy_MasksWebhookURLs_AUDIT249 pins the redaction unit:
// all three webhook URLs mask when set, empties stay empty (the UI treats ""
// as unset), and non-secret fields are untouched.
func TestRedactAlertPolicy_MasksWebhookURLs_AUDIT249(t *testing.T) {
	p := &models.AlertPolicy{
		Name:              "critical",
		EmailRecipients:   "noc@example.test",
		SlackWebhookURL:   "https://hooks.slack.example/T1/B1/tok",
		DiscordWebhookURL: "https://discord.example/api/webhooks/1/tok",
		WebhookURL:        "https://webhook.example/x",
	}
	httputil.RedactAlertPolicy(p)
	if p.SlackWebhookURL != httputil.RedactedMask {
		t.Errorf("slack_webhook_url = %q after redact, want mask", p.SlackWebhookURL)
	}
	if p.DiscordWebhookURL != httputil.RedactedMask {
		t.Errorf("discord_webhook_url = %q after redact, want mask", p.DiscordWebhookURL)
	}
	if p.WebhookURL != httputil.RedactedMask {
		t.Errorf("webhook_url = %q after redact, want mask", p.WebhookURL)
	}
	if p.Name != "critical" || p.EmailRecipients != "noc@example.test" {
		t.Errorf("non-secret fields must be untouched: %+v", p)
	}

	empty := &models.AlertPolicy{Name: "no-webhooks"}
	httputil.RedactAlertPolicy(empty)
	if empty.SlackWebhookURL != "" || empty.DiscordWebhookURL != "" || empty.WebhookURL != "" {
		t.Errorf("empty webhook fields must stay empty (mask means 'a secret exists'): %+v", empty)
	}
}

// TestListAlertPolicies_MasksWebhookURLs_AUDIT249: the viewer-visible listing
// carries the mask, never the live URL.
func TestListAlertPolicies_MasksWebhookURLs_AUDIT249(t *testing.T) {
	h, db := setupTestHandler(t)
	const realURL = "https://hooks.slack.example/T9/B9/list-tok"
	if err := db.Gorm().Create(&models.AlertPolicy{Name: "p-list", SlackWebhookURL: realURL}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/admin/api/alert-policies", "")
	h.ListAlertPolicies(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), realURL) {
		t.Error("live webhook URL leaked through ListAlertPolicies (AUDIT-249)")
	}
	if !strings.Contains(rec.Body.String(), httputil.RedactedMask) {
		t.Errorf("masked webhook missing from listing; body = %s", rec.Body.String())
	}
}

// TestUpdateAlertPolicy_MaskedWebhookPreserved_AUDIT249 is the write-back
// regression (the shape of TestUpdateDevice_RedactedCommunityNotWrittenBack):
// the admin UI GETs masked values, round-trips them on save, and
// db.UpdateAlertPolicy is a full-column Save — a masked PUT must preserve the
// stored URLs while the genuine edit applies.
func TestUpdateAlertPolicy_MaskedWebhookPreserved_AUDIT249(t *testing.T) {
	h, db := setupTestHandler(t)
	const (
		slackURL   = "https://hooks.slack.example/T1/B1/keep-me"
		discordURL = "https://discord.example/api/webhooks/2/keep-me"
		genericURL = "https://webhook.example/keep-me"
	)
	policy := &models.AlertPolicy{
		Name:              "p-masked",
		SlackWebhookURL:   slackURL,
		DiscordWebhookURL: discordURL,
		WebhookURL:        genericURL,
	}
	if err := db.Gorm().Create(policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// Simulate the admin UI round-trip: rename, resend the masks verbatim.
	w := doPartialUpdateRequest(t, h.UpdateAlertPolicy, "/api/alert-policies/:id", policy.ID,
		map[string]interface{}{
			"name":                "p-masked-renamed",
			"slack_webhook_url":   httputil.RedactedMask,
			"discord_webhook_url": httputil.RedactedMask,
			"webhook_url":         httputil.RedactedMask,
		})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	// The save response is a read too — it must not hand the live URLs back.
	if strings.Contains(w.Body.String(), slackURL) {
		t.Error("PUT response leaked the live webhook URL")
	}

	var after models.AlertPolicy
	if err := db.Gorm().First(&after, policy.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Name != "p-masked-renamed" {
		t.Errorf("name = %q, want p-masked-renamed (the real edit must still apply)", after.Name)
	}
	if after.SlackWebhookURL != slackURL {
		t.Errorf("slack webhook overwritten by the mask: got %q, want %q", after.SlackWebhookURL, slackURL)
	}
	if after.DiscordWebhookURL != discordURL {
		t.Errorf("discord webhook overwritten by the mask: got %q, want %q", after.DiscordWebhookURL, discordURL)
	}
	if after.WebhookURL != genericURL {
		t.Errorf("generic webhook overwritten by the mask: got %q, want %q", after.WebhookURL, genericURL)
	}
}

// TestUpdateAlertPolicy_RealWebhookStillUpdates_AUDIT249 is the companion
// guard: a genuine new URL replaces the stored one, and an explicit "" clears
// it — the preserve-on-write must not make the fields read-only.
func TestUpdateAlertPolicy_RealWebhookStillUpdates_AUDIT249(t *testing.T) {
	h, db := setupTestHandler(t)
	policy := &models.AlertPolicy{
		Name:            "p-real",
		SlackWebhookURL: "https://hooks.slack.example/T1/B1/old",
		WebhookURL:      "https://webhook.example/old",
	}
	if err := db.Gorm().Create(policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	w := doPartialUpdateRequest(t, h.UpdateAlertPolicy, "/api/alert-policies/:id", policy.ID,
		map[string]interface{}{
			"name":              "p-real",
			"slack_webhook_url": "https://hooks.slack.example/T1/B1/new",
			"webhook_url":       "", // operator clears the generic webhook
		})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	var after models.AlertPolicy
	if err := db.Gorm().First(&after, policy.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.SlackWebhookURL != "https://hooks.slack.example/T1/B1/new" {
		t.Errorf("a real webhook update was dropped: got %q", after.SlackWebhookURL)
	}
	if after.WebhookURL != "" {
		t.Errorf("clearing a webhook with \"\" must still work: got %q", after.WebhookURL)
	}
}

// TestCreateAlertPolicy_RejectsLiteralMask_AUDIT249: on create there is no
// stored value to preserve, so a literal mask can only be a client bug —
// storing it would make "********" the live webhook URL.
func TestCreateAlertPolicy_RejectsLiteralMask_AUDIT249(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodPost, "/admin/api/alert-policies",
		`{"name":"p-new","slack_webhook_url":"`+httputil.RedactedMask+`"}`)
	h.CreateAlertPolicy(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a literal mask on create (body = %s)", rec.Code, rec.Body.String())
	}
}
