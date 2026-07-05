package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// doSettingsRequest invokes a settings handler (GetSettings / UpdateSettings)
// with an optional JSON body and returns the recorder.
func doSettingsRequest(t *testing.T, h func(*gin.Context), method string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Handle(method, "/api/settings", h)

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req := httptest.NewRequest(method, "/api/settings", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// settingsSecretFixtures returns one real plaintext value per key in
// settingsSecretKeys and fails the test if the map has grown a key without a
// fixture — so every future secret is automatically pulled into these
// regressions instead of silently escaping coverage (the exact way LC-37/LC-38
// happened for the T2 keys).
func settingsSecretFixtures(t *testing.T) map[string]string {
	t.Helper()
	fixtures := map[string]string{
		"smtp_password":         "real-smtp-pass",
		"webhook_secret":        "real-webhook-signing-secret",
		"pagerduty_routing_key": "real-pd-routing-key",
		"opsgenie_api_key":      "real-og-api-key",
	}
	for k := range settingsSecretKeys {
		if _, ok := fixtures[k]; !ok {
			t.Fatalf("settingsSecretKeys gained %q without a fixture here — add one so the mask-skip and encrypt-at-rest regressions cover it", k)
		}
	}
	for k := range fixtures {
		if !settingsSecretKeys[k] {
			t.Fatalf("fixture key %q is not in settingsSecretKeys — remove it or reclassify", k)
		}
	}
	return fixtures
}

// TestUpdateSettings_MaskedSecretsNotWrittenBack_LC37 is the settings variant
// of the v0.10.324 SNMP-community writeback regression: GetSettings masks
// every settingsSecretKeys value as "********", the admin UI round-trips the
// mask on save, and the pre-fix UpdateSettings only skipped the mask for
// smtp_password — so one save of ANYTHING on the Settings page destroyed the
// stored PagerDuty routing key, Opsgenie API key, and webhook signing secret.
// This test resends the mask for EVERY secret key alongside one genuine edit
// and asserts all stored secrets survive byte-for-byte.
func TestUpdateSettings_MaskedSecretsNotWrittenBack_LC37(t *testing.T) {
	h, db := setupTestHandler(t)
	db.SetEncryptionKeyForTesting("lc37-test-key")
	real := settingsSecretFixtures(t)

	storedBefore := map[string]string{}
	for k, v := range real {
		row := models.SystemSetting{Key: k, Value: db.EncryptField(v), IsSecret: true}
		if err := db.Gorm().Create(&row).Error; err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
		storedBefore[k] = row.Value
	}

	// Simulate the UI round-trip: one genuine edit plus the mask for every
	// secret, exactly as GetSettings returned them.
	payload := []models.SystemSetting{{Key: "smtp_host", Value: "mail.example.com"}}
	for k := range real {
		payload = append(payload, models.SystemSetting{Key: k, Value: httputil.RedactedMask})
	}
	w := doSettingsRequest(t, h.UpdateSettings, "PUT", payload)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	// The genuine edit must apply.
	var host models.SystemSetting
	if err := db.Gorm().Where("\"key\" = ?", "smtp_host").First(&host).Error; err != nil {
		t.Fatalf("reload smtp_host: %v", err)
	}
	if host.Value != "mail.example.com" {
		t.Errorf("smtp_host = %q, want mail.example.com (the real edit must still apply)", host.Value)
	}

	// No secret may have been overwritten by the mask.
	for k, v := range real {
		var after models.SystemSetting
		if err := db.Gorm().Where("\"key\" = ?", k).First(&after).Error; err != nil {
			t.Fatalf("reload %s: %v", k, err)
		}
		if after.Value != storedBefore[k] {
			t.Errorf("%s overwritten by the mask:\n got            %q\n want unchanged %q", k, after.Value, storedBefore[k])
		}
		if got := db.DecryptField(after.Value); got != v {
			t.Errorf("decrypted %s = %q, want %q (the real secret must survive a redacted save)", k, got, v)
		}
	}
}

// TestUpdateSettings_SecretsEncryptedAtRest_LC38 pins the encrypted-at-rest
// contract for EVERY secret key: pre-fix, EncryptField was only reachable
// from inside the smtp_password switch case, so the T2 incident-channel
// secrets were stored plaintext while the AUDIT-026 comment promised
// "a future field added to BOTH [allowedKeys and secretKeys] is encrypted".
func TestUpdateSettings_SecretsEncryptedAtRest_LC38(t *testing.T) {
	h, db := setupTestHandler(t)
	db.SetEncryptionKeyForTesting("lc38-test-key")
	real := settingsSecretFixtures(t)

	var payload []models.SystemSetting
	for k, v := range real {
		payload = append(payload, models.SystemSetting{Key: k, Value: v})
	}
	w := doSettingsRequest(t, h.UpdateSettings, "PUT", payload)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	for k, v := range real {
		var row models.SystemSetting
		if err := db.Gorm().Where("\"key\" = ?", k).First(&row).Error; err != nil {
			t.Fatalf("reload %s: %v", k, err)
		}
		if !strings.HasPrefix(row.Value, "{enc}") {
			t.Errorf("%s stored WITHOUT the {enc} prefix (value %q) — secret persisted plaintext", k, row.Value)
		}
		if !row.IsSecret {
			t.Errorf("%s stored with is_secret=false", k)
		}
		if got := db.DecryptField(row.Value); got != v {
			t.Errorf("decrypted %s = %q, want %q", k, got, v)
		}
	}
}

// TestGetSettings_MasksEverySecretKey_LC37 pins the read half of the
// invariant: the exact set of keys whose masked value is skipped on write
// must be redacted on read. If a secret leaked here, the mask-skip on write
// would never see the mask and the invariant would silently rot.
func TestGetSettings_MasksEverySecretKey_LC37(t *testing.T) {
	h, db := setupTestHandler(t)
	db.SetEncryptionKeyForTesting("lc37-read-key")
	real := settingsSecretFixtures(t)

	for k, v := range real {
		row := models.SystemSetting{Key: k, Value: db.EncryptField(v), IsSecret: true}
		if err := db.Gorm().Create(&row).Error; err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	// A non-secret must NOT be masked.
	if err := db.Gorm().Create(&models.SystemSetting{Key: "smtp_host", Value: "mail.example.com"}).Error; err != nil {
		t.Fatalf("seed smtp_host: %v", err)
	}

	w := doSettingsRequest(t, h.GetSettings, "GET", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp struct {
		Data []models.SystemSetting `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	got := map[string]string{}
	for _, s := range resp.Data {
		got[s.Key] = s.Value
	}
	for k := range real {
		if got[k] != httputil.RedactedMask {
			t.Errorf("GET returned %q for secret %s, want the mask %q", got[k], k, httputil.RedactedMask)
		}
	}
	if got["smtp_host"] != "mail.example.com" {
		t.Errorf("GET returned %q for non-secret smtp_host, want the plain value", got["smtp_host"])
	}
}

// TestGetNotificationSetting_EnvFallback_LC39 is the regression for the
// Test-button/delivery split: real alert delivery runs off the env-seeded
// config (PAGERDUTY_ROUTING_KEY, OPSGENIE_API_KEY, TEAMS_WEBHOOK_URL,
// WEBHOOK_SECRET), but getNotificationSetting's env fallback stopped at the
// pre-T2 channel set — so env-only deployments delivered production alerts
// while the admin Test buttons reported "not configured" and the F18 test
// signature was skipped. DB-non-empty-wins / env-fallback must hold for the
// T2 keys exactly like the slack/discord/webhook_url precedent.
func TestGetNotificationSetting_EnvFallback_LC39(t *testing.T) {
	h, db := setupTestHandler(t)
	h.config.Alerts.PagerDutyRoutingKey = "env-pd-key"
	h.config.Alerts.OpsgenieAPIKey = "env-og-key"
	h.config.Alerts.TeamsWebhookURL = "https://outlook.office.com/webhook/env"
	h.config.Alerts.WebhookSecret = "env-signing-secret"

	envWant := map[string]string{
		"pagerduty_routing_key": "env-pd-key",
		"opsgenie_api_key":      "env-og-key",
		"teams_webhook":         "https://outlook.office.com/webhook/env",
		"webhook_secret":        "env-signing-secret",
	}
	// No DB rows → the env value must win (pre-fix this returned "").
	for k, want := range envWant {
		if got := h.getNotificationSetting(k); got != want {
			t.Errorf("getNotificationSetting(%q) = %q, want env fallback %q", k, got, want)
		}
	}

	// A non-empty DB row must take precedence over env — the same
	// resolution order AlertManager.RefreshThresholds applies for delivery,
	// so test and delivery can never disagree.
	if err := db.Gorm().Create(&models.SystemSetting{
		Key: "pagerduty_routing_key", Value: db.EncryptField("db-pd-key"), IsSecret: true,
	}).Error; err != nil {
		t.Fatalf("seed pagerduty_routing_key: %v", err)
	}
	if got := h.getNotificationSetting("pagerduty_routing_key"); got != "db-pd-key" {
		t.Errorf("getNotificationSetting(pagerduty_routing_key) = %q, want DB value db-pd-key to win over env", got)
	}
}

// TestGetNotificationSetting_LegacyPlaintextStillReadable_LC38 pins the
// read-compatibility half of the LC-38 fix: rows written plaintext by the
// pre-fix UpdateSettings must keep resolving (DecryptField is idempotent for
// non-{enc} values), because the at-rest upgrade happens lazily via the
// startup backfill, not synchronously on read.
func TestGetNotificationSetting_LegacyPlaintextStillReadable_LC38(t *testing.T) {
	h, db := setupTestHandler(t)
	db.SetEncryptionKeyForTesting("lc38-legacy-key")

	if err := db.Gorm().Create(&models.SystemSetting{
		Key: "webhook_secret", Value: "legacy-plaintext-secret", IsSecret: true,
	}).Error; err != nil {
		t.Fatalf("seed webhook_secret: %v", err)
	}
	if got := h.getNotificationSetting("webhook_secret"); got != "legacy-plaintext-secret" {
		t.Errorf("getNotificationSetting(webhook_secret) = %q, want the legacy plaintext value", got)
	}
}
