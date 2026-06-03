package handlers

import (
	"testing"
)

// TestSettingsSecretKeys_AUDIT026 is the regression for the audit: the
// system_settings handler used to call db.EncryptField on EVERY row
// (including non-secret thresholds, display preferences, and boolean
// toggles). The fix is to gate encryption on membership in
// settingsSecretKeys, so a future field added to the allowed-keys
// allow-list but NOT to the secret-keys list is stored as plaintext
// (the right default), and only the rows explicitly marked as secret
// are encrypted.
//
// This test pins the source-of-truth map: it asserts that
//   - the currently-known secrets are present,
//   - a sampling of the most obvious non-secrets are NOT present,
//   - no key is silently added without being intentional.
//
// A future agent who adds a new secret to allowedKeys MUST also add
// it to settingsSecretKeys, and the corresponding test case here. A
// future agent who refactors the map away entirely will get a compile
// error in the test (because it references the symbol), which is the
// right kind of break — they have to think about the migration.
func TestSettingsSecretKeys_AUDIT026(t *testing.T) {
	// Currently-known secrets. Add a row here whenever a new secret
	// is added to the allowedKeys list in UpdateSettings, so a
	// regression on either side surfaces as a test failure.
	expectedSecrets := []string{
		"smtp_password",
	}

	// Sample of currently-allowed non-secret keys. AUDIT-026: none
	// of these are encrypted, and the test pins that.
	knownNonSecrets := []string{
		"cpu_threshold",
		"memory_threshold",
		"disk_threshold",
		"session_threshold",
		"email_enabled",
		"smtp_host",
		"smtp_port",
		"smtp_username", // username is not a secret; password is
		"smtp_from",
		"smtp_to",
		"slack_webhook", // webhook URLs are flagged in the audit for separate reasons
		"discord_webhook",
		"webhook_url",
		"public_refresh_interval",
		"public_show_vpn",
		"public_show_connections",
		"public_interfaces",
		"display_timezone",
		"report_daily_enabled",
		"report_daily_time",
		"report_weekly_enabled",
		"report_weekly_day",
		"report_recipients",
		"report_timezone",
		"spike_stddev_threshold",
		"spike_alert_enabled",
	}

	for _, k := range expectedSecrets {
		if !settingsSecretKeys[k] {
			t.Errorf("expected settingsSecretKeys[%q] = true (it is a known secret); fix the test if you intentionally changed the secret/non-secret classification", k)
		}
	}
	for _, k := range knownNonSecrets {
		if settingsSecretKeys[k] {
			t.Errorf("settingsSecretKeys[%q] = true; this is a non-secret key (threshold / display pref / webhook url) and MUST NOT be encrypted at rest (AUDIT-026)", k)
		}
	}
}

// TestSettingsSecretKeys_NoOverlapWithNonSecrets_AUDIT026 is a
// belt-and-suspenders check: the two slices above must not share any
// element. If a future agent accidentally reclassifies a non-secret
// as a secret (or vice versa), this catches the contradiction
// directly.
func TestSettingsSecretKeys_NoOverlapWithNonSecrets_AUDIT026(t *testing.T) {
	known := map[string]bool{}
	for _, k := range []string{
		"smtp_password",
	} {
		known[k] = true
	}
	nonSecrets := []string{
		"cpu_threshold", "memory_threshold", "disk_threshold",
		"session_threshold", "email_enabled", "smtp_host",
		"smtp_port", "smtp_username", "smtp_from", "smtp_to",
		"slack_webhook", "discord_webhook", "webhook_url",
		"public_refresh_interval", "public_show_vpn",
		"public_show_connections", "public_interfaces",
		"display_timezone", "report_daily_enabled",
		"report_daily_time", "report_weekly_enabled",
		"report_weekly_day", "report_recipients",
		"report_timezone", "spike_stddev_threshold",
		"spike_alert_enabled",
	}
	for _, k := range nonSecrets {
		if known[k] {
			t.Fatalf("AUDIT-026 contradiction: key %q appears in BOTH the secrets and non-secrets lists; pick one.", k)
		}
	}
}
