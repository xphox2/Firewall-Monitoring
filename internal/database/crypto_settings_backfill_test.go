package database

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// TestMigrateEncryptSecrets_UpgradesPlaintextSecretSettings is the LC-38
// (2026-07-04 audit) startup self-heal regression: system_settings rows for
// the incident-channel secrets written plaintext by the pre-fix
// UpdateSettings must be encrypted (and flagged is_secret) on the next
// startup, while already-encrypted rows, non-secret rows, and rows corrupted
// to the literal redaction mask are left untouched.
func TestMigrateEncryptSecrets_UpgradesPlaintextSecretSettings(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.encKeys = keyChain{current: deriveKey("backfill-test-key")}

	alreadyEncrypted := encryptField("already-encrypted-pass", d.encKeys.current)
	seed := []models.SystemSetting{
		{Key: "webhook_secret", Value: "legacy-wh-secret"},
		{Key: "pagerduty_routing_key", Value: "legacy-pd-key"},
		{Key: "opsgenie_api_key", Value: "legacy-og-key"},
		// Already migrated — must not be double-encrypted or otherwise touched.
		{Key: "smtp_password", Value: alreadyEncrypted, IsSecret: true},
		// Non-secret — must stay plaintext (AUDIT-026).
		{Key: "slack_webhook", Value: "https://hooks.slack.com/services/T000/B000/x"},
	}
	for i := range seed {
		if err := d.db.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed %s: %v", seed[i].Key, err)
		}
	}
	d.migrateEncryptSecrets()

	load := func(key string) models.SystemSetting {
		t.Helper()
		var s models.SystemSetting
		if err := d.db.Where("key = ?", key).First(&s).Error; err != nil {
			t.Fatalf("reload %s: %v", key, err)
		}
		return s
	}

	upgraded := map[string]string{
		"webhook_secret":        "legacy-wh-secret",
		"pagerduty_routing_key": "legacy-pd-key",
		"opsgenie_api_key":      "legacy-og-key",
	}
	for key, plain := range upgraded {
		row := load(key)
		if !strings.HasPrefix(row.Value, encPrefix) {
			t.Errorf("%s not upgraded: value %q lacks the %s prefix", key, row.Value, encPrefix)
		}
		if !row.IsSecret {
			t.Errorf("%s upgraded without is_secret=true", key)
		}
		if got := decryptFieldWithChain(row.Value, d.encKeys); got != plain {
			t.Errorf("decrypt(%s) = %q, want %q", key, got, plain)
		}
	}

	if row := load("smtp_password"); row.Value != alreadyEncrypted {
		t.Errorf("already-encrypted smtp_password was modified:\n got  %q\n want %q", row.Value, alreadyEncrypted)
	}
	if row := load("slack_webhook"); row.Value != "https://hooks.slack.com/services/T000/B000/x" {
		t.Errorf("non-secret slack_webhook was modified to %q — the backfill must only touch SecretSettingKeys", row.Value)
	}
}

// TestMigrateEncryptSecrets_SkipsMaskCorruptedRows pins the corrupted-row
// carve-out: a secret row holding the literal "********" mask (written by the
// pre-LC-37 save path) is left as-is so the operator can see the corruption
// and re-enter the credential, instead of the mask being encrypted into a
// plausible-looking {enc} blob.
func TestMigrateEncryptSecrets_SkipsMaskCorruptedRows(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.encKeys = keyChain{current: deriveKey("backfill-mask-key")}

	if err := d.db.Create(&models.SystemSetting{Key: "pagerduty_routing_key", Value: "********"}).Error; err != nil {
		t.Fatalf("seed masked row: %v", err)
	}

	d.migrateEncryptSecrets()

	var row models.SystemSetting
	if err := d.db.Where("key = ?", "pagerduty_routing_key").First(&row).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.Value != "********" {
		t.Errorf("mask-corrupted row was rewritten to %q; want the literal mask preserved for operator visibility", row.Value)
	}
}
