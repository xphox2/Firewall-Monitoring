package database

import (
	"errors"
	"fmt"
	"log"

	"gorm.io/gorm"

	"firewall-mon/internal/models"
)

// M8 — encryption key-check value (KCV).
//
// A rotated or lost ENCRYPTION_KEY makes every {enc} secret in the database
// silently undecryptable: decryptFieldWithChain returns "" (the AUDIT-027
// fail-closed contract), polling/notification quietly break, and the operator
// only notices hours later when devices drift offline. The dangerous part is
// that nothing surfaces the misconfiguration at startup.
//
// A self encrypt→decrypt round-trip does NOT detect this — it succeeds with
// ANY valid key. So we persist a key-check value: a fixed sentinel encrypted
// with the key the first time encryption is enabled. On every later startup we
// decrypt the stored ciphertext; if the key changed, it no longer decrypts to
// the sentinel — exactly when the database's real secrets are unreadable too.
const (
	encKeyCanaryKey       = "encryption_key_canary"
	encKeyCanaryPlaintext = "firewall-mon-encryption-canary-v1"
)

// VerifyEncryptionKey checks that the configured ENCRYPTION_KEY (plus any
// ENCRYPTION_KEY_HISTORY legacy keys) can still decrypt the secrets stored in
// this database, and caches the verdict for EncryptionVerified.
//
// The verdict drives two behaviours, decided by each binary:
//   - poller / trap-receiver fail-fast (they are useless without secrets);
//   - the API stays up but reports the failure on /health (/readyz), so an
//     operator can still reach the UI to fix ENCRYPTION_KEY / HISTORY.
//
// Only a genuine key mismatch marks the database broken. Infrastructure errors
// (can't read/write the canary row) are logged and returned but leave the
// verdict "not broken" — a transient DB hiccup right after a successful
// migration must not crash-loop the daemons or 503 the API.
func (d *Database) VerifyEncryptionKey() error {
	var setting models.SystemSetting
	err := d.db.Where("key = ?", encKeyCanaryKey).First(&setting).Error
	canaryMissing := errors.Is(err, gorm.ErrRecordNotFound)
	if err != nil && !canaryMissing {
		d.setEncStatus(false, fmt.Sprintf("encryption canary check skipped: %v", err))
		return fmt.Errorf("read encryption canary: %w", err)
	}

	if canaryMissing {
		if !d.encKeys.hasAny() {
			// No key configured and none ever was — encryption is disabled
			// (dev / SQLite). There are no {enc} secrets to protect.
			d.setEncStatus(false, "encryption disabled (no key configured)")
			return nil
		}
		// First run with a key: establish the KCV for every future startup.
		ct := encryptField(encKeyCanaryPlaintext, d.encKeys.current)
		if err := d.UpsertSetting(&models.SystemSetting{
			Key:      encKeyCanaryKey,
			Value:    ct,
			Type:     "string",
			Category: "system",
			IsSecret: true,
		}); err != nil {
			d.setEncStatus(false, fmt.Sprintf("encryption canary check skipped: %v", err))
			return fmt.Errorf("write encryption canary: %w", err)
		}
		d.setEncStatus(false, "encryption key verified (canary established)")
		return nil
	}

	// Canary present — it must decrypt to the sentinel with the current chain.
	if decryptFieldWithChain(setting.Value, d.encKeys) == encKeyCanaryPlaintext {
		d.setEncStatus(false, "encryption key verified")
		return nil
	}

	detail := "ENCRYPTION_KEY does not match the key that encrypted this database's secrets; " +
		"stored SNMP/SSH/IRC credentials are unreadable. Set ENCRYPTION_KEY back to the original " +
		"value, or add the previous key to ENCRYPTION_KEY_HISTORY to complete a rotation."
	d.setEncStatus(true, detail)
	log.Printf("ERROR: encryption key verification FAILED: %s", detail)
	return errors.New(detail)
}

// setEncStatus records the cached M8 verdict. broken=true means the key chain
// provably cannot decrypt this database's secrets.
func (d *Database) setEncStatus(broken bool, detail string) {
	d.encKeyBroken = broken
	d.encKeyDetail = detail
}

// EncryptionVerified reports the cached result of the startup
// VerifyEncryptionKey check (M8): whether the configured key chain can decrypt
// this database's secrets, plus a human-readable detail. The key is fixed for
// the process lifetime, so the startup verdict stays valid — health/readiness
// handlers read it without re-querying. The zero value (no check run, e.g. the
// SQLite test harness) reports verified=true.
func (d *Database) EncryptionVerified() (bool, string) {
	return !d.encKeyBroken, d.encKeyDetail
}
