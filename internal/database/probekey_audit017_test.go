package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestHashProbeKey_AUDIT017 pins the hashing contract: prefixed, deterministic,
// idempotent, and never equal to the plaintext.
func TestHashProbeKey_AUDIT017(t *testing.T) {
	const plain = "abc123def456"
	h := HashProbeKey(plain)
	if !IsHashedProbeKey(h) {
		t.Fatalf("hash %q lacks the sha256: prefix", h)
	}
	if h == plain {
		t.Fatal("hash equals plaintext — key not actually hashed")
	}
	if HashProbeKey(plain) != h {
		t.Error("HashProbeKey not deterministic")
	}
	// SECURITY: HashProbeKey must ALWAYS hash, never pass an already-hashed
	// value through. Otherwise presenting the stored hash as a token would
	// re-hash to itself and authenticate (DB-leak → access). Idempotency for
	// the migration is provided by the IsHashedProbeKey guard, not here.
	if HashProbeKey(h) == h {
		t.Error("HashProbeKey returned an already-hashed value unchanged — presenting the stored hash as a token would authenticate")
	}
	if HashProbeKey("") != "" {
		t.Error("empty input must stay empty")
	}
	if IsHashedProbeKey(plain) {
		t.Error("a 64-char-ish plaintext must not be misidentified as hashed")
	}
}

// TestMigrateProbeKeysToHash_AUDIT017 verifies the startup migration hashes
// legacy plaintext keys (probe rows + their probe_registration_ settings), is
// idempotent, and — critically — keeps a live probe authenticatable: the
// original plaintext token still hashes to the stored value.
func TestMigrateProbeKeysToHash_AUDIT017(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate system_settings: %v", err)
	}

	const plain = "deadbeefcafe1234"
	p := &models.Probe{Name: "legacy", RegistrationKey: plain, ApprovalStatus: "approved"}
	if err := d.db.Create(p).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	if err := d.db.Create(&models.SystemSetting{
		Key: "probe_registration_" + plain, Value: "legacy", Type: "string", Category: "probes",
	}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	d.migrateProbeKeysToHash()

	var got models.Probe
	if err := d.db.First(&got, p.ID).Error; err != nil {
		t.Fatalf("reload probe: %v", err)
	}
	if got.RegistrationKey == plain {
		t.Fatal("probe row still holds the PLAINTEXT key after migration")
	}
	if got.RegistrationKey != HashProbeKey(plain) {
		t.Errorf("probe key = %q, want hash %q", got.RegistrationKey, HashProbeKey(plain))
	}

	var hashedCnt, plainCnt int64
	d.db.Model(&models.SystemSetting{}).Where("key = ?", "probe_registration_"+HashProbeKey(plain)).Count(&hashedCnt)
	d.db.Model(&models.SystemSetting{}).Where("key = ?", "probe_registration_"+plain).Count(&plainCnt)
	if hashedCnt != 1 {
		t.Errorf("registration setting not renamed to hashed key (count=%d)", hashedCnt)
	}
	if plainCnt != 0 {
		t.Errorf("plaintext-embedded registration setting still present (count=%d)", plainCnt)
	}

	// Idempotent: a second run must not double-hash.
	before := got.RegistrationKey
	d.migrateProbeKeysToHash()
	var again models.Probe
	d.db.First(&again, p.ID)
	if again.RegistrationKey != before {
		t.Errorf("second migration changed the key (double-hash): %q != %q", again.RegistrationKey, before)
	}

	// Live-probe safety: the collector keeps sending the original plaintext;
	// it must still hash to the stored value.
	if HashProbeKey(plain) != again.RegistrationKey {
		t.Error("original plaintext token no longer matches the stored hash — a live probe would be locked out")
	}
}
