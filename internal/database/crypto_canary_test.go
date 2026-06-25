package database

import "testing"

// TestVerifyEncryptionKey covers the M8 key-check value: a fresh database
// establishes the canary, an unchanged key keeps verifying, a rotated key with
// no history is reported broken, and adding the original key to the chain
// (ENCRYPTION_KEY_HISTORY) makes it verify again.
func TestVerifyEncryptionKey(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// First boot with a configured key — establishes the canary row.
	d.encKeys = keyChain{current: deriveKey("key-one")}
	if err := d.VerifyEncryptionKey(); err != nil {
		t.Fatalf("first verify (establish canary): %v", err)
	}
	if ok, detail := d.EncryptionVerified(); !ok {
		t.Fatalf("expected verified after establishing canary; detail=%q", detail)
	}

	// Second boot, same key — the stored canary must still decrypt.
	if err := d.VerifyEncryptionKey(); err != nil {
		t.Fatalf("second verify, unchanged key: %v", err)
	}
	if ok, _ := d.EncryptionVerified(); !ok {
		t.Fatal("expected verified with unchanged key")
	}

	// Key rotated/lost with no history — the canary no longer decrypts, which
	// is exactly when every {enc} secret in the DB is unreadable. Must be
	// reported broken so the daemons fail-fast and /health degrades.
	d.encKeys = keyChain{current: deriveKey("key-two")}
	if err := d.VerifyEncryptionKey(); err == nil {
		t.Fatal("expected error when the key no longer decrypts the canary")
	}
	if ok, detail := d.EncryptionVerified(); ok {
		t.Fatalf("expected NOT verified after key change; detail=%q", detail)
	}

	// Original key supplied via the legacy chain (ENCRYPTION_KEY_HISTORY) —
	// the canary decrypts again, matching the real secrets' decryptability.
	d.encKeys = keyChain{current: deriveKey("key-two"), legacy: [][]byte{deriveKey("key-one")}}
	if err := d.VerifyEncryptionKey(); err != nil {
		t.Fatalf("verify with original key in history: %v", err)
	}
	if ok, _ := d.EncryptionVerified(); !ok {
		t.Fatal("expected verified once the original key is in the chain")
	}
}

// TestVerifyEncryptionKey_DisabledWhenNoKey confirms that a deployment with no
// encryption key configured (dev/SQLite) is treated as verified — there are no
// {enc} secrets to protect, so it must not be reported broken.
func TestVerifyEncryptionKey_DisabledWhenNoKey(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.VerifyEncryptionKey(); err != nil {
		t.Fatalf("verify with no key configured: %v", err)
	}
	if ok, _ := d.EncryptionVerified(); !ok {
		t.Fatal("encryption disabled (no key) must report verified")
	}
}
