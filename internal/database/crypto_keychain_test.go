package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

// legacyEncryptIndependently reproduces the pre-D-11 encryptField byte for
// byte WITHOUT using this package's helpers: AES-256-GCM under
// sha256(secret), "{enc}" + base64(nonce||ct). It stands in for the rows
// already sitting in production, so a regression in the shared helpers cannot
// mask a broken legacy read.
func legacyEncryptIndependently(t testing.TB, plaintext, secret string) string {
	t.Helper()
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	return "{enc}" + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil))
}

// TestDecryptFieldWithChain_LegacyKeyRotated_AUDIT009 — the core AUDIT-009
// regression: encrypt with key A, then operator rotates so current=B and
// history=[A]. The chain must still decrypt the old ciphertext via A — for
// BOTH the legacy {enc} format and the v2 {enc2} format.
func TestDecryptFieldWithChain_LegacyKeyRotated_AUDIT009(t *testing.T) {
	chain := newKeyChain("new-key-version-2", []string{"old-key-version-1"})
	for _, f := range cipherFormats {
		t.Run(f.name, func(t *testing.T) {
			// Encrypted while key A was current.
			ct := f.enc(t, "super-secret-smtp-password", deriveFieldKey("old-key-version-1"))
			if !strings.HasPrefix(ct, f.prefix) {
				t.Fatal("setup: ciphertext missing prefix")
			}
			if got := decryptFieldWithChain(ct, chain); got != "super-secret-smtp-password" {
				t.Errorf("decryptFieldWithChain after rotation: got %q, want %q", got, "super-secret-smtp-password")
			}
		})
	}
}

// TestDecryptFieldWithChain_HistoryKeyLegacyCiphertext — a production {enc}
// row written by a pre-D-11 binary under what is now an
// ENCRYPTION_KEY_HISTORY entry (built with the independent legacy
// algorithm) still decrypts through the chain.
func TestDecryptFieldWithChain_HistoryKeyLegacyCiphertext(t *testing.T) {
	ct := legacyEncryptIndependently(t, "ipsec-psk-from-old-key", "retired-key")
	chain := newKeyChain("current-key", []string{"other-old-key", "retired-key"})
	if got := decryptFieldWithChain(ct, chain); got != "ipsec-psk-from-old-key" {
		t.Fatalf("history-key {enc} row: got %q", got)
	}
}

// TestDecryptFieldWithChain_CurrentKeyTriedFirst — when both current and
// legacy keys could decrypt (encrypted with current), current is tried
// first and succeeds.
func TestDecryptFieldWithChain_CurrentKeyTriedFirst(t *testing.T) {
	chain := newKeyChain("k-b", []string{"k-a"})
	for _, f := range cipherFormats {
		ct := f.enc(t, "payload", chain.current)
		if got := decryptFieldWithChain(ct, chain); got != "payload" {
			t.Errorf("%s: got %q, want payload", f.name, got)
		}
	}
}

// TestDecryptFieldWithChain_AllKeysFailReturnsEmpty — exhausting every
// key in the chain returns "" (AUDIT-027 fail-closed contract still
// holds across the multi-key path).
func TestDecryptFieldWithChain_AllKeysFailReturnsEmpty(t *testing.T) {
	chain := newKeyChain("k-a", []string{"k-b", "k-c"})
	for _, f := range cipherFormats {
		ct := f.enc(t, "payload", deriveFieldKey("k-d")) // none of the chain keys
		if got := decryptFieldWithChain(ct, chain); got != "" {
			t.Errorf("%s: all keys wrong: got %q, want \"\" (AUDIT-027 fail-closed must hold even with chain)", f.name, got)
		}
	}
}

// TestDecryptFieldWithChain_TriesAllLegacyKeysInOrder — multi-legacy
// chain. Encrypted with the SECOND legacy key — must be reached and used.
func TestDecryptFieldWithChain_TriesAllLegacyKeysInOrder(t *testing.T) {
	chain := newKeyChain("current", []string{"legacy-1", "legacy-2", "legacy-3"})
	for _, f := range cipherFormats {
		ct := f.enc(t, "middle-payload", deriveFieldKey("legacy-2"))
		if got := decryptFieldWithChain(ct, chain); got != "middle-payload" {
			t.Errorf("%s: got %q, want middle-payload (chain must try every legacy)", f.name, got)
		}
	}
}

// TestDecryptFieldWithChain_NoKeysReturnsEmpty — empty chain → fail-closed.
func TestDecryptFieldWithChain_NoKeysReturnsEmpty(t *testing.T) {
	for _, f := range cipherFormats {
		ct := f.enc(t, "payload", deriveFieldKey("real"))
		if got := decryptFieldWithChain(ct, keyChain{}); got != "" {
			t.Errorf("%s: empty chain: got %q, want \"\"", f.name, got)
		}
	}
}

// TestDecryptFieldWithChain_NonEncryptedPassThrough — legacy plaintext
// rule still applies through the chain.
func TestDecryptFieldWithChain_NonEncryptedPassThrough(t *testing.T) {
	chain := newKeyChain("k", []string{"k2"})
	got := decryptFieldWithChain("plain-text-no-prefix", chain)
	if got != "plain-text-no-prefix" {
		t.Errorf("got %q, want plain-text-no-prefix", got)
	}
}

// TestNewKeyChain_DerivesBothKeysPerEntry — every chain entry carries the
// legacy sha256 key AND the HKDF key, so both formats work for current and
// history alike.
func TestNewKeyChain_DerivesBothKeysPerEntry(t *testing.T) {
	chain := newKeyChain("cur", []string{"", "old"})
	if len(chain.legacy) != 1 {
		t.Fatalf("legacy entries = %d, want 1 (empty history entries skipped)", len(chain.legacy))
	}
	for i, k := range append([]fieldKey{chain.current}, chain.legacy...) {
		if len(k.v1) != 32 || len(k.v2) != 32 {
			t.Fatalf("entry %d: v1 %d bytes, v2 %d bytes, want 32/32", i, len(k.v1), len(k.v2))
		}
	}
	want := sha256.Sum256([]byte("old"))
	if string(chain.legacy[0].v1) != string(want[:]) {
		t.Fatal("legacy derivation is no longer sha256(secret): every existing {enc} row would break")
	}
	if !(newKeyChain("", nil)).current.empty() {
		t.Fatal("empty secret must give an empty current key")
	}
}

// TestKeyChain_All_OrdersCurrentFirst
func TestKeyChain_All_OrdersCurrentFirst(t *testing.T) {
	chain := keyChain{current: fieldKey{v2: []byte{1}}, legacy: []fieldKey{{v2: []byte{2}}, {v1: []byte{3}}}}
	all := chain.all()
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	if all[0].v2[0] != 1 {
		t.Errorf("all[0] = %v, want current first", all[0])
	}
	if all[1].v2[0] != 2 || all[2].v1[0] != 3 {
		t.Errorf("all = %v, legacy must be in order", all)
	}
}

// TestKeyChain_All_SkipsEmpty — empty keys in the chain are filtered out
// (defensive: empty entries in ENCRYPTION_KEY_HISTORY env shouldn't poison).
func TestKeyChain_All_SkipsEmpty(t *testing.T) {
	chain := keyChain{legacy: []fieldKey{{}, {v1: []byte{1}}, {v1: nil, v2: nil}, {v2: []byte{2}}, {}}}
	if all := chain.all(); len(all) != 2 {
		t.Errorf("len(all) = %d, want 2 (only non-empty legacy keys)", len(all))
	}
}

// TestKeyChain_HasAny
func TestKeyChain_HasAny(t *testing.T) {
	if (keyChain{}).hasAny() {
		t.Error("empty chain: hasAny=true, want false")
	}
	if !(keyChain{current: fieldKey{v2: []byte{1}}}).hasAny() {
		t.Error("current set: hasAny=false, want true")
	}
	if !(keyChain{legacy: []fieldKey{{v1: []byte{1}}}}).hasAny() {
		t.Error("only legacy set: hasAny=false, want true")
	}
	if (keyChain{legacy: []fieldKey{{}, {v1: []byte{}}}}).hasAny() {
		t.Error("only empty-legacy entries: hasAny=true, want false")
	}
}

// TestDecryptFieldWithChain_UnwrapsRollbackDoubleWrap — after a rollback, a
// pre-D-11 binary's startup backfill sees an {enc2} SNMP/IRC/settings value as
// plaintext and wraps it: {enc}({enc2}…). Re-upgrading must still recover the
// original secret.
func TestDecryptFieldWithChain_UnwrapsRollbackDoubleWrap(t *testing.T) {
	const secret = "rollback-key"
	inner := mustEncrypt(t, "real-community", deriveFieldKey(secret))
	wrapped := legacyEncryptIndependently(t, inner, secret) // what the old backfill writes
	if got := decryptFieldWithChain(wrapped, newKeyChain(secret, nil)); got != "real-community" {
		t.Fatalf("double-wrapped value: got %q, want the original secret", got)
	}
	// A genuine {enc} value is not affected.
	if got := decryptFieldWithChain(legacyEncryptIndependently(t, "plain-old", secret), newKeyChain(secret, nil)); got != "plain-old" {
		t.Fatalf("plain legacy value: got %q", got)
	}
}
