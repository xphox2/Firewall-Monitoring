package database

import (
	"strings"
	"testing"
)

// TestDecryptFieldWithChain_LegacyKeyRotated_AUDIT009 — the core AUDIT-009
// regression: encrypt with key A, then operator rotates so current=B and
// legacy=[A]. The chain must still decrypt the old ciphertext via A.
//
// Without the chain support (pre-AUDIT) every {enc} row encrypted under
// key A would be permanently unreadable after the rotation.
func TestDecryptFieldWithChain_LegacyKeyRotated_AUDIT009(t *testing.T) {
	keyA := deriveKey("old-key-version-1")
	keyB := deriveKey("new-key-version-2")

	// Encrypted while keyA was current.
	ct := encryptField("super-secret-smtp-password", keyA)
	if !strings.HasPrefix(ct, encPrefix) {
		t.Fatal("setup: ciphertext missing prefix")
	}

	// Decrypt with rotated chain: current=B, legacy=[A].
	chain := keyChain{current: keyB, legacy: [][]byte{keyA}}
	got := decryptFieldWithChain(ct, chain)
	if got != "super-secret-smtp-password" {
		t.Errorf("decryptFieldWithChain after rotation: got %q, want %q", got, "super-secret-smtp-password")
	}
}

// TestDecryptFieldWithChain_CurrentKeyTriedFirst — when both current and
// legacy keys could decrypt (encrypted with current), current is tried
// first and succeeds — legacy keys are not tried for that ciphertext.
// We can only assert this by behavior: if the current key works, the
// result is right.
func TestDecryptFieldWithChain_CurrentKeyTriedFirst(t *testing.T) {
	keyA := deriveKey("k-a")
	keyB := deriveKey("k-b")

	ct := encryptField("payload", keyB) // encrypted by what will become current
	chain := keyChain{current: keyB, legacy: [][]byte{keyA}}
	got := decryptFieldWithChain(ct, chain)
	if got != "payload" {
		t.Errorf("got %q, want payload", got)
	}
}

// TestDecryptFieldWithChain_AllKeysFailReturnsEmpty — exhausting every
// key in the chain returns "" (AUDIT-027 fail-closed contract still
// holds across the multi-key path).
func TestDecryptFieldWithChain_AllKeysFailReturnsEmpty(t *testing.T) {
	keyA := deriveKey("k-a")
	keyB := deriveKey("k-b")
	keyC := deriveKey("k-c")
	keyD := deriveKey("k-d") // none of the chain keys

	ct := encryptField("payload", keyD)
	chain := keyChain{current: keyA, legacy: [][]byte{keyB, keyC}}
	got := decryptFieldWithChain(ct, chain)
	if got != "" {
		t.Errorf("all keys wrong: got %q, want \"\" (AUDIT-027 fail-closed must hold even with chain)", got)
	}
}

// TestDecryptFieldWithChain_TriesAllLegacyKeysInOrder — multi-legacy
// chain. Encrypted with the SECOND legacy key — must be reached and used.
func TestDecryptFieldWithChain_TriesAllLegacyKeysInOrder(t *testing.T) {
	current := deriveKey("current")
	legacy1 := deriveKey("legacy-1")
	legacy2 := deriveKey("legacy-2")
	legacy3 := deriveKey("legacy-3")

	// Encrypted with legacy2 (the middle of the chain).
	ct := encryptField("middle-payload", legacy2)
	chain := keyChain{current: current, legacy: [][]byte{legacy1, legacy2, legacy3}}
	got := decryptFieldWithChain(ct, chain)
	if got != "middle-payload" {
		t.Errorf("got %q, want middle-payload (chain must try every legacy)", got)
	}
}

// TestDecryptFieldWithChain_NoKeysReturnsEmpty — empty chain → fail-closed
// (was previously the "len(key)==0" branch in single-key decryptField).
func TestDecryptFieldWithChain_NoKeysReturnsEmpty(t *testing.T) {
	ct := encryptField("payload", deriveKey("real"))
	got := decryptFieldWithChain(ct, keyChain{}) // empty chain
	if got != "" {
		t.Errorf("empty chain: got %q, want \"\"", got)
	}
}

// TestDecryptFieldWithChain_NonEncryptedPassThrough — legacy plaintext
// rule still applies through the chain.
func TestDecryptFieldWithChain_NonEncryptedPassThrough(t *testing.T) {
	chain := keyChain{current: deriveKey("k"), legacy: [][]byte{deriveKey("k2")}}
	got := decryptFieldWithChain("plain-text-no-prefix", chain)
	if got != "plain-text-no-prefix" {
		t.Errorf("got %q, want plain-text-no-prefix", got)
	}
}

// TestKeyChain_All_OrdersCurrentFirst
func TestKeyChain_All_OrdersCurrentFirst(t *testing.T) {
	cur := []byte{1}
	leg1 := []byte{2}
	leg2 := []byte{3}
	chain := keyChain{current: cur, legacy: [][]byte{leg1, leg2}}
	all := chain.all()
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	if all[0][0] != 1 {
		t.Errorf("all[0] = %v, want current first", all[0])
	}
	if all[1][0] != 2 || all[2][0] != 3 {
		t.Errorf("all = %v, legacy must be in order", all)
	}
}

// TestKeyChain_All_SkipsEmpty — empty keys in the chain are filtered out
// (defensive: empty entries in ENCRYPTION_KEY_HISTORY env shouldn't poison).
func TestKeyChain_All_SkipsEmpty(t *testing.T) {
	chain := keyChain{current: nil, legacy: [][]byte{{}, {1}, nil, {2}, {}}}
	all := chain.all()
	if len(all) != 2 {
		t.Errorf("len(all) = %d, want 2 (only non-empty legacy keys)", len(all))
	}
}

// TestKeyChain_HasAny
func TestKeyChain_HasAny(t *testing.T) {
	if (keyChain{}).hasAny() {
		t.Error("empty chain: hasAny=true, want false")
	}
	if !(keyChain{current: []byte{1}}).hasAny() {
		t.Error("current set: hasAny=false, want true")
	}
	if !(keyChain{legacy: [][]byte{{1}}}).hasAny() {
		t.Error("only legacy set: hasAny=false, want true")
	}
	if (keyChain{legacy: [][]byte{{}, nil}}).hasAny() {
		t.Error("only empty-legacy entries: hasAny=true, want false")
	}
}
