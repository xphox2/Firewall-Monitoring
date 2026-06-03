package database

import (
	"strings"
	"testing"
)

// TestDecryptField_RoundTrip locks in the basic invariant: encrypting a
// plaintext and immediately decrypting it with the same key yields the
// original plaintext.
//
// AUDIT-027 also explicitly requested a "startup round-trip test" so a
// future change to the cipher / key derivation / padding can never silently
// break every existing {enc} value in the wild.
func TestDecryptField_RoundTrip(t *testing.T) {
	key := deriveKey("test-secret-please-do-not-use-in-prod")

	cases := []string{
		"",
		"a",
		"hello world",
		"SuperSecret!@#$%^&*()_+-=",
		strings.Repeat("x", 4096),
		"unicode \u26a0\ufe0f \u4f60\u597d",
		"contains\nnewlines\r\nand\ttabs",
	}
	for _, want := range cases {
		name := want
		if len(name) > 20 {
			name = name[:20]
		}
		t.Run(name, func(t *testing.T) {
			ct := encryptField(want, key)
			if want == "" {
				if ct != "" {
					t.Fatalf("encryptField(\"\") = %q, want \"\" (empty stays empty)", ct)
				}
				return
			}
			if !strings.HasPrefix(ct, encPrefix) {
				t.Fatalf("encryptField(%q) missing %q prefix: %q", want, encPrefix, ct)
			}
			got := decryptField(ct, key)
			if got != want {
				t.Errorf("round-trip mismatch: got %q, want %q", got, want)
			}
		})
	}
}

// TestDecryptField_LegacyPlaintextPassthrough — values without the {enc}
// prefix must be returned unchanged (idempotent for callers that decrypt
// unconditionally; v0.10.226 reasoning).
func TestDecryptField_LegacyPlaintextPassthrough(t *testing.T) {
	key := deriveKey("any-key")
	cases := []string{
		"plain text",
		"this-looks-like-but-isnt-encrypted",
		"enc}not-prefixed", // close but no prefix
		"{enc",             // partial prefix
		"{not-enc}xxx",     // wrong prefix
		"",                 // empty
	}
	for _, in := range cases {
		got := decryptField(in, key)
		if got != in {
			t.Errorf("decryptField(%q, key) = %q, want %q (legacy plaintext should pass through)", in, got, in)
		}
	}
}

// TestDecryptField_NoKeyReturnsEmpty — AUDIT-027: if the field IS encrypted
// (carries the {enc} prefix) but no key is available, the function must
// return "", not the literal ciphertext. Returning the ciphertext is the
// v0.10.226 bug class — Postfix logged the {enc}<base64> string verbatim
// when used as a password.
func TestDecryptField_NoKeyReturnsEmpty(t *testing.T) {
	key := deriveKey("the-real-key")
	ct := encryptField("super-secret-password", key)
	if !strings.HasPrefix(ct, encPrefix) {
		t.Fatalf("setup: ciphertext missing prefix")
	}

	got := decryptField(ct, nil)
	if got != "" {
		t.Errorf("decryptField with nil key returned %q, want \"\" (must never leak ciphertext as plaintext)", got)
	}
	got = decryptField(ct, []byte{})
	if got != "" {
		t.Errorf("decryptField with empty key returned %q, want \"\"", got)
	}
	if strings.HasPrefix(got, encPrefix) {
		t.Errorf("decryptField result %q still carries the {enc} prefix — caller would treat it as a password and leak it to the remote server", got)
	}
}

// TestDecryptField_WrongKeyReturnsEmpty — AUDIT-027's primary regression:
// gcm.Open auth failure (wrong key, tampered data, key rotation gone wrong)
// must NEVER fall back to returning the raw ciphertext.
func TestDecryptField_WrongKeyReturnsEmpty(t *testing.T) {
	originalKey := deriveKey("the-real-key")
	wrongKey := deriveKey("a-different-key")

	ct := encryptField("smtp-password", originalKey)
	if !strings.HasPrefix(ct, encPrefix) {
		t.Fatalf("setup: ciphertext missing prefix")
	}

	got := decryptField(ct, wrongKey)
	if got != "" {
		t.Errorf("decryptField with wrong key returned %q, want \"\" — this is the AUDIT-027 / v0.10.226 bug class", got)
	}
	if strings.HasPrefix(got, encPrefix) {
		t.Fatalf("decryptField returned the ciphertext itself (%q) — exactly the bug AUDIT-027 forbids", got)
	}
}

// TestDecryptField_BadBase64ReturnsEmpty — malformed payloads must not leak.
func TestDecryptField_BadBase64ReturnsEmpty(t *testing.T) {
	key := deriveKey("any-key")
	cases := []string{
		encPrefix + "!!!not-valid-base64!!!",
		encPrefix + "AAAA===",
		encPrefix + "\x00\x01\x02",
		encPrefix + "////////\n\n\n",
	}
	for _, in := range cases {
		got := decryptField(in, key)
		if got != "" {
			t.Errorf("decryptField(%q) = %q, want \"\"", in, got)
		}
	}
}

// TestDecryptField_TamperedCiphertextReturnsEmpty — flip a byte in a valid
// ciphertext; GCM auth must fail and the function must return "".
func TestDecryptField_TamperedCiphertextReturnsEmpty(t *testing.T) {
	key := deriveKey("real-key")
	ct := encryptField("the-secret", key)

	// Flip the last char of the base64 segment. base64 alphabet is
	// [A-Za-z0-9+/=]; pick a swap that's guaranteed in-alphabet to ensure
	// we get past base64 decoding and hit the GCM auth check.
	body := ct[len(encPrefix):]
	if len(body) < 2 {
		t.Fatal("ciphertext too short to tamper")
	}
	swap := byte('A')
	if body[0] == 'A' {
		swap = 'B'
	}
	tampered := encPrefix + string(swap) + body[1:]

	got := decryptField(tampered, key)
	if got != "" {
		t.Errorf("decryptField on tampered ct returned %q, want \"\"", got)
	}
}

// TestDecryptField_ShortCiphertextReturnsEmpty — base64 that decodes to fewer
// bytes than the GCM nonce size must not panic and must return "".
func TestDecryptField_ShortCiphertextReturnsEmpty(t *testing.T) {
	key := deriveKey("real-key")
	// base64("abc") = "YWJj" → 3 raw bytes, < 12-byte GCM nonce
	got := decryptField(encPrefix+"YWJj", key)
	if got != "" {
		t.Errorf("decryptField(short ciphertext) = %q, want \"\"", got)
	}
}

// TestEncryptField_AlreadyEncryptedIsIdempotent — double-encrypt must be a
// no-op so a re-save never wraps the ciphertext twice.
func TestEncryptField_AlreadyEncryptedIsIdempotent(t *testing.T) {
	key := deriveKey("k")
	ct := encryptField("hello", key)
	ct2 := encryptField(ct, key)
	if ct != ct2 {
		t.Errorf("encryptField on already-encrypted value changed it: %q -> %q", ct, ct2)
	}
}

// TestEncryptField_EmptyOrNoKeyPassthrough — both cases must be no-ops so
// the unencrypted-defaults path of the app still works.
func TestEncryptField_EmptyOrNoKeyPassthrough(t *testing.T) {
	if got := encryptField("", deriveKey("k")); got != "" {
		t.Errorf("encryptField(\"\", key) = %q, want \"\"", got)
	}
	if got := encryptField("plain", nil); got != "plain" {
		t.Errorf("encryptField(\"plain\", nil) = %q, want \"plain\"", got)
	}
}
