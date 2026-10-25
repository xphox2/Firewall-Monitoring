package database

import (
	"errors"
	"strings"
	"testing"
)

// mustEncrypt encrypts in the current ({enc2}) format, failing the test on
// error.
func mustEncrypt(t testing.TB, plaintext string, key fieldKey) string {
	t.Helper()
	ct, err := encryptField(plaintext, key)
	if err != nil {
		t.Fatalf("encryptField: %v", err)
	}
	return ct
}

// mustEncryptLegacy builds a pre-D-11 "{enc}" value (sha256-derived key).
func mustEncryptLegacy(t testing.TB, plaintext string, key fieldKey) string {
	t.Helper()
	ct, err := encryptFieldLegacy(plaintext, key)
	if err != nil {
		t.Fatalf("encryptFieldLegacy: %v", err)
	}
	return ct
}

// cipherFormats runs the decrypt contract tests against both wire formats:
// every guarantee (fail-closed, chain fallback) must hold for legacy {enc}
// rows already in production AND for new {enc2} rows.
var cipherFormats = []struct {
	name   string
	prefix string
	enc    func(testing.TB, string, fieldKey) string
}{
	{"enc2", enc2Prefix, mustEncrypt},
	{"enc-legacy", encPrefix, mustEncryptLegacy},
}

// TestDecryptField_RoundTrip locks in the basic invariant: encrypting a
// plaintext and immediately decrypting it with the same key yields the
// original plaintext.
//
// AUDIT-027 also explicitly requested a "startup round-trip test" so a
// future change to the cipher / key derivation / padding can never silently
// break every existing encrypted value in the wild.
func TestDecryptField_RoundTrip(t *testing.T) {
	key := deriveFieldKey("test-secret-please-do-not-use-in-prod")

	cases := []string{
		"",
		"a",
		"hello world",
		"SuperSecret!@#$%^&*()_+-=",
		strings.Repeat("x", 4096),
		"unicode ⚠️ 你好",
		"contains\nnewlines\r\nand\ttabs",
	}
	for _, f := range cipherFormats {
		for _, want := range cases {
			name := want
			if len(name) > 20 {
				name = name[:20]
			}
			t.Run(f.name+"/"+name, func(t *testing.T) {
				ct := f.enc(t, want, key)
				if want == "" {
					if ct != "" {
						t.Fatalf("encrypt(\"\") = %q, want \"\" (empty stays empty)", ct)
					}
					return
				}
				if !strings.HasPrefix(ct, f.prefix) {
					t.Fatalf("encrypt(%q) missing %q prefix: %q", want, f.prefix, ct)
				}
				got := decryptField(ct, key)
				if got != want {
					t.Errorf("round-trip mismatch: got %q, want %q", got, want)
				}
			})
		}
	}
}

// TestEncryptField_WritesEnc2 — D-11: every new encryption is the v2 format.
func TestEncryptField_WritesEnc2(t *testing.T) {
	ct := mustEncrypt(t, "fresh-secret", deriveFieldKey("k"))
	if !strings.HasPrefix(ct, enc2Prefix) {
		t.Fatalf("new ciphertext %q lacks the %s prefix", ct, enc2Prefix)
	}
	if !IsEncryptedValue(ct) {
		t.Fatalf("IsEncryptedValue(%q) = false", ct)
	}
}

// TestDecryptField_LegacySha256Ciphertext — the production-safety guarantee
// of D-11: an "{enc}" value built EXACTLY as pre-D-11 binaries did (AES-256-
// GCM under sha256(secret), independent of this package's helpers) still
// decrypts with the same secret, and a v2 key alone cannot read it.
func TestDecryptField_LegacySha256Ciphertext(t *testing.T) {
	const secret = "pre-d11-production-secret"
	ct := legacyEncryptIndependently(t, "snmp-community-from-2025", secret)

	if got := decryptField(ct, deriveFieldKey(secret)); got != "snmp-community-from-2025" {
		t.Fatalf("legacy {enc} value no longer decrypts: got %q", got)
	}
	// Prefix routing: the v1 key, not the v2 key, must be what decrypts it.
	if got := decryptField(ct, fieldKey{v2: deriveKeyV2(secret)}); got != "" {
		t.Fatalf("{enc} decrypted with the HKDF key (%q): prefix routing broken", got)
	}
}

// TestDecryptField_Enc2NeedsHKDFKey — an {enc2} value must be decrypted with
// the HKDF-derived key, not sha256(secret): the two derivations differ.
func TestDecryptField_Enc2NeedsHKDFKey(t *testing.T) {
	const secret = "d11-secret"
	k := deriveFieldKey(secret)
	if string(k.v1) == string(k.v2) {
		t.Fatal("HKDF key equals sha256(secret): the derivation was not changed")
	}
	ct := mustEncrypt(t, "v2-payload", k)
	if got := decryptField(ct, fieldKey{v1: deriveLegacyKey(secret)}); got != "" {
		t.Fatalf("{enc2} decrypted with the legacy key (%q)", got)
	}
	if got := decryptField(ct, fieldKey{v2: deriveKeyV2(secret)}); got != "v2-payload" {
		t.Fatalf("{enc2} with its HKDF key: got %q", got)
	}
}

// TestDecryptField_LegacyPlaintextPassthrough — values without an encryption
// prefix must be returned unchanged (idempotent for callers that decrypt
// unconditionally; v0.10.226 reasoning).
func TestDecryptField_LegacyPlaintextPassthrough(t *testing.T) {
	key := deriveFieldKey("any-key")
	cases := []string{
		"plain text",
		"this-looks-like-but-isnt-encrypted",
		"enc}not-prefixed", // close but no prefix
		"{enc",             // partial prefix
		"{enc2",            // partial v2 prefix
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
// but no key is available, the function must return "", not the literal
// ciphertext. Returning the ciphertext is the v0.10.226 bug class — Postfix
// logged the {enc}<base64> string verbatim when used as a password.
func TestDecryptField_NoKeyReturnsEmpty(t *testing.T) {
	for _, f := range cipherFormats {
		t.Run(f.name, func(t *testing.T) {
			ct := f.enc(t, "super-secret-password", deriveFieldKey("the-real-key"))
			if !strings.HasPrefix(ct, f.prefix) {
				t.Fatalf("setup: ciphertext missing prefix")
			}
			if got := decryptField(ct, fieldKey{}); got != "" {
				t.Errorf("decryptField with no key returned %q, want \"\" (must never leak ciphertext as plaintext)", got)
			}
			if got := decryptField(ct, fieldKey{v1: []byte{}, v2: []byte{}}); got != "" {
				t.Errorf("decryptField with empty keys returned %q, want \"\"", got)
			}
		})
	}
}

// TestDecryptField_WrongKeyReturnsEmpty — AUDIT-027's primary regression:
// gcm.Open auth failure (wrong key, tampered data, key rotation gone wrong)
// must NEVER fall back to returning the raw ciphertext.
func TestDecryptField_WrongKeyReturnsEmpty(t *testing.T) {
	for _, f := range cipherFormats {
		t.Run(f.name, func(t *testing.T) {
			ct := f.enc(t, "smtp-password", deriveFieldKey("the-real-key"))
			got := decryptField(ct, deriveFieldKey("a-different-key"))
			if got != "" {
				t.Errorf("decryptField with wrong key returned %q, want \"\" — this is the AUDIT-027 / v0.10.226 bug class", got)
			}
		})
	}
}

// TestDecryptField_BadBase64ReturnsEmpty — malformed payloads must not leak.
func TestDecryptField_BadBase64ReturnsEmpty(t *testing.T) {
	key := deriveFieldKey("any-key")
	for _, prefix := range []string{encPrefix, enc2Prefix} {
		for _, body := range []string{"!!!not-valid-base64!!!", "AAAA===", "\x00\x01\x02", "////////\n\n\n"} {
			in := prefix + body
			if got := decryptField(in, key); got != "" {
				t.Errorf("decryptField(%q) = %q, want \"\"", in, got)
			}
		}
	}
}

// TestDecryptField_TamperedCiphertextReturnsEmpty — flip a byte in a valid
// ciphertext; GCM auth must fail and the function must return "".
func TestDecryptField_TamperedCiphertextReturnsEmpty(t *testing.T) {
	key := deriveFieldKey("real-key")
	for _, f := range cipherFormats {
		t.Run(f.name, func(t *testing.T) {
			ct := f.enc(t, "the-secret", key)
			// Swap the first base64 char for another in-alphabet one so we
			// get past base64 decoding and hit the GCM auth check.
			body := ct[len(f.prefix):]
			if len(body) < 2 {
				t.Fatal("ciphertext too short to tamper")
			}
			swap := byte('A')
			if body[0] == 'A' {
				swap = 'B'
			}
			tampered := f.prefix + string(swap) + body[1:]
			if got := decryptField(tampered, key); got != "" {
				t.Errorf("decryptField on tampered ct returned %q, want \"\"", got)
			}
		})
	}
}

// TestDecryptField_ShortCiphertextReturnsEmpty — base64 that decodes to fewer
// bytes than the GCM nonce size must not panic and must return "".
func TestDecryptField_ShortCiphertextReturnsEmpty(t *testing.T) {
	key := deriveFieldKey("real-key")
	// base64("abc") = "YWJj" → 3 raw bytes, < 12-byte GCM nonce
	for _, prefix := range []string{encPrefix, enc2Prefix} {
		if got := decryptField(prefix+"YWJj", key); got != "" {
			t.Errorf("decryptField(%s short ciphertext) = %q, want \"\"", prefix, got)
		}
	}
}

// TestEncryptField_AlreadyEncryptedIsIdempotent — double-encrypt must be a
// no-op for BOTH formats so a re-save never wraps the ciphertext twice.
// "{enc2}" does not start with "{enc}", so this fails if the guard only
// checks the legacy prefix.
func TestEncryptField_AlreadyEncryptedIsIdempotent(t *testing.T) {
	key := deriveFieldKey("k")
	for _, f := range cipherFormats {
		ct := f.enc(t, "hello", key)
		if ct2 := mustEncrypt(t, ct, key); ct != ct2 {
			t.Errorf("%s: encryptField on already-encrypted value changed it: %q -> %q", f.name, ct, ct2)
		}
		if ct2 := mustEncryptLegacy(t, ct, key); ct != ct2 {
			t.Errorf("%s: encryptFieldLegacy on already-encrypted value changed it: %q -> %q", f.name, ct, ct2)
		}
	}
}

// TestIsEncryptedValue covers both prefixes and near misses.
func TestIsEncryptedValue(t *testing.T) {
	for in, want := range map[string]bool{
		"{enc}abc": true, "{enc2}abc": true, "{enc}": true, "{enc2}": true,
		"": false, "{enc": false, "{enc2": false, "enc}x": false, "{enc3}x": false, "plain": false,
	} {
		if got := IsEncryptedValue(in); got != want {
			t.Errorf("IsEncryptedValue(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestEncryptField_EmptyStaysEmpty — "" is never wrapped in ciphertext.
func TestEncryptField_EmptyStaysEmpty(t *testing.T) {
	if got := mustEncrypt(t, "", deriveFieldKey("k")); got != "" {
		t.Errorf("encryptField(\"\", key) = %q, want \"\"", got)
	}
}

// TestEncryptField_NoKeyIsError — D-12: with no key the encrypter returns an
// error and an EMPTY value, never the plaintext (the pre-fix behavior).
func TestEncryptField_NoKeyIsError(t *testing.T) {
	for _, enc := range []func(string, fieldKey) (string, error){encryptField, encryptFieldLegacy} {
		got, err := enc("plain-secret", fieldKey{})
		if err == nil {
			t.Fatalf("encrypt with no key: err = nil, value %q (must fail closed)", got)
		}
		if got != "" {
			t.Fatalf("encrypt with no key returned %q alongside the error, want \"\"", got)
		}
	}
}

// failingReader forces the nonce read to fail.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("forced entropy failure") }

// TestEncryptField_RandFailureIsError — D-12: a cipher-path failure (here the
// nonce read) is an error, never a plaintext fallback.
func TestEncryptField_RandFailureIsError(t *testing.T) {
	orig := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = orig })

	got, err := encryptField("plain-secret", deriveFieldKey("k"))
	if err == nil || got != "" {
		t.Fatalf("encrypt with failing rand: got (%q, %v), want (\"\", error)", got, err)
	}
}

// TestEncryptField_BadKeyLengthIsError — an invalid AES key size is an error.
func TestEncryptField_BadKeyLengthIsError(t *testing.T) {
	got, err := encryptField("plain-secret", fieldKey{v2: []byte{1, 2, 3}})
	if err == nil || got != "" {
		t.Fatalf("encrypt with a 3-byte key: got (%q, %v), want (\"\", error)", got, err)
	}
}
