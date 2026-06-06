package database

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// probeKeyHashPrefix marks an at-rest probe registration key as already hashed.
// It is essential: a freshly generated plaintext key is hex.EncodeToString(32
// bytes) = 64 hex chars, and a SHA-256 hex digest is ALSO 64 hex chars, so the
// two are otherwise indistinguishable — without the prefix the startup
// migration could not tell a legacy plaintext key from an already-hashed one
// and would double-hash on the second run, locking every probe out.
const probeKeyHashPrefix = "sha256:"

// HashProbeKey returns the at-rest representation of a probe registration key:
// "sha256:" + hex(SHA-256(plaintext)).
//
// AUDIT-017: the registration key is an authentication token looked up and
// compared BY VALUE, so it is HASHED (not encrypted) — a DB compromise no
// longer yields usable probe tokens, and the plaintext is shown only once (the
// RegenerateProbeKey response). Hashing is deterministic, so by-value lookups
// (`WHERE registration_key = HashProbeKey(token)`) and constant-time compares
// still work.
//
// This is deliberately NOT idempotent: it ALWAYS hashes, even an
// already-"sha256:"-prefixed input. That is a security requirement — if it
// returned a hashed input unchanged, an attacker who learned the stored hash
// (DB leak) could present that hash as the Bearer token and authenticate, since
// hashing it would be a no-op that matches the stored value. By always hashing,
// presenting the stored hash double-hashes and fails to match. The startup
// migration achieves idempotency by guarding with IsHashedProbeKey before
// calling this, NOT by relying on the hash being a no-op.
func HashProbeKey(s string) string {
	if s == "" {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	return probeKeyHashPrefix + hex.EncodeToString(sum[:])
}

// IsHashedProbeKey reports whether s is already in the hashed at-rest form.
func IsHashedProbeKey(s string) bool {
	return strings.HasPrefix(s, probeKeyHashPrefix)
}
