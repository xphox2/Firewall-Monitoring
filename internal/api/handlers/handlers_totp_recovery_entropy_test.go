package handlers

import (
	"encoding/hex"
	"testing"
)

// TestNewRecoveryCodes_128BitEntropy pins the H-8 fix: recovery codes must be
// 16 random bytes (32 hex chars = 128 bits), not the pre-fix 5 bytes (40 bits,
// GPU-brute-forceable in minutes). The stored SHA-256 hash is only as strong as
// its input entropy.
func TestNewRecoveryCodes_128BitEntropy(t *testing.T) {
	codes, err := newRecoveryCodes(recoveryCodeCount)
	if err != nil {
		t.Fatalf("newRecoveryCodes: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), recoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 32 {
			t.Fatalf("code %q is %d chars, want 32 hex chars (128 bits)", c, len(c))
		}
		if _, err := hex.DecodeString(c); err != nil {
			t.Fatalf("code %q is not valid hex: %v", c, err)
		}
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true
	}
}
