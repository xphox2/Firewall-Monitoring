package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestAPIToken_Lifecycle pins the at-rest discipline (P0-2): only the hash is
// stored, plaintext lookup round-trips, the stored hash presented as a bearer
// value does NOT resolve (double-hash property), revocation sticks, and
// non-fwm_ values short-circuit.
func TestAPIToken_Lifecycle(t *testing.T) {
	d := NewDatabaseForTesting(t)

	plaintext := APITokenPlaintextPrefix + "test-token-random-part"
	tok := models.ApiToken{
		Name:      "ci",
		TokenHash: HashAPIToken(plaintext),
		Prefix:    plaintext[:12],
		Scope:     "read",
	}
	if err := d.CreateAPIToken(&tok); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	got, err := d.LookupAPIToken(plaintext)
	if err != nil || got == nil {
		t.Fatalf("LookupAPIToken(plaintext): %v (tok=%v)", err, got)
	}
	if got.Name != "ci" || got.Scope != "read" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Double-hash property: the stored at-rest value must not authenticate.
	if leaked, _ := d.LookupAPIToken(tok.TokenHash); leaked != nil {
		t.Error("stored hash presented as bearer must not resolve")
	}
	// Non-fwm_ values (e.g. probe keys) short-circuit without a query.
	if other, _ := d.LookupAPIToken("deadbeef"); other != nil {
		t.Error("non-fwm_ value must not resolve")
	}

	// Revocation sticks and is visible on lookup for the middleware to reject.
	if err := d.RevokeAPIToken(tok.ID); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	got, err = d.LookupAPIToken(plaintext)
	if err != nil || got == nil {
		t.Fatalf("LookupAPIToken after revoke: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("RevokedAt not set after revoke")
	}

	// last_used_at touch persists.
	now := time.Now()
	if err := d.TouchAPITokenLastUsed(tok.ID, now); err != nil {
		t.Fatalf("TouchAPITokenLastUsed: %v", err)
	}
	list, err := d.ListAPITokens()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAPITokens: %v (n=%d)", err, len(list))
	}
	if list[0].LastUsedAt == nil {
		t.Error("LastUsedAt not persisted")
	}
}
