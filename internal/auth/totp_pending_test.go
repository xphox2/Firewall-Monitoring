package auth_test

import (
	"testing"
	"time"

	"firewall-mon/internal/auth"
)

// TestGeneratePendingToken_StageAndExpiry: the pending 2FA token carries
// Stage=totp, no role, and a short (≤PendingTokenExpiry) lifetime.
func TestGeneratePendingToken_StageAndExpiry(t *testing.T) {
	t.Parallel()
	am, db := managerWithUser(t, "admin", "pw")
	db.version[1] = 3

	tok, err := am.GeneratePendingToken("admin", 1, 3)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	claims, err := am.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Stage != auth.StageTOTP {
		t.Errorf("Stage = %q, want %q", claims.Stage, auth.StageTOTP)
	}
	if claims.Role != "" {
		t.Errorf("pending token must carry no role, got %q", claims.Role)
	}
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > auth.PendingTokenExpiry+time.Minute {
		t.Errorf("pending token lives %v — must be ~%v", ttl, auth.PendingTokenExpiry)
	}
}

// TestMarkTOTPSlotUsed_ReplayGuard: the same 30s slot authenticates once.
func TestMarkTOTPSlotUsed_ReplayGuard(t *testing.T) {
	t.Parallel()
	am := auth.NewAuthManager(testConfig(), newFakeDB())
	if !am.MarkTOTPSlotUsed(7, "login") {
		t.Fatal("first use of a slot must succeed")
	}
	if am.MarkTOTPSlotUsed(7, "login") {
		t.Fatal("second use of the same slot must be rejected (replay)")
	}
	// A different user is tracked independently.
	if !am.MarkTOTPSlotUsed(8, "login") {
		t.Fatal("other users must not share the slot guard")
	}
	// AUDIT L3: a different PURPOSE for the same user has its own slot, so
	// logging in then revealing a credential in the same 30s window both succeed;
	// but a second reveal in that slot is still blocked.
	if !am.MarkTOTPSlotUsed(7, "reveal") {
		t.Fatal("a distinct purpose must have an independent slot")
	}
	if am.MarkTOTPSlotUsed(7, "reveal") {
		t.Fatal("second use of the same slot+purpose must be rejected (replay)")
	}
}

// TestLockout_SharedBucket: TOTP failures (RecordFailure) exhaust the SAME
// budget the password path checks, and vice versa — the second factor cannot
// be brute-forced on a fresh budget.
func TestLockout_SharedBucket(t *testing.T) {
	t.Parallel()
	am, _ := managerWithUser(t, "admin", "correct-horse")
	const ip = "10.9.9.9"

	for i := 0; i < 3; i++ { // MaxLoginAttempts in testConfig
		am.RecordFailure("admin", ip)
	}
	if !am.IsLocked("admin", ip) {
		t.Fatal("IsLocked must report true after budget exhaustion via RecordFailure")
	}
	// The password path sees the same bucket.
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != auth.ErrAccountLocked {
		t.Errorf("ValidateCredentials after TOTP failures: got %v, want ErrAccountLocked", err)
	}
	// Clearing restores access.
	am.ClearFailures("admin", ip)
	if am.IsLocked("admin", ip) {
		t.Error("ClearFailures must unlock")
	}
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Errorf("login after clear should succeed: %v", err)
	}
}
