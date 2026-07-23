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

// TestMarkTOTPSlotUsed_ReplayGuard: a given code is single-use per {purpose,user};
// the guard keys on the CODE (not the wall-clock slot), so it holds across a 30s
// boundary within the code's ±1 skew validity window.
func TestMarkTOTPSlotUsed_ReplayGuard(t *testing.T) {
	t.Parallel()
	am := auth.NewAuthManager(testConfig(), newFakeDB())

	// First use of a code succeeds; an exact replay is rejected.
	if !am.MarkTOTPSlotUsed(7, "login", "123456") {
		t.Fatal("first use of a code must succeed")
	}
	if am.MarkTOTPSlotUsed(7, "login", "123456") {
		t.Fatal("replay of the same code must be rejected")
	}
	// A DIFFERENT code for the same user/purpose is a distinct authentication
	// (e.g. the next 30s code) — must succeed.
	if !am.MarkTOTPSlotUsed(7, "login", "654321") {
		t.Fatal("a different code must not be blocked by another code's guard")
	}
	// A different user is tracked independently.
	if !am.MarkTOTPSlotUsed(8, "login", "123456") {
		t.Fatal("other users must not share the guard")
	}
	// AUDIT L3: a different PURPOSE for the same user+code is independent, so
	// logging in then revealing a credential with the current code both succeed;
	// a second reveal with that code is still blocked.
	if !am.MarkTOTPSlotUsed(7, "reveal", "123456") {
		t.Fatal("a distinct purpose must have an independent guard")
	}
	if am.MarkTOTPSlotUsed(7, "reveal", "123456") {
		t.Fatal("replay of the same code+purpose must be rejected")
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
