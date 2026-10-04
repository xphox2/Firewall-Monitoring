package auth_test

import (
	"testing"

	"firewall-mon/internal/auth"
)

// D2: a correct password must not reset the lockout bucket of a 2FA account.
// The password stage only buys a pending token; clearing there let whoever
// holds the password take (max-1) TOTP guesses, log in again, and repeat with
// a fresh budget forever. The bucket is now cleared only when the login
// completes (ClearFailures from the TOTP step).

// TestValidateCredentials_TOTPAccount_PasswordDoesNotClearBudget_D2 walks the
// attack: password ok → wrong TOTP ×(max-1) → password ok again → one more
// wrong TOTP → locked. On the pre-fix code the second password check wiped
// the counter and the final state would be one failure, not a lockout.
func TestValidateCredentials_TOTPAccount_PasswordDoesNotClearBudget_D2(t *testing.T) {
	t.Parallel()
	am, db := managerWithUser(t, "admin", "correct-horse")
	db.admins["admin"].TOTPEnabled = true
	const ip = "10.0.0.5"
	max := testConfig().Auth.MaxLoginAttempts // 3

	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Fatalf("password stage: %v", err)
	}
	for i := 0; i < max-1; i++ {
		am.RecordFailure("admin", ip) // wrong TOTP codes
	}
	if am.IsLocked("admin", ip) {
		t.Fatalf("locked after %d TOTP failures, budget is %d", max-1, max)
	}
	// Second password round-trip: must NOT reset the budget.
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Fatalf("password stage (second round): %v", err)
	}
	am.RecordFailure("admin", ip) // one more wrong TOTP
	if !am.IsLocked("admin", ip) {
		t.Fatal("D2 regression: the password stage reset the 2FA account's lockout bucket")
	}
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != auth.ErrAccountLocked {
		t.Fatalf("after the budget is spent the password stage must be locked: got %v", err)
	}
	// A different source IP keeps its own bucket (unchanged contract).
	if err := am.ValidateCredentials("admin", "correct-horse", "10.0.0.6"); err != nil {
		t.Fatalf("other IP must not inherit the lockout: %v", err)
	}
}

// TestValidateCredentials_TOTPAccount_CompletedLoginClears_D2: the clear
// still happens — at the end of the login (ClearFailures, what TOTPLogin
// calls after a valid code), so a legitimate operator is not stuck with
// stale failures after they get in.
func TestValidateCredentials_TOTPAccount_CompletedLoginClears_D2(t *testing.T) {
	t.Parallel()
	am, db := managerWithUser(t, "admin", "correct-horse")
	db.admins["admin"].TOTPEnabled = true
	const ip = "10.0.0.7"

	_ = am.ValidateCredentials("admin", "nope", ip)
	_ = am.ValidateCredentials("admin", "nope", ip)
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Fatalf("password stage: %v", err)
	}
	// Still 2 failures on the books after the password stage.
	am.RecordFailure("admin", ip)
	if !am.IsLocked("admin", ip) {
		t.Fatal("password failures and TOTP failures must share one budget across the password stage")
	}
	am.ClearFailures("admin", ip) // the login completed
	if am.IsLocked("admin", ip) {
		t.Fatal("ClearFailures must empty the bucket")
	}
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Fatalf("after a completed login the next login must be allowed: %v", err)
	}
}

// TestValidateCredentials_PasswordOnlyAccount_StillClears_D2 pins that a
// password-only account keeps the historical behaviour: the password IS the
// whole login, so success clears the bucket there and then.
func TestValidateCredentials_PasswordOnlyAccount_StillClears_D2(t *testing.T) {
	t.Parallel()
	am, _ := managerWithUser(t, "admin", "correct-horse")
	const ip = "10.0.0.8"
	_ = am.ValidateCredentials("admin", "nope", ip)
	_ = am.ValidateCredentials("admin", "nope", ip)
	if err := am.ValidateCredentials("admin", "correct-horse", ip); err != nil {
		t.Fatalf("login: %v", err)
	}
	if am.IsLocked("admin", ip) {
		t.Fatal("password-only success must clear the bucket")
	}
	am.RecordFailure("admin", ip)
	am.RecordFailure("admin", ip)
	if am.IsLocked("admin", ip) {
		t.Fatal("bucket was not cleared by the password-only login")
	}
}

// TestReauthLimiter_BurstThenOnePerMinute pins the shared in-session
// re-authentication budget (D4): 5 attempts straight away, the 6th refused,
// a different account unaffected, and the zero value usable.
func TestReauthLimiter_BurstThenOnePerMinute(t *testing.T) {
	t.Parallel()
	var l auth.ReauthLimiter
	for i := 0; i < 5; i++ {
		if !l.Allow(7) {
			t.Fatalf("attempt %d refused inside the burst", i+1)
		}
	}
	if l.Allow(7) {
		t.Fatal("6th attempt inside a minute must be refused")
	}
	if !l.Allow(8) {
		t.Fatal("another account has its own budget")
	}
}
