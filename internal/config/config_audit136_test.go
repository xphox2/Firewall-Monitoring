package config

import (
	"os"
	"testing"
)

// TestIsGeneratedPassword_AUDIT136 is the regression for the
// audit: pre-fix, `IsGeneratedPassword()` re-queried
// `os.LookupEnv("ADMIN_PASSWORD")` on every call. That's fragile
// (TOCTOU: a future caller could observe a different answer
// than config-load did) and duplicated work. Post-fix the answer
// is captured once at config-load time in
// `Auth.AdminPasswordGenerated`, and `IsGeneratedPassword` reads
// from that field.
//
// The test pins three invariants:
//  1. When ADMIN_PASSWORD is unset at config-load time,
//     `IsGeneratedPassword()` returns true.
//  2. When ADMIN_PASSWORD is set (even to empty string) at
//     config-load time, `IsGeneratedPassword()` returns false.
//  3. A subsequent call to `os.Unsetenv("ADMIN_PASSWORD")` does
//     NOT change the answer — the bool was captured at load time
//     and the env mutation is invisible. This is the TOCTOU
//     guard the audit called out.
func TestIsGeneratedPassword_AUDIT136(t *testing.T) {
	// Case 1: env unset → generated = true.
	t.Run("unset", func(t *testing.T) {
		t.Setenv("ADMIN_PASSWORD", "")
		// Force unset: t.Setenv to empty doesn't unset, it
		// sets to "". For a true unset we use os.Unsetenv
		// (which is safe inside a test because t.Setenv
		// restores it on cleanup).
		os.Unsetenv("ADMIN_PASSWORD")
		c := Load()
		if !c.IsGeneratedPassword() {
			t.Errorf("IsGeneratedPassword() = false with ADMIN_PASSWORD unset, want true (the password was auto-generated)")
		}
	})

	// Case 2: env set (even to "") → generated = false.
	t.Run("set", func(t *testing.T) {
		t.Setenv("ADMIN_PASSWORD", "")
		// t.Setenv("ADMIN_PASSWORD", "") actually sets to "".
		// That counts as "the operator set the env" per
		// the AUDIT-136 semantic (they explicitly chose to
		// pass an empty value).
		c := Load()
		if c.IsGeneratedPassword() {
			t.Errorf("IsGeneratedPassword() = true with ADMIN_PASSWORD explicitly set (even to empty), want false (the operator made a deliberate choice)")
		}
	})

	// Case 3: TOCTOU — env is unset at load time, then mutated.
	// The bool should NOT change (it's captured at load time, not
	// re-read). The test asserts the bool stays `true` (the
	// answer-at-load-time) even though the env now has a value.
	t.Run("toctou", func(t *testing.T) {
		os.Unsetenv("ADMIN_PASSWORD")
		c := Load()
		if !c.IsGeneratedPassword() {
			t.Fatalf("baseline: IsGeneratedPassword() = false with ADMIN_PASSWORD unset, want true")
		}
		// Mutate the env (simulating a fork-exec or a test
		// that does its own env manipulation). The function
		// must NOT re-read the env.
		t.Setenv("ADMIN_PASSWORD", "post-load-mutation")
		// The bool should STILL be true — the AUDIT-136
		// fix's whole point is that the bool is captured at
		// load time. A function that re-reads the env
		// would now return false (because the env is set),
		// which is the TOCTOU bug.
		if !c.IsGeneratedPassword() {
			t.Errorf("IsGeneratedPassword() = false after a post-load env mutation; the AUDIT-136 fix's whole point is that the bool is captured at load time. A live env re-read is the TOCTOU bug the audit called out.")
		}
	})
}
