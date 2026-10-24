package auth

import (
	"testing"
	"time"
)

// TestReauthLimiter_SweepsIdleEntries_L10: entries idle for a full refill are
// dropped on a later Allow, while a recently-spent account keeps its entry
// (and so its exhausted budget). Pre-fix the map only ever grew.
func TestReauthLimiter_SweepsIdleEntries_L10(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	r := &ReauthLimiter{now: func() time.Time { return clock }}
	for id := uint(1); id <= 100; id++ {
		r.Allow(id)
	}
	// Account 500 burns its whole burst shortly before the sweep.
	clock = clock.Add(reauthRefill - 30*time.Second)
	for i := 0; i < reauthBurst; i++ {
		if !r.Allow(500) {
			t.Fatalf("attempt %d denied inside the burst", i+1)
		}
	}
	clock = clock.Add(30 * time.Second)
	if r.Allow(500) {
		t.Fatal("exhausted account allowed again after 30s — budget was lost to the sweep")
	}
	if got := len(r.m); got != 1 {
		t.Fatalf("after sweep len(m) = %d, want 1 (only the active account)", got)
	}
}

// TestReauthLimiter_Capped_L10: the map never exceeds its cap.
func TestReauthLimiter_Capped_L10(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	r := &ReauthLimiter{now: func() time.Time { return clock }, max: 10}
	for id := uint(1); id <= 50; id++ {
		clock = clock.Add(time.Second)
		r.Allow(id)
		if len(r.m) > 10 {
			t.Fatalf("len(m) = %d exceeds cap 10", len(r.m))
		}
	}
	if _, ok := r.m[50]; !ok {
		t.Fatal("newest account missing after eviction")
	}
	if _, ok := r.m[1]; ok {
		t.Fatal("least-recently-used account survived eviction")
	}
}

// TestReauthLimiter_ZeroValueBudget: the zero value still enforces the
// 5-then-1/min budget per account.
func TestReauthLimiter_ZeroValueBudget(t *testing.T) {
	var r ReauthLimiter
	for i := 0; i < reauthBurst; i++ {
		if !r.Allow(7) {
			t.Fatalf("attempt %d denied inside the burst", i+1)
		}
	}
	if r.Allow(7) {
		t.Fatal("attempt past the burst allowed")
	}
	if !r.Allow(8) {
		t.Fatal("another account shares the budget")
	}
}
