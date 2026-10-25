package database

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"firewall-mon/internal/auth"
)

// TestClaimTOTPCode pins D-14 on the test backend: a code is claimable once
// inside its window, refused while the row lives, and claimable again once
// the window has passed.
func TestClaimTOTPCode(t *testing.T) {
	d := NewDatabaseForTesting(t)
	checkClaimTOTPCode(t, d)
}

func checkClaimTOTPCode(t *testing.T, d *Database) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	const key = "aa11bb22"
	if ok, err := d.ClaimTOTPCode(key, now, 90*time.Second); err != nil || !ok {
		t.Fatalf("first claim = %v, %v; want true", ok, err)
	}
	if ok, err := d.ClaimTOTPCode(key, now.Add(89*time.Second), 90*time.Second); err != nil || ok {
		t.Fatalf("replay inside the window = %v, %v; want false", ok, err)
	}
	if ok, err := d.ClaimTOTPCode(key, now.Add(90*time.Second), 90*time.Second); err != nil || ok {
		t.Fatalf("replay at the window's last second = %v, %v; want false", ok, err)
	}
	if ok, err := d.ClaimTOTPCode(key, now.Add(91*time.Second), 90*time.Second); err != nil || !ok {
		t.Fatalf("claim after the window = %v, %v; want true", ok, err)
	}
	if ok, err := d.ClaimTOTPCode("other", now.Add(91*time.Second), 90*time.Second); err != nil || !ok {
		t.Fatalf("a different code = %v, %v; want true", ok, err)
	}

	// Concurrent claims of one fresh code: exactly one wins. On the SQLite
	// test harness (one connection) the goroutines serialize, so this only
	// re-checks the sequential contract; real contention between connections
	// is proven by TestClaimTOTPCode_PG, which runs this same helper on
	// PostgreSQL in the integration lane.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := d.ClaimTOTPCode("race", now.Add(200*time.Second), 90*time.Second); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("concurrent claims won %d times, want exactly 1", wins.Load())
	}
}

// TestAuthManager_UsesDatabaseReplayGuard drives the guard end to end: two
// AuthManagers over one real Database (two API processes) — a code accepted by
// one is refused by the other.
func TestAuthManager_UsesDatabaseReplayGuard(t *testing.T) {
	d := NewDatabaseForTesting(t)
	a := auth.NewAuthManager(nil, d)
	b := auth.NewAuthManager(nil, d)
	if !a.MarkTOTPSlotUsed(7, "123456") {
		t.Fatal("first use of a code refused")
	}
	if b.MarkTOTPSlotUsed(7, "123456") {
		t.Fatal("a code accepted by one AuthManager was accepted again by another sharing the database")
	}
}
