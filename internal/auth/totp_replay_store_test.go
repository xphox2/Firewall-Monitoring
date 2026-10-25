package auth_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/auth"
)

// replayStoreDB is a fakeDB that also implements auth.TOTPReplayStore, so the
// AuthManager uses it instead of its in-process map.
type replayStoreDB struct {
	*fakeDB
	mu     sync.Mutex
	used   map[string]int64
	err    error
	claims int
}

func (r *replayStoreDB) ClaimTOTPCode(key string, now time.Time, ttl time.Duration) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claims++
	if r.err != nil {
		return false, r.err
	}
	if exp, ok := r.used[key]; ok && now.Unix() <= exp {
		return false, nil
	}
	r.used[key] = now.Add(ttl).Unix()
	return true, nil
}

// TestMarkTOTPSlotUsed_SharedStore pins D-14: with a durable store, the
// guard is the store's, so a second AuthManager (another API process, or this
// one after a restart) refuses a code the first one accepted.
func TestMarkTOTPSlotUsed_SharedStore(t *testing.T) {
	t.Parallel()
	store := &replayStoreDB{fakeDB: newFakeDB(), used: map[string]int64{}}
	first := auth.NewAuthManager(testConfig(), store)
	second := auth.NewAuthManager(testConfig(), store)

	if !first.MarkTOTPSlotUsed(7, "123456") {
		t.Fatal("first use of a code must succeed")
	}
	if second.MarkTOTPSlotUsed(7, "123456") {
		t.Fatal("a code accepted by one process was accepted again by another (or after a restart)")
	}
	if store.claims != 2 {
		t.Errorf("store claims = %d, want 2 (the store, not process memory, must decide)", store.claims)
	}
}

// TestMarkTOTPSlotUsed_StoreErrorFailsClosed: a store failure refuses the
// code rather than falling back to "accept".
func TestMarkTOTPSlotUsed_StoreErrorFailsClosed(t *testing.T) {
	t.Parallel()
	store := &replayStoreDB{fakeDB: newFakeDB(), used: map[string]int64{}, err: errors.New("db down")}
	am := auth.NewAuthManager(testConfig(), store)
	if am.MarkTOTPSlotUsed(7, "123456") {
		t.Fatal("a code was accepted although the replay guard could not record it")
	}
}
