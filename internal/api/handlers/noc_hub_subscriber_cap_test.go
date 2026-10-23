package handlers

import (
	"testing"
	"time"
)

// TestNOCHub_SubscriberCap_D16 pins D-16: concurrent NOC SSE subscribers are
// bounded so an unbounded count can't exhaust goroutines/memory.
func TestNOCHub_SubscriberCap_D16(t *testing.T) {
	_, db := setupTestHandler(t)
	hub := newNOCHub(db, time.Hour)

	var chans []chan []byte
	for i := 0; i < maxNOCSubscribers; i++ {
		ch, _, ok := hub.subscribe()
		if !ok {
			t.Fatalf("subscriber %d of %d refused prematurely", i+1, maxNOCSubscribers)
		}
		chans = append(chans, ch)
	}
	defer func() {
		for _, ch := range chans {
			hub.unsubscribe(ch)
		}
	}()

	if _, _, ok := hub.subscribe(); ok {
		t.Fatal("subscriber above the cap was accepted")
	}
}
