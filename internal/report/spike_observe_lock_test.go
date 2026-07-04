package report

import (
	"testing"
	"time"
)

// TestSeasonalSpikeDetector_ProfileFetchDoesNotBlockOtherKeys (LC-30): the
// profileFor callback is a multi-day DB aggregation in production. Observe
// must NOT hold the detector-wide mutex across it, or every concurrent
// pollDevice goroutine's spike checks serialize behind one interface's query.
func TestSeasonalSpikeDetector_ProfileFetchDoesNotBlockOtherKeys(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{})
	d := NewSeasonalSpikeDetector(time.Hour, 0, func(key string) *SeasonalProfile {
		if key == "slow" {
			close(started)
			<-block // simulates a slow 30-day DB query
		}
		return nil
	})

	slowDone := make(chan struct{})
	go func() {
		d.Observe("slow", time.Now(), 100, 3, time.Minute)
		close(slowDone)
	}()
	<-started

	fastDone := make(chan struct{})
	go func() {
		d.Observe("fast", time.Now(), 100, 3, time.Minute)
		close(fastDone)
	}()

	select {
	case <-fastDone:
		// Observe("fast") proceeded while "slow"'s profile fetch was in flight.
	case <-time.After(2 * time.Second):
		t.Fatal("Observe(fast) blocked behind another key's profile fetch — detector mutex held across the DB callback")
	}

	close(block)
	<-slowDone
}
