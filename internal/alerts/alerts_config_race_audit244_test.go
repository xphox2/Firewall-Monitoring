package alerts

import (
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestSecurityAndProbePaths_RaceWithRefresh_Audit244 pins the AUDIT-244 fix:
// ProcessSecurityEvent, ProcessSecurityDigest and CheckProbeDataFlow read the
// policy cache and config.Alerts (resolveAlertConfig + notifier.SnapshotConfig
// + the probe-lag setting) WITHOUT am.mu, while RefreshThresholds rewrites
// config.Alerts field-by-field under the write lock — a textbook data race the
// race detector catches as soon as both sides run concurrently. Run with
// -race: fails before the fix, passes after.
func TestSecurityAndProbePaths_RaceWithRefresh_Audit244(t *testing.T) {
	am, db := newTestManager(t)
	// The :memory: test DB is per-connection — a second pooled connection sees
	// an EMPTY database. Concurrent goroutines need the pool pinned to the one
	// connection that ran the migrations.
	if sqlDB, err := db.Gorm().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	// Seed settings so RefreshThresholds actually WRITES config.Alerts fields
	// on every pass — with an empty settings table nothing is assigned and
	// there is no write for -race to observe.
	for k, v := range map[string]string{
		"cpu_threshold": "91",
		"smtp_host":     "smtp.example.com",
		"smtp_to":       "ops@example.com",
	} {
		if err := db.UpsertSetting(&models.SystemSetting{Key: k, Value: v, Category: "alerts", Type: "string"}); err != nil {
			t.Fatalf("seed setting %s: %v", k, err)
		}
	}

	// Non-zero lag threshold so CheckProbeDataFlow runs its full read path
	// (with 0 it returns after the first config read).
	am.config.Alerts.ProbeDataLagAlertMinutes = 60

	stop := make(chan struct{})
	var refresher sync.WaitGroup
	refresher.Add(1)
	go func() {
		defer refresher.Done()
		for {
			select {
			case <-stop:
				return
			default:
				am.RefreshThresholds(db.Gorm())
			}
		}
	}()

	// Several reader goroutines: the pre-fix reads are unlocked, so the racy
	// window is the gap between a reader's other lock operations and its bare
	// config read — parallel readers widen the chance the refresher's write
	// lands inside one (the race exists on every iteration; detection needs
	// an interleaving without an accidental happens-before edge).
	group := []*models.FlowDetection{{
		SrcAddr: "203.0.113.9", Detector: "port_scan", Severity: "warning",
		DetectedAt: time.Now(),
	}}
	var readers sync.WaitGroup
	for g := 0; g < 4; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 250; i++ {
				if _, err := am.ProcessSecurityEvent(group, nil); err != nil {
					t.Errorf("ProcessSecurityEvent: %v", err)
				}
				if _, err := am.ProcessSecurityDigest(nil, "port_scan", group); err != nil {
					t.Errorf("ProcessSecurityDigest: %v", err)
				}
				if err := am.CheckProbeDataFlow(); err != nil {
					t.Errorf("CheckProbeDataFlow: %v", err)
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	refresher.Wait()
}
