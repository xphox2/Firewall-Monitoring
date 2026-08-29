package handlers

import (
	"sync"
	"testing"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestHandlerConfigFallbacks_RaceWithRefresh_Audit250: the API process shares
// ONE config.Config between its handlers and its AlertManager, whose
// RefreshThresholds rewrites config.Alerts field-by-field under the manager's
// lock — while alertGlobalDefaults, getNotificationSetting's fallback switch
// and the report resolvers read the same struct through a bare h.config
// dereference. Run with -race: fails before the AUDIT-250 snapshot routing,
// passes after. Handlers built WITHOUT a manager keep the direct config read
// (the nil path), which the rest of the handler test suite exercises.
func TestHandlerConfigFallbacks_RaceWithRefresh_Audit250(t *testing.T) {
	h, db := setupTestHandler(t)
	// The :memory: test DB is per-connection — a second pooled connection sees
	// an EMPTY database. Concurrent goroutines need the pool pinned to the one
	// connection that ran the migrations.
	if sqlDB, err := db.Gorm().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	am := alerts.NewAlertManager(h.config, notifier.NewNotifier(h.config), db)
	h.SetAlertManager(am)

	// The readers' settings queries go to a SEPARATE database handle. This is
	// load-bearing for -race, not a convenience: with the refresher and the
	// readers sharing one serialized SQLite pool, every pool hand-off is a
	// happens-before edge that orders the refresher's config writes ahead of
	// the readers' config reads — the race exists on every iteration but the
	// detector can no longer observe it. An independent pool leaves the shared
	// config.Alerts struct as the ONLY connection between the two sides.
	readerDB := database.NewDatabaseForTesting(t)
	if sqlDB, err := readerDB.Gorm().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	// Seed every threshold/spike setting so RefreshThresholds WRITES the same
	// config.Alerts fields alertGlobalDefaults reads unconditionally — that
	// write/read pair is what -race must observe. The readers' settings DB
	// stays empty so their fallback path (the racy config read) executes.
	for k, v := range map[string]string{
		"cpu_threshold":              "91",
		"memory_threshold":           "92",
		"disk_threshold":             "93",
		"session_threshold":          "1000",
		"spike_stddev_threshold":     "3.5",
		"spike_alert_enabled":        "true",
		"spike_min_duration_minutes": "10",
		"spike_min_throughput_mbps":  "2",
		"smtp_host":                  "smtp.example.com",
	} {
		if err := db.UpsertSetting(&models.SystemSetting{Key: k, Value: v, Category: "alerts", Type: "string"}); err != nil {
			t.Fatalf("seed setting %s: %v", k, err)
		}
	}

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

	var readers sync.WaitGroup
	// Pure alertGlobalDefaults readers: these goroutines touch ONLY the
	// isolated readerDB, so nothing orders them against the refresher and the
	// pre-fix race is reliably observable.
	for g := 0; g < 2; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 400; i++ {
				_ = h.alertGlobalDefaults(readerDB)
			}
		}()
	}
	// The remaining routed readers resolve through h.db (the shared handle) —
	// raced here for coverage of every AUDIT-250 path, though the pool
	// hand-offs they perform give the detector fewer clean windows than the
	// goroutines above.
	readers.Add(1)
	go func() {
		defer readers.Done()
		for i := 0; i < 200; i++ {
			_ = h.getNotificationSetting("smtp_from") // unseeded → config fallback
			_ = h.reportTimezone()
			_ = h.reportSpikeThreshold()
			_ = h.reportSpikeFloorMbps()
		}
	}()
	readers.Wait()
	close(stop)
	refresher.Wait()
}
