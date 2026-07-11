package main

import (
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// newTestPoller builds a Poller over an in-memory test database. Shared by the
// connection-detector and relayed-telemetry tests. No alert manager and spike
// detection off by default — tests that need alerting wire their own.
func newTestPoller(t *testing.T) (*Poller, *database.Database) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	p := &Poller{
		cfg:            &config.Config{},
		db:             db,
		prevIfaceStats: make(map[string]*models.InterfaceStats),
	}
	return p, db
}
