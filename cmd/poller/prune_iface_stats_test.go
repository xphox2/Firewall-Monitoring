package main

import (
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestPruneStaleIfaceStats verifies that prevIfaceStats entries older than the
// TTL (decommissioned devices / removed interfaces) are dropped while recently
// refreshed entries are retained, so the map cannot grow without bound.
func TestPruneStaleIfaceStats(t *testing.T) {
	now := time.Now()
	p := &Poller{
		prevIfaceStats: map[string]*models.InterfaceStats{
			"1_port1": {Timestamp: now},                        // fresh: keep
			"1_port2": {Timestamp: now.Add(-30 * time.Minute)}, // within TTL: keep
			"2_port1": {Timestamp: now.Add(-2 * time.Hour)},    // stale: drop
			"3_port1": nil,                                     // nil value: drop
		},
		ifaceStatsMu: sync.RWMutex{},
	}

	p.pruneStaleIfaceStats(time.Hour)

	if _, ok := p.prevIfaceStats["1_port1"]; !ok {
		t.Error("fresh entry 1_port1 was pruned")
	}
	if _, ok := p.prevIfaceStats["1_port2"]; !ok {
		t.Error("within-TTL entry 1_port2 was pruned")
	}
	if _, ok := p.prevIfaceStats["2_port1"]; ok {
		t.Error("stale entry 2_port1 was not pruned")
	}
	if _, ok := p.prevIfaceStats["3_port1"]; ok {
		t.Error("nil entry 3_port1 was not pruned")
	}
	if len(p.prevIfaceStats) != 2 {
		t.Errorf("expected 2 entries after prune, got %d", len(p.prevIfaceStats))
	}
}
