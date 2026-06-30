package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestFlowInterfaceCounterRoundTrip verifies sFlow interface counter samples
// persist via SaveFlowInterfaceCounters and that GetLatestInterfaceCounter
// returns the most recent row for a (device, ifIndex) — the source the capacity
// detector falls back to when SNMP ifSpeed is unavailable.
func TestFlowInterfaceCounterRoundTrip(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	rows := []models.FlowInterfaceCounter{
		{Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, IfIndex: 5, IfSpeed: 1_000_000_000, InOctets: 100, OutOctets: 200},
		{Timestamp: now.Add(-1 * time.Minute), DeviceID: 1, IfIndex: 5, IfSpeed: 1_000_000_000, InOctets: 500, OutOctets: 900, InErrors: 3},
		{Timestamp: now.Add(-1 * time.Minute), DeviceID: 1, IfIndex: 6, IfSpeed: 10_000_000_000, InOctets: 1, OutOctets: 2},
	}
	if err := db.SaveFlowInterfaceCounters(rows); err != nil {
		t.Fatalf("SaveFlowInterfaceCounters: %v", err)
	}

	latest, err := db.GetLatestInterfaceCounter(1, 5)
	if err != nil {
		t.Fatalf("GetLatestInterfaceCounter: %v", err)
	}
	if latest == nil {
		t.Fatal("expected a counter row, got nil")
	}
	if latest.InOctets != 500 || latest.OutOctets != 900 || latest.InErrors != 3 {
		t.Errorf("latest = in %d / out %d / inErr %d, want 500 / 900 / 3", latest.InOctets, latest.OutOctets, latest.InErrors)
	}
	if latest.IfSpeed != 1_000_000_000 {
		t.Errorf("IfSpeed = %d, want 1e9", latest.IfSpeed)
	}

	// Unknown (device, ifIndex) returns nil, not an error.
	none, err := db.GetLatestInterfaceCounter(99, 99)
	if err != nil {
		t.Fatalf("GetLatestInterfaceCounter(unknown): %v", err)
	}
	if none != nil {
		t.Errorf("expected nil for unknown interface, got %+v", none)
	}
}
