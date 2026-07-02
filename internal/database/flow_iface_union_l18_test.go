package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetLatestInterfaceCountersByDevice_L18 pins the 2026-07-01 audit L18
// helper: it returns exactly one row per distinct if_index (the most recent),
// which the device-detail handler unions into the interface list so an
// SNMP-host-restricted device that only pushes sFlow if_counters still renders
// interface cards and can reach the sflow-chart endpoint.
func TestGetLatestInterfaceCountersByDevice_L18(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Unix(1_700_000_000, 0)

	rows := []models.FlowInterfaceCounter{
		{DeviceID: 9, ProbeID: 1, IfIndex: 2, InOctets: 100, Timestamp: base},
		{DeviceID: 9, ProbeID: 1, IfIndex: 2, InOctets: 250, Timestamp: base.Add(time.Minute)}, // newer for if 2
		{DeviceID: 9, ProbeID: 1, IfIndex: 5, InOctets: 700, Timestamp: base},
		{DeviceID: 8, ProbeID: 1, IfIndex: 2, InOctets: 999, Timestamp: base}, // other device — excluded
	}
	if err := d.SaveFlowInterfaceCounters(rows); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := d.GetLatestInterfaceCountersByDevice(9)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (one per distinct if_index of device 9)", len(got))
	}
	byIdx := map[uint32]models.FlowInterfaceCounter{}
	for _, c := range got {
		byIdx[c.IfIndex] = c
	}
	if byIdx[2].InOctets != 250 {
		t.Errorf("if_index 2 InOctets = %d, want 250 (latest row)", byIdx[2].InOctets)
	}
	if _, ok := byIdx[5]; !ok {
		t.Error("if_index 5 missing")
	}
}
