package database

import (
	"encoding/json"
	"testing"

	"firewall-mon/internal/models"
)

// TestFlowInterfaceCounter_IfDirectionPersists_L12 pins the 2026-07-01 audit L12
// fix: the collector sends the sFlow ifDirection field as JSON `if_direction` on
// the schema-v2 counter wire form, but the server model lacked the column, so
// the value was silently dropped at ingest. It must now both (a) bind from JSON
// and (b) survive a DB round-trip.
func TestFlowInterfaceCounter_IfDirectionPersists_L12(t *testing.T) {
	// (a) JSON bind — the exact shape ReceiveFlowCounterSamples decodes.
	const wire = `[{"device_id":4,"if_index":7,"if_speed":1000000000,"if_direction":2,"if_status":3,"in_octets":100,"out_octets":200}]`
	var got []models.FlowInterfaceCounter
	if err := json.Unmarshal([]byte(wire), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0].IfDirection != 2 {
		t.Fatalf("if_direction not bound from JSON: %+v", got)
	}

	// (b) DB round-trip — the column exists and preserves the value.
	d := NewDatabaseForTesting(t)
	got[0].ProbeID = 1
	if err := d.SaveFlowInterfaceCounters(got); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := d.GetLatestInterfaceCounter(4, 7)
	if err != nil || back == nil {
		t.Fatalf("get: %v (nil=%v)", err, back == nil)
	}
	if back.IfDirection != 2 {
		t.Errorf("IfDirection round-trip = %d, want 2", back.IfDirection)
	}
}
