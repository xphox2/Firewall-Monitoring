package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestFlowSampleBGPColumnsRoundTrip verifies the v15 as_path / next_hop columns
// persist and read back through the real SaveFlowSamples path, and that a
// BGP-derived ASN (set on SrcASN/DstASN at ingest) survives. This guards the
// model→column mapping for the extended_gateway enrichment (R5a).
func TestFlowSampleBGPColumnsRoundTrip(t *testing.T) {
	db := NewDatabaseForTesting(t)
	s := models.FlowSample{
		Timestamp: time.Now().Add(-time.Minute), DeviceID: 1, Protocol: 6,
		SrcAddr: "203.0.113.5", DstAddr: "198.51.100.9", SrcPort: 40000, DstPort: 443,
		Bytes: 1000, Packets: 1,
		SrcASN: 64511, DstASN: 64496, // BGP-derived at ingest
		ASPath: "64500 65000 64496", NextHop: "192.0.2.1",
	}
	if err := db.SaveFlowSamples([]models.FlowSample{s}); err != nil {
		t.Fatalf("SaveFlowSamples: %v", err)
	}
	got, err := db.GetFlowSamples(10)
	if err != nil {
		t.Fatalf("GetFlowSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d samples, want 1", len(got))
	}
	r := got[0]
	if r.ASPath != "64500 65000 64496" {
		t.Errorf("ASPath = %q, want %q", r.ASPath, "64500 65000 64496")
	}
	if r.NextHop != "192.0.2.1" {
		t.Errorf("NextHop = %q, want %q", r.NextHop, "192.0.2.1")
	}
	if r.SrcASN != 64511 || r.DstASN != 64496 {
		t.Errorf("ASN round-trip = src %d / dst %d, want 64511 / 64496", r.SrcASN, r.DstASN)
	}
}
