package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestFlowDetectionPersistence covers the Save → GetRecent → Ack round-trip and
// the unackedOnly + since filters.
func TestFlowDetectionPersistence(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().UTC()

	recent := &models.FlowDetection{
		DetectedAt: now.Add(-1 * time.Minute), WindowStart: now.Add(-16 * time.Minute), WindowEnd: now,
		Detector: "cleartext", Category: "policy", Severity: "warning",
		DeviceID: 1, DstPort: 23, Protocol: 6, Score: 5000,
		Message: "Cleartext Telnet", DedupKey: "cleartext_1_23",
	}
	old := &models.FlowDetection{
		DetectedAt: now.Add(-3 * time.Hour), Detector: "capacity", Category: "operational",
		Severity: "warning", DeviceID: 2, DedupKey: "capacity_2_7", Message: "old",
	}
	if err := db.SaveFlowDetection(recent); err != nil {
		t.Fatalf("save recent: %v", err)
	}
	if err := db.SaveFlowDetection(old); err != nil {
		t.Fatalf("save old: %v", err)
	}

	// Window of 1h excludes the 3h-old row.
	rows, err := db.GetRecentDetections(now.Add(-1*time.Hour), 100, true)
	if err != nil {
		t.Fatalf("get recent: %v", err)
	}
	if len(rows) != 1 || rows[0].Detector != "cleartext" {
		t.Fatalf("GetRecentDetections = %+v, want only the recent cleartext row", rows)
	}

	// Ack the recent one; unackedOnly should now return nothing.
	if err := db.AckFlowDetection(rows[0].ID); err != nil {
		t.Fatalf("ack: %v", err)
	}
	unacked, err := db.GetRecentDetections(now.Add(-1*time.Hour), 100, true)
	if err != nil {
		t.Fatalf("get unacked: %v", err)
	}
	if len(unacked) != 0 {
		t.Errorf("after ack, unacked list = %+v, want empty", unacked)
	}
	// Without unackedOnly the acked row is still returned.
	all, err := db.GetRecentDetections(now.Add(-1*time.Hour), 100, false)
	if err != nil {
		t.Fatalf("get all: %v", err)
	}
	if len(all) != 1 || !all[0].Acknowledged {
		t.Errorf("GetRecentDetections(all) = %+v, want 1 acked row", all)
	}
}
