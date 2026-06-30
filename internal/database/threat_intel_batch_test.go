package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestUpsertThreatIntelBatchAndPrune verifies the threat-feed write path: a batch
// upsert is idempotent on (cidr, source), re-upsert refreshes expiry, and
// PruneExpiredThreatIntel removes only expired rows (never NULL-expiry ones).
func TestUpsertThreatIntelBatchAndPrune(t *testing.T) {
	db := NewDatabaseForTesting(t)
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-time.Hour)

	batch := []models.ThreatIntel{
		{CIDR: "203.0.113.0/24", Category: "attacker", Source: "feedA", Severity: "warning", ExpiresAt: &future},
		{CIDR: "198.51.100.9", Category: "attacker", Source: "feedA", Severity: "warning", ExpiresAt: &future},
	}
	if err := db.UpsertThreatIntelBatch(batch); err != nil {
		t.Fatalf("UpsertThreatIntelBatch: %v", err)
	}
	// Re-upsert the same (cidr, source) — must not duplicate.
	if err := db.UpsertThreatIntelBatch(batch); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	active, err := db.CountActiveThreatIntel()
	if err != nil {
		t.Fatalf("CountActiveThreatIntel: %v", err)
	}
	if active != 2 {
		t.Fatalf("active = %d, want 2 (idempotent on cidr+source)", active)
	}

	// Add an expired feed entry + a permanent manual entry (NULL expiry).
	if err := db.UpsertThreatIntelBatch([]models.ThreatIntel{
		{CIDR: "192.0.2.0/24", Category: "attacker", Source: "feedA", Severity: "warning", ExpiresAt: &past},
	}); err != nil {
		t.Fatalf("upsert expired: %v", err)
	}
	if err := db.UpsertThreatIntel(&models.ThreatIntel{CIDR: "10.10.0.0/16", Category: "manual", Source: "manual", Severity: "critical"}); err != nil {
		t.Fatalf("upsert manual: %v", err)
	}

	pruned, err := db.PruneExpiredThreatIntel()
	if err != nil {
		t.Fatalf("PruneExpiredThreatIntel: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1 (only the expired feed entry)", pruned)
	}
	// The permanent manual entry (NULL expiry) must survive.
	all, err := db.ListThreatIntel(100)
	if err != nil {
		t.Fatalf("ListThreatIntel: %v", err)
	}
	var sawManual bool
	for _, e := range all {
		if e.CIDR == "10.10.0.0/16" {
			sawManual = true
		}
		if e.CIDR == "192.0.2.0/24" {
			t.Errorf("expired entry 192.0.2.0/24 should have been pruned")
		}
	}
	if !sawManual {
		t.Error("permanent manual entry (NULL expiry) must not be pruned")
	}
}
