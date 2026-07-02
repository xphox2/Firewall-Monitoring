package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestUpsertThreatIntelBatch_InBatchDedup_M5 pins the 2026-07-01 audit M5 fix:
// a batch containing duplicate (cidr, source) rows — routine after feed
// normalization masks prefixes, or with repeated lines in aggregate lists —
// must upsert cleanly. On PostgreSQL the pre-fix multi-row INSERT ... ON
// CONFLICT DO UPDATE failed with "cannot affect row a second time" and rolled
// back the WHOLE feed (SQLite tolerated it, which is why tests never caught
// it); the batch is now deduped first, keeping the first occurrence.
func TestUpsertThreatIntelBatch_InBatchDedup_M5(t *testing.T) {
	d := NewDatabaseForTesting(t)

	batch := []models.ThreatIntel{
		{CIDR: "203.0.113.0/24", Source: "feedA", Category: "botnet", Severity: "critical"},
		{CIDR: "203.0.113.0/24", Source: "feedA", Category: "scanner", Severity: "info"}, // in-batch dup
		{CIDR: "198.51.100.0/24", Source: "feedA", Category: "botnet"},
		{CIDR: "203.0.113.0/24", Source: "feedB", Category: "botnet"}, // same CIDR, different source — NOT a dup
	}
	if err := d.UpsertThreatIntelBatch(batch); err != nil {
		t.Fatalf("upsert with in-batch duplicate: %v", err)
	}

	var n int64
	d.db.Model(&models.ThreatIntel{}).Count(&n)
	if n != 3 {
		t.Errorf("stored rows = %d, want 3 (dup collapsed, distinct sources kept)", n)
	}

	// First occurrence wins for the duplicated key.
	var row models.ThreatIntel
	if err := d.db.Where("cidr = ? AND source = ?", "203.0.113.0/24", "feedA").First(&row).Error; err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if row.Category != "botnet" || row.Severity != "critical" {
		t.Errorf("deduped row = %s/%s, want the FIRST occurrence (botnet/critical)", row.Category, row.Severity)
	}

	// Re-upserting the same batch (the every-sync case) must also succeed.
	if err := d.UpsertThreatIntelBatch(batch); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	d.db.Model(&models.ThreatIntel{}).Count(&n)
	if n != 3 {
		t.Errorf("rows after re-upsert = %d, want 3", n)
	}
}
