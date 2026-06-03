package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestFlowSampleIndexes_AUDIT034 verifies that AutoMigrate creates the
// src_addr / dst_addr btree indexes on flow_samples. Without them, every
// connection flow-stats query (which filters `src_addr LIKE ? OR dst_addr
// LIKE ?` with cidrToLikePattern prefixes) full-scans the table.
func TestFlowSampleIndexes_AUDIT034(t *testing.T) {
	db := NewDatabaseForTesting(t)
	mig := db.Gorm().Migrator()
	for _, idx := range []string{"idx_flow_src_addr", "idx_flow_dst_addr"} {
		if !mig.HasIndex(&models.FlowSample{}, idx) {
			t.Errorf("flow_samples is missing index %q (AUDIT-034): connection flow-stats queries full-scan src_addr/dst_addr without it.", idx)
		}
	}
}
