//go:build integration

package database

import "testing"

// TestClaimTOTPCode_PG runs the D-14 claim contract on PostgreSQL (ON
// CONFLICT DO NOTHING, the bigint expiry compare) on a schema built by the
// registered migrations.
func TestClaimTOTPCode_PG(t *testing.T) {
	d := NewIntegrationDB(t) // runs every registered migration, v83 included
	checkClaimTOTPCode(t, d)
}
