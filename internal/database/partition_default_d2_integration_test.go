//go:build integration

// AUDIT D2 (Postgres-only): partitioned parents must have a DEFAULT partition so
// a row whose timestamp falls outside the current±6-month window (backward clock
// skew, month-boundary batch) lands in the default instead of failing the whole
// insert with SQLSTATE 23514 "no partition of relation found for row".
package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestD2_DefaultPartition_AcceptsBackdatedRow(t *testing.T) {
	d := NewIntegrationDB(t) // runs migrations incl. v51 (default partitions)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	if !pgIsPartitioned(t, d, "system_status") {
		t.Fatal("system_status is not a partitioned parent")
	}

	var hasDefault bool
	if err := d.Gorm().Raw(
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'system_status_default')`).
		Scan(&hasDefault).Error; err != nil {
		t.Fatalf("probe default partition: %v", err)
	}
	if !hasDefault {
		t.Fatal("AUDIT D2: system_status_default partition was not created by the migration/EnsurePartitions")
	}

	// A row 2 months in the past has no monthly partition (EnsurePartitions only
	// creates current + 6 FUTURE months). Before D2 this errored 23514; with the
	// default partition it must insert cleanly.
	backdated := time.Now().AddDate(0, -2, 0)
	row := models.SystemStatus{DeviceID: 1, Timestamp: backdated, CPUUsage: 5}
	if err := d.Gorm().Create(&row).Error; err != nil {
		t.Fatalf("backdated insert should land in the DEFAULT partition, got: %v", err)
	}

	var got int64
	if err := d.Gorm().Model(&models.SystemStatus{}).Where("device_id = 1").Count(&got).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != 1 {
		t.Fatalf("expected 1 backdated row queryable via the parent, got %d", got)
	}

	// And it physically resides in the default child.
	var inDefault int64
	if err := d.Gorm().Raw(`SELECT count(*) FROM system_status_default WHERE device_id = 1`).
		Scan(&inDefault).Error; err != nil {
		t.Fatalf("count in default: %v", err)
	}
	if inDefault != 1 {
		t.Fatalf("expected the backdated row in system_status_default, got %d", inDefault)
	}
}

// TestD4_SessionTimeZoneIsUTC proves AUDIT D4: the app pins the PG session time
// zone to UTC on every connection (via the DSN), so chart bucketing's UTC
// assumption holds even when the server's default TimeZone is not UTC (this
// scratch PG defaults to America/Toronto — exactly the drift case D4 fixes).
func TestD4_SessionTimeZoneIsUTC(t *testing.T) {
	d := NewIntegrationDB(t)
	var tz string
	if err := d.Gorm().Raw("SHOW TimeZone").Scan(&tz).Error; err != nil {
		t.Fatalf("SHOW TimeZone: %v", err)
	}
	if tz != "UTC" {
		t.Fatalf("AUDIT D4: session TimeZone = %q, want UTC", tz)
	}
}
