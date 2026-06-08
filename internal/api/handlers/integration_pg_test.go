//go:build integration

// Cross-package end-to-end integration test (AUDIT-123). The database-package
// integration suite (AUDIT-118) verifies Postgres-specific DB paths in
// isolation; this verifies the FULL stack — gin handler → probe auth →
// SaveSystemStatus → real Postgres (partitioned) → query-back — which neither
// the SQLite unit tests nor the db-only suite exercise. Behind
// `//go:build integration`; skips unless TEST_PG_DSN is set.
package handlers

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func TestEndToEndIngestion_Postgres_AUDIT123(t *testing.T) {
	db := database.NewIntegrationDB(t) // skips if TEST_PG_DSN unset
	if err := db.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	h := NewHandler(&config.Config{}, nil, db)
	probe, device := setupProbeAndDevice(t, db) // reuses the shared (untagged) test harness

	now := time.Now().UTC()
	statuses := []map[string]interface{}{{
		"device_id":    device.ID,
		"probe_id":     probe.ID,
		"timestamp":    now,
		"cpu_usage":    42.0,
		"memory_usage": 71.0,
	}}

	// Drive a real HTTP request through the handler (incl. Bearer probe auth).
	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey, statuses)
	if w.Code != http.StatusOK {
		t.Fatalf("ingestion status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// 1) The row persisted on real Postgres.
	var count int64
	db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 1 {
		t.Fatalf("system_status rows for device %d = %d, want 1", device.ID, count)
	}

	// 2) It routed into the current-month partition — proves the partitioned-write
	//    path works end-to-end through the handler, not just a direct Create.
	child := fmt.Sprintf("system_status_%d%02d", now.Year(), int(now.Month()))
	var inChild int64
	if err := db.Gorm().Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE device_id = ?", child), device.ID).Scan(&inChild).Error; err != nil {
		t.Fatalf("count in child partition %s: %v", child, err)
	}
	if inChild != 1 {
		t.Fatalf("row did not route into current-month partition %s (got %d)", child, inChild)
	}

	// 3) The handler's side effect — marking the device online — hit real PG.
	got, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.Status != "online" {
		t.Fatalf("device status = %q, want online (ingestion should mark it online)", got.Status)
	}

	// 4) Round-trip the value back so we confirm it's readable through the same
	//    query path the dashboard uses.
	var cpu float64
	if err := db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", device.ID).
		Select("cpu_usage").Scan(&cpu).Error; err != nil {
		t.Fatalf("read back cpu_usage: %v", err)
	}
	if cpu != 42.0 {
		t.Fatalf("round-tripped cpu_usage = %v, want 42", cpu)
	}
}
