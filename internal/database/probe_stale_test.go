package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestMarkStaleProbesOffline verifies the probe staleness sweep flips only
// online probes whose last heartbeat predates the threshold, and returns them.
func TestMarkStaleProbesOffline(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	probes := []models.Probe{
		{Name: "fresh", RegistrationKey: "k-fresh", Status: "online", ApprovalStatus: "approved", LastSeen: now.Add(-1 * time.Minute)},
		{Name: "stale", RegistrationKey: "k-stale", Status: "online", ApprovalStatus: "approved", LastSeen: now.Add(-30 * time.Minute)},
		{Name: "already-offline", RegistrationKey: "k-off", Status: "offline", ApprovalStatus: "approved", LastSeen: now.Add(-30 * time.Minute)},
	}
	if err := db.Gorm().Create(&probes).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	threshold := now.Add(-5 * time.Minute)
	transitioned, err := db.MarkStaleProbesOffline(threshold)
	if err != nil {
		t.Fatalf("MarkStaleProbesOffline: %v", err)
	}
	if len(transitioned) != 1 || transitioned[0].Name != "stale" {
		t.Fatalf("transitioned = %+v, want exactly [stale]", transitioned)
	}

	// Verify persisted state: only "stale" flipped; "fresh" stays online.
	got := map[string]string{}
	var all []models.Probe
	if err := db.Gorm().Find(&all).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	for _, p := range all {
		got[p.Name] = p.Status
	}
	if got["fresh"] != "online" {
		t.Errorf("fresh probe should stay online, got %q", got["fresh"])
	}
	if got["stale"] != "offline" {
		t.Errorf("stale probe should be offline, got %q", got["stale"])
	}

	// Idempotent: a second sweep finds nothing new.
	again, err := db.MarkStaleProbesOffline(threshold)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second sweep should transition 0, got %d", len(again))
	}
}
