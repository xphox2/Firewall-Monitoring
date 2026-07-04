package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// TestDeleteDevice_ResolvesOpenIncident_LC21 (2026-07-04 audit): deleting a
// device with an open incident used to strand the incident open forever — the
// only resolve path is the device-recovery correlator, which can never fire
// once the device row is gone, and the incidents HTTP surface is read-only.
// DeleteDevice now resolves the device's open incidents (state machine closed,
// row preserved per the telemetry-preservation rule) and leaves other
// devices' incidents alone.
func TestDeleteDevice_ResolvesOpenIncident_LC21(t *testing.T) {
	d := NewDatabaseForTesting(t)

	if err := d.Gorm().Create(&models.Device{ID: 1, Name: "fw-doomed"}).Error; err != nil {
		t.Fatalf("seed device 1: %v", err)
	}
	if err := d.Gorm().Create(&models.Device{ID: 2, Name: "fw-survivor"}).Error; err != nil {
		t.Fatalf("seed device 2: %v", err)
	}
	for _, inc := range []*models.Incident{
		{DeviceID: 1, StartedAt: time.Now().Add(-time.Hour), Severity: models.SeverityCritical, Title: "fw-doomed offline"},
		{DeviceID: 2, StartedAt: time.Now().Add(-time.Hour), Severity: models.SeverityCritical, Title: "fw-survivor offline"},
	} {
		if err := d.CreateIncident(inc); err != nil {
			t.Fatalf("open incident for device %d: %v", inc.DeviceID, err)
		}
	}

	if err := d.DeleteDevice(1); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}

	// The deleted device's incident is resolved with a reason in the title.
	var closed models.Incident
	if err := d.Gorm().Where("device_id = ?", 1).First(&closed).Error; err != nil {
		t.Fatalf("load device-1 incident: %v", err)
	}
	if closed.ResolvedAt == nil {
		t.Fatalf("device-1 incident is still open after DeleteDevice — LC-21 dead-end regression (no code path can ever resolve it)")
	}
	if !strings.Contains(closed.Title, "(device deleted)") {
		t.Errorf("device-1 incident title = %q, want the '(device deleted)' close reason", closed.Title)
	}

	// The surviving device's incident stays open.
	open, err := d.OpenIncidentForDevice(2)
	if err != nil {
		t.Fatalf("OpenIncidentForDevice(2): %v", err)
	}
	if open == nil {
		t.Fatalf("device-2 open incident was closed by an unrelated device delete")
	}

	// The poller's per-cycle open-incidents reload no longer sees the orphan.
	opens, err := d.GetOpenIncidents()
	if err != nil {
		t.Fatalf("GetOpenIncidents: %v", err)
	}
	for _, inc := range opens {
		if inc.DeviceID == 1 {
			t.Errorf("GetOpenIncidents still returns the deleted device's incident %d", inc.ID)
		}
	}
}

// TestCleanupOldData_ResolvedIncidentRetention_LC22 (2026-07-04 audit): the T2
// incidents table (migration v27) had no retention path. CleanupOldData now
// deletes RESOLVED incidents older than the window (aging on resolved_at,
// default = RETENTION_DEFAULT_DAYS like alert history) and never touches open
// incidents, however old.
func TestCleanupOldData_ResolvedIncidentRetention_LC22(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	oldResolved := now.AddDate(0, 0, -100)
	recentResolved := now.AddDate(0, 0, -10)

	seed := []models.Incident{
		{DeviceID: 1, StartedAt: oldResolved.Add(-time.Hour), ResolvedAt: &oldResolved, Title: "old resolved"},
		{DeviceID: 2, StartedAt: recentResolved.Add(-time.Hour), ResolvedAt: &recentResolved, Title: "recent resolved"},
		{DeviceID: 3, StartedAt: now.AddDate(0, 0, -200), Title: "ancient but OPEN"},
	}
	for i := range seed {
		if err := d.Gorm().Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed incident %q: %v", seed[i].Title, err)
		}
	}

	// IncidentDays unset (0) → ret.Days → DefaultDays 30: the 100-day-old
	// resolved incident is past the window, the 10-day-old one is not.
	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 30}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var remaining []models.Incident
	if err := d.Gorm().Order("device_id").Find(&remaining).Error; err != nil {
		t.Fatalf("load incidents: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("want 2 incidents to survive (recent resolved + open), got %d: %+v", len(remaining), remaining)
	}
	if remaining[0].Title != "recent resolved" || remaining[1].Title != "ancient but OPEN" {
		t.Errorf("wrong incidents survived: %q, %q — open incidents must NEVER be deleted and recent resolved ones must be kept",
			remaining[0].Title, remaining[1].Title)
	}
}

// TestCleanupOldData_IncidentKnob_LC22 verifies RETENTION_INCIDENT_DAYS
// overrides the default: with IncidentDays=200 the 100-day-old resolved
// incident survives even though DefaultDays is 30.
func TestCleanupOldData_IncidentKnob_LC22(t *testing.T) {
	d := NewDatabaseForTesting(t)
	resolved := time.Now().AddDate(0, 0, -100)
	if err := d.Gorm().Create(&models.Incident{
		DeviceID: 1, StartedAt: resolved.Add(-time.Hour), ResolvedAt: &resolved, Title: "resolved 100d ago",
	}).Error; err != nil {
		t.Fatalf("seed incident: %v", err)
	}

	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 30, IncidentDays: 200}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var count int64
	d.Gorm().Model(&models.Incident{}).Count(&count)
	if count != 1 {
		t.Errorf("incident deleted despite RETENTION_INCIDENT_DAYS=200 (count=%d)", count)
	}
}
