package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestIncidentGrouping_F12 drives the full storm story: device goes offline
// (incident opens, offline alert attaches + notifies), subsequent alerts for
// the device attach and are muted, recovery closes the incident with a
// summary, and a healthy device elsewhere is untouched.
func TestIncidentGrouping_F12(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	dev := &models.Device{ID: 60, Name: "fw-edge", IPAddress: "192.0.2.60"}

	// 1. Offline fires → incident opens, offline alert attached.
	if err := am.CheckDeviceOffline(dev); err != nil {
		t.Fatalf("CheckDeviceOffline: %v", err)
	}
	var inc models.Incident
	if err := db.Gorm().Where("device_id = ? AND resolved_at IS NULL", dev.ID).First(&inc).Error; err != nil {
		t.Fatalf("incident not opened: %v", err)
	}
	var offline models.Alert
	if err := db.Gorm().Where("device_id = ? AND alert_type = ?", dev.ID, "DEVICE_OFFLINE").First(&offline).Error; err != nil {
		t.Fatalf("offline alert: %v", err)
	}
	if offline.IncidentID == nil || *offline.IncidentID != inc.ID {
		t.Errorf("offline alert not attached to incident: %+v", offline.IncidentID)
	}

	// 2. A CPU alert during the outage attaches to the incident.
	if err := am.CheckSystemStatus(cpuStatus(dev.ID, 95), nil); err != nil {
		t.Fatalf("CheckSystemStatus: %v", err)
	}
	var cpu models.Alert
	if err := db.Gorm().Where("device_id = ? AND alert_type = ?", dev.ID, models.AlertTypeCPUHigh).First(&cpu).Error; err != nil {
		t.Fatalf("cpu alert: %v", err)
	}
	if cpu.IncidentID == nil || *cpu.IncidentID != inc.ID {
		t.Errorf("storm alert not attached: %+v", cpu.IncidentID)
	}

	// 3. A different, healthy device is NOT grouped.
	if err := am.CheckSystemStatus(cpuStatus(61, 95), nil); err != nil {
		t.Fatalf("other device: %v", err)
	}
	var other models.Alert
	if err := db.Gorm().Where("device_id = 61").First(&other).Error; err != nil {
		t.Fatalf("other alert: %v", err)
	}
	if other.IncidentID != nil {
		t.Errorf("unrelated device grouped into incident: %v", *other.IncidentID)
	}

	// 4. Recovery closes the incident with a summary alert and a final count.
	am.CheckDeviceOnline(dev)
	var closed models.Incident
	if err := db.Gorm().First(&closed, inc.ID).Error; err != nil {
		t.Fatalf("closed incident: %v", err)
	}
	if closed.ResolvedAt == nil {
		t.Fatal("incident not resolved on device recovery")
	}
	if closed.AlertCount < 2 {
		t.Errorf("alert count = %d, want ≥2 (offline + cpu)", closed.AlertCount)
	}
	var summary models.Alert
	if err := db.Gorm().Where("device_id = ? AND alert_type = ?", dev.ID, "INCIDENT_RESOLVED").First(&summary).Error; err != nil {
		t.Fatalf("summary alert missing: %v", err)
	}
	if summary.IncidentID == nil || *summary.IncidentID != inc.ID {
		t.Errorf("summary not linked to incident")
	}

	// 5. After resolution, new alerts are NOT grouped anymore: recover the
	// CPU condition (resolves the open row so the restart-dedup won't gate),
	// clear the in-memory cooldown, and re-fire.
	if err := am.CheckSystemStatus(cpuStatus(dev.ID, 50), nil); err != nil {
		t.Fatalf("cpu recovery: %v", err)
	}
	am.mu.Lock()
	delete(am.lastAlert, "cpu_high_60")
	am.mu.Unlock()
	if err := am.CheckSystemStatus(cpuStatus(dev.ID, 95), nil); err != nil {
		t.Fatalf("post-recovery fire: %v", err)
	}
	var post models.Alert
	if err := db.Gorm().Where("device_id = ? AND alert_type = ? AND metric_name <> ?", dev.ID, models.AlertTypeCPUHigh, "recovery").
		Order("id DESC").First(&post).Error; err != nil {
		t.Fatalf("post-recovery alert: %v", err)
	}
	if post.IncidentID != nil {
		t.Errorf("post-recovery alert still grouped: %v", *post.IncidentID)
	}
}

// TestIncidentIdempotent_ReopenReuses: a second offline fire while the
// incident is open reuses it rather than opening a duplicate.
func TestIncidentIdempotent_ReopenReuses(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	dev := &models.Device{ID: 62, Name: "fw2", IPAddress: "192.0.2.62"}

	if inc := am.openIncident(dev, "critical"); inc == nil {
		t.Fatal("first openIncident failed")
	}
	second := am.openIncident(dev, "critical")
	if second == nil {
		t.Fatal("second openIncident failed")
	}
	var n int64
	db.Gorm().Model(&models.Incident{}).Where("device_id = ? AND resolved_at IS NULL", dev.ID).Count(&n)
	if n != 1 {
		t.Errorf("open incidents for device = %d, want 1", n)
	}
}
