package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetAlertResponseStats_F05 pins the MTTA/MTTR math: operator acks count
// toward MTTA, auto-resolved rows count toward MTTR only, and recovery
// companion rows are excluded entirely.
func TestGetAlertResponseStats_F05(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-2 * time.Hour)

	mk := func(ackAfter, resAfter time.Duration, notes, metric string) models.Alert {
		a := models.Alert{Timestamp: base, DeviceID: 1, AlertType: "CPU_HIGH", Severity: "warning", MetricName: metric, Notes: notes}
		if ackAfter > 0 {
			t := base.Add(ackAfter)
			a.Acknowledged, a.AcknowledgedAt = true, &t
		}
		if resAfter > 0 {
			t := base.Add(resAfter)
			a.ResolvedAt = &t
		}
		return a
	}

	rows := []models.Alert{
		// Operator-acked in 10m, resolved in 30m.
		mk(10*time.Minute, 30*time.Minute, "looked into it", "cpu_usage"),
		// Operator-acked in 20m, never resolved.
		mk(20*time.Minute, 0, "", "cpu_usage"),
		// Auto-resolved in 60m: MTTR yes, MTTA no.
		mk(60*time.Minute, 60*time.Minute, "Auto-resolved: cpu recovered", "cpu_usage"),
		// Recovery companion: excluded from both.
		mk(time.Minute, time.Minute, "", "recovery"),
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	mtta, mttr, acked, resolved, err := d.GetAlertResponseStats(7)
	if err != nil {
		t.Fatalf("GetAlertResponseStats: %v", err)
	}
	if acked != 2 {
		t.Errorf("acked = %d, want 2 (auto-resolve and recovery excluded)", acked)
	}
	if mtta < 14 || mtta > 16 { // (10+20)/2 = 15
		t.Errorf("MTTA = %.1f min, want ≈15", mtta)
	}
	if resolved != 2 {
		t.Errorf("resolved = %d, want 2 (manual + auto)", resolved)
	}
	if mttr < 44 || mttr > 46 { // (30+60)/2 = 45
		t.Errorf("MTTR = %.1f min, want ≈45", mttr)
	}
}

// TestGetNoisiestAlerts_F06: leaderboard groups by (type, device), newest
// window only, ordered by count, with device names joined.
func TestGetNoisiestAlerts_F06(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().Create(&models.Device{ID: 1, Name: "fw-a", IPAddress: "192.0.2.1"}).Error; err != nil {
		t.Fatalf("device: %v", err)
	}
	now := time.Now()
	var rows []models.Alert
	for i := 0; i < 5; i++ { // noisy: CPU on fw-a ×5 (one suppressed)
		rows = append(rows, models.Alert{Timestamp: now.Add(-time.Hour), DeviceID: 1, AlertType: "CPU_HIGH", MetricName: "cpu_usage", Suppressed: i == 0})
	}
	rows = append(rows, models.Alert{Timestamp: now.Add(-time.Hour), DeviceID: 2, AlertType: "VPN_DOWN", MetricName: "vpn_x"})
	rows = append(rows, models.Alert{Timestamp: now.AddDate(0, 0, -40), DeviceID: 1, AlertType: "DISK_HIGH", MetricName: "disk_usage"}) // outside window
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	top, err := d.GetNoisiestAlerts(30, 10)
	if err != nil {
		t.Fatalf("GetNoisiestAlerts: %v", err)
	}
	if len(top) != 2 {
		t.Fatalf("rows = %d, want 2 (40-day-old row excluded)", len(top))
	}
	if top[0].AlertType != "CPU_HIGH" || top[0].Count != 5 || top[0].DeviceName != "fw-a" || top[0].Suppressed != 1 {
		t.Errorf("top row wrong: %+v", top[0])
	}
	if top[1].AlertType != "VPN_DOWN" || top[1].DeviceName != "" {
		t.Errorf("second row wrong (unknown device should have empty name): %+v", top[1])
	}
}
