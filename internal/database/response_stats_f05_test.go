package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetAlertResponseStats_F05 pins the MTTA/MTTR math: operator acks count
// toward MTTA, auto-resolved rows count toward MTTR only, and synthetic
// companion rows (recovery records AND F12 incident summaries, LC-27) are
// excluded entirely — both are instant-acked and would bias the averages
// toward zero.
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
		// F12 incident summary companion (closeIncident sets ack=resolve=now,
		// a zero-minute sample): excluded from both (LC-27).
		mk(time.Second, time.Second, "", "incident"),
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	mtta, mttr, acked, resolved, err := d.GetAlertResponseStats(7)
	if err != nil {
		t.Fatalf("GetAlertResponseStats: %v", err)
	}
	if acked != 2 {
		t.Errorf("acked = %d, want 2 (auto-resolve, recovery and incident rows excluded)", acked)
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

// TestGetAlertResponseStats_Deterministic pins AUDIT-266: with SQL-side
// aggregation the whole trailing window is summarised (not an arbitrary
// DB-ordered slice), so the result is independent of row/insertion order, and
// rows older than the window are excluded. MTTA excludes auto-resolved rows;
// MTTR includes them.
func TestGetAlertResponseStats_Deterministic(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	mk := func(ts time.Time, ackAfter, resAfter time.Duration, notes string) models.Alert {
		a := models.Alert{Timestamp: ts, DeviceID: 1, AlertType: "CPU_HIGH", Severity: "warning", MetricName: "cpu_usage", Notes: notes}
		if ackAfter > 0 {
			tt := ts.Add(ackAfter)
			a.Acknowledged, a.AcknowledgedAt = true, &tt
		}
		if resAfter > 0 {
			tt := ts.Add(resAfter)
			a.ResolvedAt = &tt
		}
		return a
	}

	rows := []models.Alert{
		mk(now.Add(-1*time.Hour), 5*time.Minute, 10*time.Minute, "looked into it"),
		mk(now.Add(-2*time.Hour), 15*time.Minute, 0, ""),
		mk(now.Add(-3*time.Hour), 0, 40*time.Minute, "Auto-resolved: recovered"),
		// Older than the 7-day window: excluded regardless of insertion order.
		mk(now.AddDate(0, 0, -8), 100*time.Minute, 100*time.Minute, ""),
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	mtta, mttr, acked, resolved, err := d.GetAlertResponseStats(7)
	if err != nil {
		t.Fatalf("GetAlertResponseStats: %v", err)
	}
	if acked != 2 {
		t.Errorf("acked = %d, want 2 (old row excluded; auto-resolved not acked)", acked)
	}
	if mtta < 9.5 || mtta > 10.5 { // (5+15)/2 = 10
		t.Errorf("MTTA = %.2f min, want ≈10", mtta)
	}
	if resolved != 2 {
		t.Errorf("resolved = %d, want 2 (old row excluded; manual + auto)", resolved)
	}
	if mttr < 24.5 || mttr > 25.5 { // (10+40)/2 = 25
		t.Errorf("MTTR = %.2f min, want ≈25", mttr)
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
	rows = append(rows, models.Alert{Timestamp: now.AddDate(0, 0, -40), DeviceID: 1, AlertType: "DISK_HIGH", MetricName: "disk_usage"})          // outside window
	rows = append(rows, models.Alert{Timestamp: now.Add(-time.Hour), DeviceID: 1, AlertType: "INCIDENT_RESOLVED", MetricName: "incident"})       // F12 summary: excluded (LC-27)
	rows = append(rows, models.Alert{Timestamp: now.Add(-time.Hour), DeviceID: 1, AlertType: "DEVICE_OFFLINE_RESOLVED", MetricName: "recovery"}) // companion: excluded
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
