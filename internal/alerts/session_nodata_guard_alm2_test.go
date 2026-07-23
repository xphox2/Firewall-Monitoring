package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

func setSessionPolicy(am *AlertManager, threshold, clear float64) {
	policy := models.AlertPolicy{
		ID: 1, Name: "test", IsDefault: true,
		Rules: []models.AlertRule{{
			PolicyID: 1, AlertType: models.AlertTypeSessionsHigh,
			Enabled: true, Threshold: threshold, ClearThreshold: clear,
		}},
	}
	am.policyCache = PolicyCache{
		policies:      []models.AlertPolicy{policy},
		policyByID:    map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		defaultPolicy: &policy,
		loaded:        true,
	}
}

func openSessionAlerts(t *testing.T, am *AlertManager, deviceID uint) int64 {
	t.Helper()
	var n int64
	if err := am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND resolved_at IS NULL AND metric_name <> ?",
			deviceID, models.AlertTypeSessionsHigh, "recovery").
		Count(&n).Error; err != nil {
		t.Fatalf("count open session alerts: %v", err)
	}
	return n
}

// TestRowMeasuredSessions documents the AL-M2 inference: only a full SNMP row
// (Uptime>0, no SSH-perf-only fields) is treated as having measured sessions.
func TestRowMeasuredSessions(t *testing.T) {
	cases := []struct {
		name string
		row  *models.SystemStatus
		want bool
	}{
		{"full SNMP row (uptime, no perf fields)", &models.SystemStatus{Uptime: 12345, CPUUsage: 10, MemoryUsage: 20}, true},
		{"ssh-perf partial (uptime 0, perf fields)", &models.SystemStatus{CPUUsage: 10, NetworkInKbps: 100, CPUIdle: 80}, false},
		{"perf field set even with uptime>0", &models.SystemStatus{Uptime: 999, SessionRate1: 5}, false},
		{"empty row", &models.SystemStatus{}, false},
	}
	for _, tc := range cases {
		if got := rowMeasuredSessions(tc.row); got != tc.want {
			t.Errorf("%s: rowMeasuredSessions = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCheckSystemStatus_SessionsHighResolvesAtGenuineZero is the AUDIT AL-M2
// regression: SESSIONS_HIGH must auto-resolve when sessions legitimately fall to
// 0 on an idle device (a full SNMP row, Uptime>0), while a partial SSH-perf row
// (session_count merely absent) must NOT false-resolve it.
func TestCheckSystemStatus_SessionsHighResolvesAtGenuineZero(t *testing.T) {
	am, _ := newTestManager(t)
	setSessionPolicy(am, 10000, 8000)
	const dev = 9

	// Fire SESSIONS_HIGH at 15000 (full row).
	if err := am.CheckSystemStatus(&models.SystemStatus{DeviceID: dev, SessionCount: 15000, Uptime: 1000}, nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 1 {
		t.Fatalf("after fire: %d open, want 1", n)
	}

	// A partial SSH-perf row (session_count=0, uptime 0, perf fields set) must NOT resolve.
	if err := am.CheckSystemStatus(&models.SystemStatus{DeviceID: dev, SessionCount: 0, CPUUsage: 20, MemoryUsage: 40, NetworkInKbps: 100, CPUIdle: 80}, nil); err != nil {
		t.Fatalf("perf row: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 1 {
		t.Fatalf("after partial perf-row 0: %d open, want 1 (must not auto-resolve)", n)
	}

	// A genuine full SNMP row with sessions=0 (idle device, Uptime>0) resolves it.
	if err := am.CheckSystemStatus(&models.SystemStatus{DeviceID: dev, SessionCount: 0, Uptime: 2000, CPUUsage: 5, MemoryUsage: 10}, nil); err != nil {
		t.Fatalf("genuine idle: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 0 {
		t.Fatalf("after genuine idle (full row, sessions=0): %d open, want 0 (AL-M2 stuck-alert fix)", n)
	}
}
