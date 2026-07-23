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

// TestCheckSystemStatus_SessionsHighResolvesOnlyFromSNMPZero is the AUDIT AL-M2
// regression, done via the explicit Source column (the field-shape inference
// was proven unsound — both writers share Uptime/NetworkInKbps). SESSIONS_HIGH
// must auto-resolve when a full SNMP poll reports 0 sessions (idle device), but
// a supplementary SSH-perf row or a legacy empty-Source row with session_count=0
// must NOT false-resolve it.
func TestCheckSystemStatus_SessionsHighResolvesOnlyFromSNMPZero(t *testing.T) {
	am, _ := newTestManager(t)
	setSessionPolicy(am, 10000, 8000)
	const dev = 9

	// Fire SESSIONS_HIGH at 15000 (SNMP full poll).
	if err := am.CheckSystemStatus(&models.SystemStatus{
		DeviceID: dev, SessionCount: 15000, Source: models.SystemStatusSourceSNMP,
	}, nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 1 {
		t.Fatalf("after fire: %d open, want 1", n)
	}

	// A supplementary SSH-perf row reporting 0 sessions must NOT resolve.
	if err := am.CheckSystemStatus(&models.SystemStatus{
		DeviceID: dev, SessionCount: 0, Source: models.SystemStatusSourceSSHPerf,
	}, nil); err != nil {
		t.Fatalf("ssh-perf row: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 1 {
		t.Fatalf("after ssh-perf 0: %d open, want 1 (supplementary row must not auto-resolve)", n)
	}

	// A legacy row with no Source (pre-Source collector) must also NOT resolve.
	if err := am.CheckSystemStatus(&models.SystemStatus{
		DeviceID: dev, SessionCount: 0, Source: "",
	}, nil); err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 1 {
		t.Fatalf("after legacy empty-source 0: %d open, want 1 (fails safe)", n)
	}

	// A full SNMP poll reporting 0 sessions (genuinely idle) resolves it.
	if err := am.CheckSystemStatus(&models.SystemStatus{
		DeviceID: dev, SessionCount: 0, Source: models.SystemStatusSourceSNMP,
	}, nil); err != nil {
		t.Fatalf("snmp idle: %v", err)
	}
	if n := openSessionAlerts(t, am, dev); n != 0 {
		t.Fatalf("after SNMP idle (sessions=0): %d open, want 0 (AL-M2 stuck-alert fix)", n)
	}
}
