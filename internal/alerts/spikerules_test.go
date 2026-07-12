package alerts

import (
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// Phase 4b spike evaluator: ProcessSpike/ProcessSpikeResolve route the poller's
// detector decision through the rule engine, non-regressively (global delivery,
// no cooldown, detector severity) with per-rule scope/suppress/severity/policy.

func spikeIface(deviceID uint, name string) *models.InterfaceStats {
	return &models.InterfaceStats{DeviceID: deviceID, Name: name, Index: 1, Status: "up"}
}

func spikeDevice(id uint) *models.Device {
	return &models.Device{ID: id, Name: "fw"}
}

func openSpikeAlerts(t *testing.T, am *AlertManager, deviceID uint, ifaceName string) int64 {
	t.Helper()
	var n int64
	am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL",
			deviceID, models.AlertTypeTrafficSpike, "traffic_"+ifaceName).Count(&n)
	return n
}

func addSpikeRule(t *testing.T, am *AlertManager, db *database.Database, action, severity, dampen string) {
	t.Helper()
	r := &models.EventRule{
		Name: "spike " + action + severity + dampen, Enabled: true, Source: "spike", Action: action,
		Severity: models.Severity(severity), AlertType: models.AlertTypeTrafficSpike,
		MatchJSON: `{"op":"eq","field":"event_type","value":"traffic_spike"}`, DampenJSON: dampen,
	}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatalf("create spike rule: %v", err)
	}
	am.RefreshEventRules(db)
}

// TestSpikeParamsFor_InheritsLiveSettings is the B1 guard: the shipped seed
// (dampen {}) must inherit the operator's live spike settings, not a baked value.
func TestSpikeParamsFor_InheritsLiveSettings(t *testing.T) {
	am, db := newTestManager(t)
	am.config.Alerts.SpikeStdDevThreshold = 5.0 // operator tuned k to 5
	am.config.Alerts.SpikeMinDurationMinutes = 20
	addSpikeRule(t, am, db, "alert", "", `{}`) // seed-shaped: no dampen
	k, minDur := am.SpikeParamsFor(1, nil, "eth0")
	if k != 5.0 {
		t.Errorf("k should inherit live setting 5.0, got %v", k)
	}
	if minDur.Minutes() != 20 {
		t.Errorf("minDur should inherit live 20m, got %v", minDur)
	}
}

func TestSpikeParamsFor_RuleOverrides(t *testing.T) {
	am, db := newTestManager(t)
	am.config.Alerts.SpikeStdDevThreshold = 5.0
	addSpikeRule(t, am, db, "alert", "", `{"stddev_k":8,"min_duration_minutes":30}`)
	k, minDur := am.SpikeParamsFor(1, nil, "eth0")
	if k != 8.0 || minDur.Minutes() != 30 {
		t.Errorf("rule should override to k=8 min=30, got k=%v min=%v", k, minDur)
	}
}

func TestProcessSpike_FiresAndResolves(t *testing.T) {
	am, db := newTestManager(t)
	addSpikeRule(t, am, db, "alert", "", `{}`)
	dev, iface := spikeDevice(1), spikeIface(1, "eth0")

	am.ProcessSpike(dev, iface, "warning", 1e9, 1e8, "spike", nil)
	if n := openSpikeAlerts(t, am, 1, "eth0"); n != 1 {
		t.Fatalf("fire: want 1 open spike alert, got %d", n)
	}
	// The severity is the detector's, not a resolved default.
	var got models.Alert
	am.db.Gorm().Where("alert_type = ? AND resolved_at IS NULL", models.AlertTypeTrafficSpike).First(&got)
	if got.Severity != "warning" {
		t.Errorf("severity should be the detector's warning, got %q", got.Severity)
	}
	// Resolve closes the open row.
	am.ProcessSpikeResolve(dev, iface, "normal", nil)
	if n := openSpikeAlerts(t, am, 1, "eth0"); n != 0 {
		t.Fatalf("resolve must close the open row, got %d open", n)
	}
}

func TestProcessSpike_SuppressRuleDrops(t *testing.T) {
	am, db := newTestManager(t)
	addSpikeRule(t, am, db, "suppress", "", "")
	dev, iface := spikeDevice(1), spikeIface(1, "eth0")
	am.ProcessSpike(dev, iface, "critical", 1e9, 1e8, "spike", nil)
	if n := openSpikeAlerts(t, am, 1, "eth0"); n != 0 {
		t.Fatalf("suppress rule must drop the spike, got %d", n)
	}
}

func TestProcessSpike_RuleSeverityOverride(t *testing.T) {
	am, db := newTestManager(t)
	addSpikeRule(t, am, db, "alert", "critical", `{}`)
	dev, iface := spikeDevice(1), spikeIface(1, "eth0")
	am.ProcessSpike(dev, iface, "warning", 1e9, 1e8, "spike", nil) // detector warning, rule forces critical
	var got models.Alert
	am.db.Gorm().Where("alert_type = ? AND resolved_at IS NULL", models.AlertTypeTrafficSpike).First(&got)
	if got.Severity != "critical" {
		t.Errorf("rule severity should override the detector's, got %q", got.Severity)
	}
}

// TestProcessSpike_NoRuleStillFires: even with the seed deleted (no spike rule),
// spike still fires via the fallback (global delivery) — non-regressive.
func TestProcessSpike_NoRuleStillFires(t *testing.T) {
	am, db := newTestManager(t)
	am.RefreshEventRules(db) // no spike rules
	dev, iface := spikeDevice(1), spikeIface(1, "eth0")
	am.ProcessSpike(dev, iface, "warning", 1e9, 1e8, "spike", nil)
	if n := openSpikeAlerts(t, am, 1, "eth0"); n != 1 {
		t.Fatalf("spike must fire even with no rule, got %d", n)
	}
}
