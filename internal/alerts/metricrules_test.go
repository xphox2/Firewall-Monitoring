package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// Phase 4a metric evaluator: when cpu_high is owned, CheckSystemStatus routes
// through the matching metric rule (override-else-inherit). The crux is
// non-regression — a shipped seed (no threshold) fires exactly like the legacy
// path.

// addCPUMetricRule installs an enabled source="metric" rule for CPU_HIGH with the
// given action/severity/dampen, flips ownership for cpu_high, and refreshes.
func addCPUMetricRule(t *testing.T, am *AlertManager, db *database.Database, action, severity, dampen string) {
	t.Helper()
	r := &models.EventRule{
		Name: "CPU rule " + action + severity + dampen, Enabled: true, Source: "metric", Action: action,
		Severity: models.Severity(severity), AlertType: models.AlertTypeCPUHigh,
		MatchJSON: `{"op":"eq","field":"event_type","value":"cpu_high"}`, DampenJSON: dampen,
	}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatalf("create metric rule: %v", err)
	}
	if err := db.UpsertSetting(&models.SystemSetting{Key: "state_engine_owns", Value: "cpu_high"}); err != nil {
		t.Fatalf("set ownership: %v", err)
	}
	am.RefreshEventRules(db)
}

func TestMetricRule_InheritsThreshold_NonRegressive(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0) // policy CPU threshold 90
	addCPUMetricRule(t, am, db, "alert", "", `{"mode":"static"}`)
	const dev = 7

	// Below the inherited threshold → no alert (proves it didn't fire at 0).
	if err := am.CheckSystemStatus(cpuStatus(dev, 80), nil); err != nil {
		t.Fatal(err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("below inherited threshold should not fire, got %d", n)
	}
	// Above the inherited threshold → fires exactly like legacy.
	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatal(err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("above inherited threshold should fire once, got %d", n)
	}
}

func TestMetricRule_OverridesThreshold(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	addCPUMetricRule(t, am, db, "alert", "", `{"threshold":50}`) // override 90→50
	const dev = 7
	if err := am.CheckSystemStatus(cpuStatus(dev, 60), nil); err != nil {
		t.Fatal(err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("rule threshold 50 should fire at 60, got %d open", n)
	}
}

func TestMetricRule_SeverityOverride(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	addCPUMetricRule(t, am, db, "alert", "critical", `{"mode":"static"}`)
	const dev = 7
	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatal(err)
	}
	var got models.Alert
	if err := am.db.Gorm().Where("device_id = ? AND alert_type = ? AND metric_name <> ?", dev, models.AlertTypeCPUHigh, "recovery").
		Order("id desc").First(&got).Error; err != nil {
		t.Fatalf("load alert: %v", err)
	}
	if got.Severity != "critical" {
		t.Fatalf("severity override not applied: got %q", got.Severity)
	}
}

func TestMetricRule_SuppressMutesFireButRecovers(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	const dev = 7
	// Seed an already-open CPU alert (as if fired before the suppress rule).
	seedAlert(t, db, openAlert(dev, models.AlertTypeCPUHigh, "cpu_usage", time.Now().Add(-time.Minute)))
	addCPUMetricRule(t, am, db, "suppress", "", "")

	// A high reading must NOT create a second alert (suppressed)...
	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatal(err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("suppress should not add a new alert, got %d open", n)
	}
	// ...but a recovery reading must STILL resolve the open alert (S6).
	if err := am.CheckSystemStatus(cpuStatus(dev, 10), nil); err != nil {
		t.Fatal(err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("suppress must not strand an open alert; recovery should resolve it, got %d open", n)
	}
}

func TestMetricRule_OwnedNoRuleFallsBackToLegacy(t *testing.T) {
	am, db := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	const dev = 7
	// Own cpu_high but provide NO enabled metric rule → legacy must still fire.
	if err := db.UpsertSetting(&models.SystemSetting{Key: "state_engine_owns", Value: "cpu_high"}); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatal(err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("owned + no rule must fall back to legacy and fire, got %d open", n)
	}
}
