package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// Phase 4a trap evaluator: when a trap_type is owned, ProcessTrap consults a
// matching source="trap" rule for suppress / severity override / info opt-in, on
// top of the existing policy path.

func addTrapRule(t *testing.T, am *AlertManager, db *database.Database, trapType, action, severity string) {
	t.Helper()
	r := &models.EventRule{
		Name: "trap " + trapType + action + severity, Enabled: true, Source: "trap", Action: action,
		Severity: models.Severity(severity), AlertType: models.AlertType(trapType),
		MatchJSON: `{"op":"eq","field":"trap_type","value":"` + trapType + `"}`,
	}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatalf("create trap rule: %v", err)
	}
	if err := db.UpsertSetting(&models.SystemSetting{Key: "state_engine_owns", Value: trapType}); err != nil {
		t.Fatalf("set ownership: %v", err)
	}
	am.RefreshEventRules(db)
}

func trapAlertCount(t *testing.T, am *AlertManager, trapType string) int64 {
	t.Helper()
	var n int64
	am.db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND metric_name <> ?", trapType, "recovery").Count(&n)
	return n
}

func fireTrap(t *testing.T, am *AlertManager, trapType, severity string) {
	t.Helper()
	if err := am.ProcessTrap(&models.TrapEvent{
		TrapType: trapType, Severity: severity, SourceIP: "10.9.9.9",
		Message: trapType, Timestamp: time.Now(),
	}, nil); err != nil {
		t.Fatalf("ProcessTrap: %v", err)
	}
}

func TestTrapRule_Suppress(t *testing.T) {
	am, db := newTestManager(t)
	addTrapRule(t, am, db, "HA_MEMBER_DOWN", "suppress", "")
	fireTrap(t, am, "HA_MEMBER_DOWN", "critical")
	if n := trapAlertCount(t, am, "HA_MEMBER_DOWN"); n != 0 {
		t.Fatalf("suppress rule must drop the trap, got %d alerts", n)
	}
}

func TestTrapRule_SeverityOverride(t *testing.T) {
	am, db := newTestManager(t)
	addTrapRule(t, am, db, "HA_MEMBER_DOWN", "alert", "critical")
	fireTrap(t, am, "HA_MEMBER_DOWN", "warning") // trap says warning, rule forces critical
	var got models.Alert
	if err := am.db.Gorm().Where("alert_type = ? AND metric_name <> ?", "HA_MEMBER_DOWN", "recovery").
		Order("id desc").First(&got).Error; err != nil {
		t.Fatalf("load alert: %v", err)
	}
	if got.Severity != "critical" {
		t.Fatalf("event-rule severity must win, got %q", got.Severity)
	}
}

func TestTrapRule_InfoTrapOptIn(t *testing.T) {
	am, db := newTestManager(t)
	// An info-severity trap is dropped by LC-14 UNLESS a rule opts it in.
	fireTrap(t, am, "HA_MEMBER_UP", "info")
	if n := trapAlertCount(t, am, "HA_MEMBER_UP"); n != 0 {
		t.Fatalf("info trap without a rule should be dropped, got %d", n)
	}
	// Now add a matching trap rule → it opts in and fires.
	addTrapRule(t, am, db, "HA_MEMBER_UP", "alert", "")
	fireTrap(t, am, "HA_MEMBER_UP", "info")
	if n := trapAlertCount(t, am, "HA_MEMBER_UP"); n != 1 {
		t.Fatalf("info trap with a matching rule should fire once, got %d", n)
	}
}

func TestTrapRule_OwnedNoRuleFallsBackToLegacy(t *testing.T) {
	am, db := newTestManager(t)
	// Own the type but provide no trap rule → the legacy path still fires a
	// warning/critical trap.
	if err := db.UpsertSetting(&models.SystemSetting{Key: "state_engine_owns", Value: "HA_MEMBER_DOWN"}); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	fireTrap(t, am, "HA_MEMBER_DOWN", "critical")
	if n := trapAlertCount(t, am, "HA_MEMBER_DOWN"); n != 1 {
		t.Fatalf("owned + no rule must fall back to legacy and fire, got %d", n)
	}
}
