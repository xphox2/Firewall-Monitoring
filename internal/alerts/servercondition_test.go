package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The raw archive's alerts (archive plan PR 8) ride the device-less server
// condition path that SERVER_DISK_HIGH uses. Synthetic data only.

func archiveLag(stream string, breached bool) ServerCondition {
	return ServerCondition{Type: models.AlertTypeArchiveLag, Key: "archive_lag_" + stream, Metric: "archive_lag_" + stream,
		Breached: breached, Message: "Raw archive of " + stream + " is 30.0 h behind", Recovery: "Raw archive of " + stream + " caught up",
		Fields: map[string]string{"stream": stream}}
}

// backdate moves the fire of key (in memory and its open row, the
// cross-restart backstop) d into the past, as if d had elapsed.
func backdate(t *testing.T, am *AlertManager, key string, d time.Duration) {
	t.Helper()
	am.mu.Lock()
	fired, ok := am.lastAlert[key]
	am.lastAlert[key] = fired.Add(-d)
	am.mu.Unlock()
	if !ok {
		t.Fatalf("no cooldown recorded for %s", key)
	}
	if err := am.db.Gorm().Model(&models.Alert{}).Where("metric_name = ? AND resolved_at IS NULL", key).
		Update("timestamp", fired.Add(-d)).Error; err != nil {
		t.Fatal(err)
	}
}

func openAlerts(t *testing.T, am *AlertManager, typ models.AlertType, metric string) []models.Alert {
	t.Helper()
	var as []models.Alert
	if err := am.db.Gorm().Where("alert_type = ? AND metric_name = ? AND resolved_at IS NULL", typ, metric).Find(&as).Error; err != nil {
		t.Fatal(err)
	}
	return as
}

// TestServerConditions_ArchiveFireAndClear: a breached condition opens one
// row (the type's default severity, device 0), a repeat
// inside the 6 h archive cooldown adds none — 6 minutes later either — a
// second stream is independent, and clearing resolves the row with a
// recovery companion while the other stream stays open.
func TestServerConditions_ArchiveFireAndClear(t *testing.T) {
	am, db := newTestManager(t)
	am.CheckServerConditions([]ServerCondition{archiveLag("syslog", true), archiveLag("sflow", true),
		{Type: models.AlertTypeRetentionHeld, Key: "retention_held_flow_samples", Metric: "retention_held_flow_samples", Breached: true,
			Message: "held", Recovery: "not held"}})
	as := openAlerts(t, am, models.AlertTypeArchiveLag, "archive_lag_syslog")
	if len(as) != 1 || as[0].Severity != "warning" || as[0].DeviceID != 0 {
		t.Fatalf("syslog lag rows: %+v", as)
	}
	if held := openAlerts(t, am, models.AlertTypeRetentionHeld, "retention_held_flow_samples"); len(held) != 1 || held[0].Severity != "critical" {
		t.Fatalf("retention held rows: %+v", held)
	}

	backdate(t, am, "archive_lag_syslog", 6*time.Minute)
	am.CheckServerConditions([]ServerCondition{archiveLag("syslog", true)})
	if n := len(openAlerts(t, am, models.AlertTypeArchiveLag, "archive_lag_syslog")); n != 1 {
		t.Fatalf("re-fired 6 minutes later: %d rows (the archive cooldown is %d minutes, not the generic 5)", n, archiveAlertCooldownMinutes)
	}

	am.CheckServerConditions([]ServerCondition{archiveLag("syslog", false)})
	if n := len(openAlerts(t, am, models.AlertTypeArchiveLag, "archive_lag_syslog")); n != 0 {
		t.Fatalf("syslog lag still open after clearing: %d", n)
	}
	if n := len(openAlerts(t, am, models.AlertTypeArchiveLag, "archive_lag_sflow")); n != 1 {
		t.Fatalf("clearing syslog closed sflow: %d open", n)
	}
	var companions int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND metric_name = ?", models.AlertTypeArchiveLag+"_RESOLVED", "recovery").Count(&companions)
	if companions != 1 {
		t.Fatalf("recovery companions = %d, want 1", companions)
	}
}

// TestServerConditions_ArchiveSeedRule: the seeded event rule matches the
// archive alert (event_type archive_lag) and its 6 h cooldown wins over a
// policy's 5 minutes; switching the rule to suppress silences it.
func TestServerConditions_ArchiveSeedRule(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()
	am.RefreshEventRules(db)
	policy := models.AlertPolicy{ID: 1, Name: "test", IsDefault: true, CooldownMinutes: 5,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: models.AlertTypeArchiveLag, Enabled: true}}}
	am.policyCache = PolicyCache{policies: []models.AlertPolicy{policy}, policyByID: map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{}, siteConfigs: map[uint]*models.SiteAlertConfig{}, defaultPolicy: &policy, loaded: true}

	resolved := am.resolveAlertConfig(0, nil, models.AlertTypeArchiveLag)
	am.mu.RLock()
	rule, suppressed := am.consultDeviceRuleLocked(models.AlertTypeArchiveLag, 0, nil, "warning", map[string]string{"stream": "syslog"}, &resolved)
	am.mu.RUnlock()
	if rule == nil || suppressed || rule.cooldownMin == nil || *rule.cooldownMin != 360 {
		t.Fatalf("seeded archive rule: %+v suppressed %v", rule, suppressed)
	}

	am.CheckServerConditions([]ServerCondition{archiveLag("syslog", true)})
	backdate(t, am, "archive_lag_syslog", 10*time.Minute)
	am.CheckServerConditions([]ServerCondition{archiveLag("syslog", true)})
	if n := len(openAlerts(t, am, models.AlertTypeArchiveLag, "archive_lag_syslog")); n != 1 {
		t.Fatalf("the policy's 5 minutes shadowed the rule's 6 h: %d rows", n)
	}

	if err := db.Gorm().Model(&models.EventRule{}).Where("alert_type = ?", models.AlertTypeArchiveLag).Update("action", "suppress").Error; err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	am.CheckServerConditions([]ServerCondition{archiveLag("netflow", true)})
	if n := len(openAlerts(t, am, models.AlertTypeArchiveLag, "archive_lag_netflow")); n != 0 {
		t.Fatalf("a suppress rule did not silence the archive alert: %d rows", n)
	}
}
