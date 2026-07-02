package report

import (
	"testing"

	"firewall-mon/internal/config"
)

// TestReportScheduler_PrivateConfigIsolation_M15 pins the 2026-07-01 audit M15
// fix: the scheduler owns a PRIVATE copy of AlertsConfig, so a concurrent
// mutation of the shared *config.Config.Alerts (as the AlertManager does, under
// a different mutex) can neither be read nor corrupted by the scheduler — there
// is no shared mutable memory to race on.
func TestReportScheduler_PrivateConfigIsolation_M15(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.ReportRecipients = "ops@example.com"
	cfg.Alerts.SMTPHost = "smtp.example.com"

	rs := NewReportScheduler(cfg, nil, nil)

	// The scheduler seeded its private copy from cfg at construction.
	rs.mu.RLock()
	gotRecip := rs.alertCfg.ReportRecipients
	gotHost := rs.alertCfg.SMTPHost
	rs.mu.RUnlock()
	if gotRecip != "ops@example.com" || gotHost != "smtp.example.com" {
		t.Fatalf("private copy not seeded: recipients=%q host=%q", gotRecip, gotHost)
	}

	// Simulate the AlertManager mutating the SHARED cfg (the pre-fix racing
	// writer). The scheduler's private copy must NOT change — proving no shared
	// mutable state.
	cfg.Alerts.ReportRecipients = "attacker@evil.example"
	cfg.Alerts.SMTPHost = "smtp.evil.example"

	rs.mu.RLock()
	stillRecip := rs.alertCfg.ReportRecipients
	stillHost := rs.alertCfg.SMTPHost
	rs.mu.RUnlock()
	if stillRecip != "ops@example.com" || stillHost != "smtp.example.com" {
		t.Errorf("scheduler read the shared cfg mutation (recipients=%q host=%q) — still shares mutable state with the AlertManager", stillRecip, stillHost)
	}
}
