package alerts

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// installPolicyCache wires a loaded policy cache directly (the tests drive the
// resolution logic; RefreshPolicyCache round-trips are covered elsewhere).
// policy may be nil (windows-only cache); it becomes the default policy.
func installPolicyCache(am *AlertManager, policy *models.AlertPolicy, windows []models.MaintenanceWindow) {
	pc := PolicyCache{
		policyByID:    map[uint]*models.AlertPolicy{},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		windows:       windows,
		loaded:        true,
	}
	if policy != nil {
		pc.policies = []models.AlertPolicy{*policy}
		pc.policyByID[policy.ID] = policy
		pc.defaultPolicy = policy
	}
	am.policyCache = pc
}

// installDefaultProfileToggles wires a Default event rule profile carrying the
// given explicit toggle rows into an already-installed policy cache (v48 —
// the per-type kill switch the retired AlertRule.Enabled used to be).
func installDefaultProfileToggles(am *AlertManager, toggles map[models.AlertType]bool) {
	def := &models.EventRuleProfile{ID: 1, Name: "Default", IsDefault: true}
	am.policyCache.eventProfiles = map[uint]*models.EventRuleProfile{def.ID: def}
	am.policyCache.defaultEventProfileID = def.ID
	am.policyCache.eventToggles = map[uint]map[models.AlertType]bool{def.ID: toggles}
}

// TestCheckEscalations_SnoozedAlertDoesNotEscalate (LC-10): snooze is
// "silence temporarily WITHOUT acking" — the escalation engine must not keep
// paging for an alert the operator just snoozed, and must resume once the
// snooze expires.
func TestCheckEscalations_SnoozedAlertDoesNotEscalate(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{
		ID: 1, Name: "esc", IsDefault: true,
		EscalationEnabled: true, EscalationMinutes: 5, EscalationRepeat: 3,
	}
	installPolicyCache(am, &policy, nil)

	pid := uint(1)
	future := time.Now().Add(4 * time.Hour)
	alert := models.Alert{
		Timestamp: time.Now().Add(-20 * time.Minute),
		DeviceID:  5, AlertType: "CPU_HIGH", Severity: "warning",
		Message: "cpu high", MetricName: "cpu_usage", PolicyID: &pid,
		SnoozedUntil: &future,
	}
	seedAlert(t, db, &alert)

	am.CheckEscalations()
	if got := getAlert(t, db, alert.ID); got.EscalationCount != 0 {
		t.Fatalf("snoozed alert escalated: count = %d, want 0", got.EscalationCount)
	}

	// Expired snooze: the alert resurfaces to the escalation engine.
	past := time.Now().Add(-time.Minute)
	if err := db.Gorm().Model(&models.Alert{}).Where("id = ?", alert.ID).
		Update("snoozed_until", past).Error; err != nil {
		t.Fatalf("expire snooze: %v", err)
	}
	am.CheckEscalations()
	if got := getAlert(t, db, alert.ID); got.EscalationCount == 0 {
		t.Fatal("alert with expired snooze must escalate again, count stayed 0")
	}
}

// TestCheckEscalations_OpenIncidentAlertsSkipped (LC-11): an alert attached to
// a still-open F12 incident was muted at fire time — escalation must not
// resurrect it individually while the incident is open, and may resume once
// the incident closes.
func TestCheckEscalations_OpenIncidentAlertsSkipped(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{
		ID: 1, Name: "esc", IsDefault: true,
		EscalationEnabled: true, EscalationMinutes: 5, EscalationRepeat: 3,
	}
	installPolicyCache(am, &policy, nil)

	pid := uint(1)
	incID := uint(42)
	am.openIncidents[5] = incID
	alert := models.Alert{
		Timestamp: time.Now().Add(-20 * time.Minute),
		DeviceID:  5, AlertType: "INTERFACE_DOWN", Severity: "critical",
		Message: "iface down", MetricName: "interface_port1",
		PolicyID: &pid, IncidentID: &incID,
	}
	seedAlert(t, db, &alert)

	am.CheckEscalations()
	if got := getAlert(t, db, alert.ID); got.EscalationCount != 0 {
		t.Fatalf("incident-attached alert escalated while incident open: count = %d, want 0", got.EscalationCount)
	}

	// Incident closed: the still-unacked alert is escalatable again.
	delete(am.openIncidents, 5)
	am.CheckEscalations()
	if got := getAlert(t, db, alert.ID); got.EscalationCount == 0 {
		t.Fatal("alert must escalate again after its incident closes, count stayed 0")
	}
}

// TestCheckDeviceOffline_DisabledPolicyNoRecoveryNoise (LC-12; re-pinned on
// the v48 toggle chain): with DEVICE_OFFLINE toggled Off in the Default event
// profile, an offline device must produce NO alert row, NO in-memory active
// state, and — critically — NO "back online" companion or notification when
// it recovers. The stale AlertRule.Enabled=false row stays seeded to pin the
// retirement: on its own it no longer disables anything (the toggle does).
func TestCheckDeviceOffline_DisabledPolicyNoRecoveryNoise(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{
		ID: 1, Name: "p", IsDefault: true,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: "DEVICE_OFFLINE", Enabled: false}},
	}
	installPolicyCache(am, &policy, nil)
	installDefaultProfileToggles(am, map[models.AlertType]bool{models.AlertTypeDeviceOffline: false})

	dev := &models.Device{ID: 3, Name: "fw", IPAddress: "10.0.0.3"}
	if err := am.CheckDeviceOffline(dev); err != nil {
		t.Fatalf("CheckDeviceOffline: %v", err)
	}

	var n int64
	if err := db.Gorm().Model(&models.Alert{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("disabled DEVICE_OFFLINE saved %d alert rows, want 0", n)
	}
	am.mu.RLock()
	active := am.activeAlerts["device_offline_3"]
	am.mu.RUnlock()
	if active {
		t.Fatal("disabled DEVICE_OFFLINE must not mark the key active")
	}

	am.CheckDeviceOnline(dev)
	if c := countResolvedCompanions(t, db); c != 0 {
		t.Fatalf("companion _RESOLVED rows = %d, want 0 (no 'back online' noise for a disabled alert type)", c)
	}
}

// TestSendRecovery_MaintenanceMutesNotificationButResolves (LC-13): during a
// maintenance window the recovery's DB auto-resolve still runs (the ticket
// clears), but the companion is saved Suppressed so no "back up" notification
// goes out at 3am for a fire that was itself suppressed.
func TestSendRecovery_MaintenanceMutesNotificationButResolves(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	installPolicyCache(am, nil, []models.MaintenanceWindow{{
		Name: "planned", StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour), SuppressAll: true,
	}})

	open := models.Alert{
		DeviceID: 4, AlertType: "VPN_TUNNEL_DOWN", MetricName: "vpn_t1",
		Message: "VPN tunnel t1 is down", Timestamp: now, Suppressed: true,
	}
	seedAlert(t, db, &open)

	am.activeAlerts["vpn_down_4_t1"] = true
	am.sendRecovery("vpn_down_4_t1", "VPN_TUNNEL_DOWN", "vpn_t1",
		"VPN tunnel t1 is back up", 4, nil)

	if got := getAlert(t, db, open.ID); got.ResolvedAt == nil {
		t.Error("maintenance must not defer the DB auto-resolve")
	}
	var comp models.Alert
	if err := db.Gorm().Where("metric_name = ?", "recovery").First(&comp).Error; err != nil {
		t.Fatalf("companion row missing: %v", err)
	}
	if !comp.Suppressed {
		t.Error("recovery companion during maintenance must be saved Suppressed (notification muted)")
	}
}

// TestProcessTrap_RuleSeverityOverrideAndOptIn (LC-14): a per-rule severity
// override applies to trap alert types, and an enabled rule opts an info-level
// trap type into alerting; unmatched info traps stay dropped.
func TestProcessTrap_RuleSeverityOverrideAndOptIn(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{
		ID: 1, Name: "p", IsDefault: true,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: "LINK_DOWN", Enabled: true, Severity: "critical"}},
	}
	installPolicyCache(am, &policy, nil)

	// Warning trap with a rule severity override → alert carries "critical".
	if err := am.ProcessTrap(&models.TrapEvent{
		Timestamp: time.Now(), TrapType: "LINK_DOWN", Severity: "warning",
		SourceIP: "192.0.2.9", Message: "link down",
	}, nil); err != nil {
		t.Fatalf("ProcessTrap: %v", err)
	}
	var a models.Alert
	if err := db.Gorm().Where("alert_type = ?", "LINK_DOWN").First(&a).Error; err != nil {
		t.Fatalf("LINK_DOWN alert missing: %v", err)
	}
	if a.Severity != "critical" {
		t.Errorf("severity = %q, want rule override %q", a.Severity, "critical")
	}

	// Info-level trap of a rule-matched type is opted in (different source →
	// different cooldown key).
	if err := am.ProcessTrap(&models.TrapEvent{
		Timestamp: time.Now(), TrapType: "LINK_DOWN", Severity: "info",
		SourceIP: "192.0.2.10", Message: "link down",
	}, nil); err != nil {
		t.Fatalf("ProcessTrap (info, rule-matched): %v", err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "LINK_DOWN").Count(&n)
	if n != 2 {
		t.Errorf("rule-matched info trap not opted in: LINK_DOWN rows = %d, want 2", n)
	}

	// Info-level trap with NO matching rule keeps the legacy drop.
	if err := am.ProcessTrap(&models.TrapEvent{
		Timestamp: time.Now(), TrapType: "COLD_START", Severity: "info",
		SourceIP: "192.0.2.9", Message: "cold start",
	}, nil); err != nil {
		t.Fatalf("ProcessTrap (info, unmatched): %v", err)
	}
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "COLD_START").Count(&n)
	if n != 0 {
		t.Errorf("unmatched info trap must stay dropped: COLD_START rows = %d, want 0", n)
	}
}

// TestRecordProbeDataTruncation_FiresOnceWithCooldown (LC-26): a truncated
// batch produces exactly one PROBE_DATA_TRUNCATED alert (the old guard read a
// never-written lastAlert key with an inverted comparison — it could never
// fire), and an immediate repeat is spam-guarded by the cooldown.
func TestRecordProbeDataTruncation_FiresOnceWithCooldown(t *testing.T) {
	am, db := newTestManager(t)

	am.RecordProbeDataTruncation(9, "probe-9", 1300, 1000)

	count := func() int64 {
		t.Helper()
		var n int64
		if err := db.Gorm().Model(&models.Alert{}).
			Where("alert_type = ?", "PROBE_DATA_TRUNCATED").Count(&n).Error; err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if got := count(); got != 1 {
		t.Fatalf("truncation alerts = %d, want 1 (alert must fire on first truncation)", got)
	}

	// Second truncation inside the 5-minute window: cooldown-gated, still 1.
	am.RecordProbeDataTruncation(9, "probe-9", 1300, 1000)
	if got := count(); got != 1 {
		t.Fatalf("truncation alerts after repeat = %d, want still 1 (cooldown)", got)
	}
}

// TestCheckInterfaceErrors_MessageClampsCounterResets (LC-28): when one
// counter resets while another grows enough that the total still rises, the
// per-counter breakdown in the message must clamp to 0, not underflow to
// ~1.8e19.
func TestCheckInterfaceErrors_MessageClampsCounterResets(t *testing.T) {
	am, db := newTestManager(t)

	prev := &models.InterfaceStats{DeviceID: 1, Name: "wan1", InErrors: 100, OutErrors: 200}
	cur := models.InterfaceStats{
		DeviceID: 1, Name: "wan1", Status: "up", AdminStatus: "up",
		InErrors: 5 /* reset */, OutErrors: 400,
	}
	if err := am.CheckInterfaceErrors([]models.InterfaceStats{cur},
		map[string]*models.InterfaceStats{"1_wan1": prev}, nil); err != nil {
		t.Fatalf("CheckInterfaceErrors: %v", err)
	}

	var a models.Alert
	if err := db.Gorm().Where("alert_type = ?", "INTERFACE_ERRORS").First(&a).Error; err != nil {
		t.Fatalf("INTERFACE_ERRORS alert missing: %v", err)
	}
	if strings.Contains(a.Message, "18446744073709") {
		t.Errorf("message contains an underflowed uint64 delta: %q", a.Message)
	}
	if !strings.Contains(a.Message, "in_err: 0") {
		t.Errorf("reset counter's delta not clamped to 0: %q", a.Message)
	}
	if !strings.Contains(a.Message, "out_err: 200") {
		t.Errorf("growing counter's delta wrong: %q", a.Message)
	}
}
