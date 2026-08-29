package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func addDeviceRule(t *testing.T, am *AlertManager, db *database.Database, name, action, severity, matchJSON string, priority int) {
	t.Helper()
	r := &models.EventRule{
		Name: name, Enabled: true, Source: "device", Action: action,
		Severity: models.Severity(severity), Priority: priority, MatchJSON: matchJSON,
	}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatalf("create device rule: %v", err)
	}
	am.RefreshEventRules(db)
}

// TestDeviceFields_PerFamily pins the matcher field surface: common fields plus
// per-family extras, with empty values omitted (missing-field neq semantics).
func TestDeviceFields_PerFamily(t *testing.T) {
	site := uint(3)
	f := deviceFields("interface_errors", 7, &site, "warning", map[string]string{"interface_name": "port5", "detail": ""})
	if f["event_type"] != "interface_errors" || f["device_id"] != "7" || f["site_id"] != "3" ||
		f["severity"] != "warning" || f["interface_name"] != "port5" {
		t.Errorf("fields wrong: %+v", f)
	}
	if _, ok := f["detail"]; ok {
		t.Error("empty extras must be omitted")
	}
	for at, ev := range map[models.AlertType]string{
		models.AlertTypeDeviceOffline: "device_offline", models.AlertTypeTelemetryStale: "telemetry_stale",
		models.AlertTypeInterfaceErrors: "interface_errors", models.AlertTypeConfigChange: "config_change",
		models.AlertTypeSSHHostKeyChanged: "ssh_host_key_changed",
		models.AlertTypeProbeDataLag:      "probe_data_lag", models.AlertTypeProbeDataTruncated: "probe_data_truncated",
	} {
		if got := deviceEventType(at); got != ev {
			t.Errorf("deviceEventType(%s) = %q, want %q", at, got, ev)
		}
	}
	if deviceEventType(models.AlertTypeCPUHigh) != "" {
		t.Error("non-device types must map to empty")
	}
}

// TestDeviceRule_AnySourceIsolation: an "any"-source rule must NOT match device
// events (exact-source filter; a missing-field neq evaluates true).
func TestDeviceRule_AnySourceIsolation(t *testing.T) {
	am, db := newTestManager(t)
	r := &models.EventRule{Name: "any-noise", Enabled: true, Source: "any", Action: "suppress",
		MatchJSON: `{"op":"neq","field":"nonexistent","value":"x"}`}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	if rule := func() *compiledRule {
		am.mu.RLock()
		defer am.mu.RUnlock()
		return am.matchDeviceRuleLocked(deviceFields("device_offline", 1, nil, "critical", nil), 1, nil)
	}(); rule != nil {
		t.Fatal("an any-source rule must NOT match device events")
	}
}

// TestCheckDeviceOffline_RuleSuppressAndCustomize: a device suppress rule mutes
// the fire (no alert, no active marking → no recovery); an alert rule
// overrides severity.
func TestCheckDeviceOffline_RuleSuppressAndCustomize(t *testing.T) {
	am, db := newTestManager(t)
	dev := &models.Device{Name: "edge-1", IPAddress: "10.0.0.1", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	addDeviceRule(t, am, db, "mute offline", "suppress", "",
		`{"op":"eq","field":"event_type","value":"device_offline"}`, 50)
	if err := am.CheckDeviceOffline(dev); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "DEVICE_OFFLINE").Count(&n)
	if n != 0 {
		t.Fatalf("suppress rule must mute DEVICE_OFFLINE, found %d alerts", n)
	}

	am2, db2 := newTestManager(t)
	dev2 := &models.Device{Name: "edge-2", IPAddress: "10.0.0.2", Enabled: true}
	if err := db2.Gorm().Create(dev2).Error; err != nil {
		t.Fatal(err)
	}
	addDeviceRule(t, am2, db2, "downgrade offline", "alert", "info",
		`{"op":"eq","field":"event_type","value":"device_offline"}`, 50)
	if err := am2.CheckDeviceOffline(dev2); err != nil {
		t.Fatal(err)
	}
	var a models.Alert
	if err := db2.Gorm().Where("alert_type = ?", "DEVICE_OFFLINE").First(&a).Error; err != nil {
		t.Fatalf("alert-action rule must still emit: %v", err)
	}
	if a.Severity != "info" {
		t.Errorf("rule severity override not applied: got %s want info", a.Severity)
	}
}

// TestDeviceRule_DanglingPolicyIDNotStamped (AUDIT-246): an alert-action rule
// whose PolicyID no longer exists in the cache (deleted policy, stale rule)
// must NOT stamp that dangling id onto the saved alert row — the row keeps the
// resolved policy (nil here: no cache loaded), so policy attribution and
// policy-joined reads stay sound.
func TestDeviceRule_DanglingPolicyIDNotStamped(t *testing.T) {
	am, db := newTestManager(t)
	dev := &models.Device{Name: "edge-9", IPAddress: "10.0.0.9", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	dangling := uint(999)
	r := &models.EventRule{Name: "route offline to retired policy", Enabled: true, Source: "device",
		Action: "alert", Priority: 50, PolicyID: &dangling,
		MatchJSON: `{"op":"eq","field":"event_type","value":"device_offline"}`}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)

	if err := am.CheckDeviceOffline(dev); err != nil {
		t.Fatal(err)
	}
	var a models.Alert
	if err := db.Gorm().Where("alert_type = ?", "DEVICE_OFFLINE").First(&a).Error; err != nil {
		t.Fatalf("alert must still fire: %v", err)
	}
	if a.PolicyID != nil && *a.PolicyID == dangling {
		t.Fatalf("saved row carries the dangling policy id %d; want the resolved policy or nil", dangling)
	}
}

// TestCheckInterfaceErrors_RuleScopedToInterface: a rule narrowed to one
// interface mutes only that port; a sibling port still fires.
func TestCheckInterfaceErrors_RuleScopedToInterface(t *testing.T) {
	am, db := newTestManager(t)
	addDeviceRule(t, am, db, "mute port5 errors", "suppress", "",
		`{"op":"and","conditions":[{"op":"eq","field":"event_type","value":"interface_errors"},{"op":"eq","field":"interface_name","value":"port5"}]}`, 50)

	prev := map[string]*models.InterfaceStats{
		"1_port5": {DeviceID: 1, Name: "port5", InErrors: 0},
		"1_port6": {DeviceID: 1, Name: "port6", InErrors: 0},
	}
	cur := []models.InterfaceStats{
		{DeviceID: 1, Name: "port5", Status: "up", AdminStatus: "up", InErrors: 10},
		{DeviceID: 1, Name: "port6", Status: "up", AdminStatus: "up", InErrors: 10},
	}
	if err := am.CheckInterfaceErrors(cur, prev, nil); err != nil {
		t.Fatal(err)
	}
	var alerts []models.Alert
	db.Gorm().Where("alert_type = ?", "INTERFACE_ERRORS").Find(&alerts)
	if len(alerts) != 1 {
		t.Fatalf("want exactly 1 INTERFACE_ERRORS (port6 only), got %d", len(alerts))
	}
	if alerts[0].MetricName != "interface_errors_port6" {
		t.Errorf("wrong port fired: %s", alerts[0].MetricName)
	}
}

// TestCheckConfigRevision_GainsGatesAndRules pins the v0.11.112 upgrade of the
// previously gate-less path: severity still derives from the configdiff info
// (with the unattributed escalation), a device rule can suppress, and a rule
// severity re-grade wins.
func TestCheckConfigRevision_GainsGatesAndRules(t *testing.T) {
	am, db := newTestManager(t)
	dev := &models.Device{Name: "edge-1", IPAddress: "10.0.0.1", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	// Baseline (no rules): unattributed medium change escalates to critical.
	am.CheckConfigRevision(dev.ID, "aaaa1111bbbb", "cccc2222dddd", ConfigChangeInfo{Severity: "medium"})
	var a models.Alert
	if err := db.Gorm().Where("alert_type = ?", "CONFIG_CHANGE").First(&a).Error; err != nil {
		t.Fatalf("baseline CONFIG_CHANGE must fire: %v", err)
	}
	if a.Severity != "critical" {
		t.Errorf("unattributed medium change should escalate to critical, got %s", a.Severity)
	}

	// Suppress rule mutes (fresh manager to reset cooldown).
	am2, db2 := newTestManager(t)
	dev2 := &models.Device{Name: "edge-2", IPAddress: "10.0.0.2", Enabled: true}
	if err := db2.Gorm().Create(dev2).Error; err != nil {
		t.Fatal(err)
	}
	addDeviceRule(t, am2, db2, "mute config change", "suppress", "",
		`{"op":"eq","field":"event_type","value":"config_change"}`, 50)
	am2.CheckConfigRevision(dev2.ID, "a", "b", ConfigChangeInfo{Severity: "medium", Attributed: true})
	var n int64
	db2.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "CONFIG_CHANGE").Count(&n)
	if n != 0 {
		t.Fatalf("suppress rule must mute CONFIG_CHANGE, found %d", n)
	}

	// Method-scoped rule: only GUI changes muted; CLI still fires.
	am3, db3 := newTestManager(t)
	dev3 := &models.Device{Name: "edge-3", IPAddress: "10.0.0.3", Enabled: true}
	if err := db3.Gorm().Create(dev3).Error; err != nil {
		t.Fatal(err)
	}
	addDeviceRule(t, am3, db3, "mute GUI changes", "suppress", "",
		`{"op":"and","conditions":[{"op":"eq","field":"event_type","value":"config_change"},{"op":"eq","field":"method","value":"GUI"}]}`, 50)
	am3.CheckConfigRevision(dev3.ID, "a", "b", ConfigChangeInfo{Severity: "medium", Method: "CLI(ssh)", ChangedBy: "admin", Attributed: true})
	var cli int64
	db3.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "CONFIG_CHANGE").Count(&cli)
	if cli != 1 {
		t.Fatalf("CLI change must still fire under a GUI-scoped mute, got %d", cli)
	}
}

// TestRecordProbeDataTruncation_Rules pins the gate-less path's upgrade: a
// probe-scoped suppress mutes; without rules the legacy warning still fires.
func TestRecordProbeDataTruncation_Rules(t *testing.T) {
	am, db := newTestManager(t)
	am.RecordProbeDataTruncation(4, "probe-a", 100, 60)
	var a models.Alert
	if err := db.Gorm().Where("alert_type = ?", "PROBE_DATA_TRUNCATED").First(&a).Error; err != nil {
		t.Fatalf("baseline PROBE_DATA_TRUNCATED must fire: %v", err)
	}
	if a.Severity != "warning" || a.ProbeID == nil || *a.ProbeID != 4 {
		t.Errorf("baseline alert wrong: %+v", a)
	}

	am2, db2 := newTestManager(t)
	addDeviceRule(t, am2, db2, "mute probe 4 truncation", "suppress", "",
		`{"op":"and","conditions":[{"op":"eq","field":"event_type","value":"probe_data_truncated"},{"op":"eq","field":"probe_id","value":"4"}]}`, 50)
	am2.RecordProbeDataTruncation(4, "probe-a", 100, 60)
	var n int64
	db2.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "PROBE_DATA_TRUNCATED").Count(&n)
	if n != 0 {
		t.Fatalf("probe-scoped suppress must mute, found %d", n)
	}
	// A different probe is unaffected.
	am2.RecordProbeDataTruncation(5, "probe-b", 100, 60)
	db2.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "PROBE_DATA_TRUNCATED").Count(&n)
	if n != 1 {
		t.Fatalf("other probes must still fire, got %d", n)
	}
}

// TestDeviceRule_ExpiryHonored: a temporary device rule stops matching after
// expires_at (match-time check, same as flow_security).
func TestDeviceRule_ExpiryHonored(t *testing.T) {
	am, db := newTestManager(t)
	past := time.Now().Add(-time.Hour)
	r := &models.EventRule{Name: "expired mute", Enabled: true, Source: "device", Action: "suppress",
		MatchJSON: `{"op":"eq","field":"event_type","value":"device_offline"}`, Priority: 50, ExpiresAt: &past}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	dev := &models.Device{Name: "edge-1", IPAddress: "10.0.0.1", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	if err := am.CheckDeviceOffline(dev); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "DEVICE_OFFLINE").Count(&n)
	if n != 1 {
		t.Fatalf("an expired temp rule must not mute; got %d alerts", n)
	}
}

// TestCheckSSHHostKeyChanged_HADowngradeVsRule pins the severity plumbing: a
// severity-scoped device rule matches the severity the alert WOULD carry (the
// HA-failover downgrade to warning), and an explicit rule re-grade wins over
// the downgrade.
func TestCheckSSHHostKeyChanged_HADowngradeVsRule(t *testing.T) {
	am, db := newTestManager(t)
	dev := &models.Device{Name: "edge-1", IPAddress: "10.0.0.1", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	// Rule matches ONLY warning-severity host-key events (i.e. the HA-downgraded
	// class) and re-grades them to critical.
	addDeviceRule(t, am, db, "regrade HA key learns", "alert", "critical",
		`{"op":"and","conditions":[{"op":"eq","field":"event_type","value":"ssh_host_key_changed"},{"op":"eq","field":"severity","value":"warning"}]}`, 50)

	if err := am.CheckSSHHostKeyChanged(dev, "SHA256:aaa", true); err != nil {
		t.Fatal(err)
	}
	var a models.Alert
	if err := db.Gorm().Where("alert_type = ?", "SSH_HOST_KEY_CHANGED").First(&a).Error; err != nil {
		t.Fatalf("alert must fire: %v", err)
	}
	if a.Severity != "critical" {
		t.Errorf("rule re-grade must win over the HA downgrade: got %s want critical", a.Severity)
	}

	// Fingerprint-scoped suppress (pre-approving a planned rotation) mutes.
	am2, db2 := newTestManager(t)
	dev2 := &models.Device{Name: "edge-2", IPAddress: "10.0.0.2", Enabled: true}
	if err := db2.Gorm().Create(dev2).Error; err != nil {
		t.Fatal(err)
	}
	addDeviceRule(t, am2, db2, "approve planned rotation", "suppress", "",
		`{"op":"eq","field":"fingerprint","value":"SHA256:planned"}`, 50)
	if err := am2.CheckSSHHostKeyChanged(dev2, "SHA256:planned", false); err != nil {
		t.Fatal(err)
	}
	var n int64
	db2.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SSH_HOST_KEY_CHANGED").Count(&n)
	if n != 0 {
		t.Fatalf("fingerprint-scoped suppress must mute the planned rotation, found %d", n)
	}
}

// TestCheckProbeDataFlow_DeviceScopedRuleIsolation pins the deviceID=0
// semantics: a device-scoped rule must NOT match probe alerts; a global
// event_type rule must.
func TestCheckProbeDataFlow_DeviceScopedRuleIsolation(t *testing.T) {
	run := func(t *testing.T, matchJSON string, scopeDevice *uint) int64 {
		t.Helper()
		am, db := newTestManager(t)
		am.config.Alerts.ProbeDataLagAlertMinutes = 60
		stale := time.Now().Add(-2 * time.Hour)
		p := &models.Probe{Name: "lagging-probe", RegistrationKey: "dr-key", ApprovalStatus: "approved",
			Enabled: true, LastDataReceived: stale}
		if err := db.Gorm().Create(p).Error; err != nil {
			t.Fatal(err)
		}
		r := &models.EventRule{Name: "probe rule", Enabled: true, Source: "device", Action: "suppress",
			MatchJSON: matchJSON, Priority: 50, DeviceID: scopeDevice}
		if err := db.CreateEventRule(r); err != nil {
			t.Fatal(err)
		}
		am.RefreshEventRules(db)
		if err := am.CheckProbeDataFlow(); err != nil {
			t.Fatal(err)
		}
		var n int64
		db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "PROBE_DATA_LAG").Count(&n)
		return n
	}
	dev7 := uint(7)
	if n := run(t, `{"op":"eq","field":"event_type","value":"probe_data_lag"}`, &dev7); n != 1 {
		t.Errorf("a device-7-scoped rule must NOT mute probe alerts (device_id=0); got %d alerts, want 1", n)
	}
	if n := run(t, `{"op":"eq","field":"event_type","value":"probe_data_lag"}`, nil); n != 0 {
		t.Errorf("a global event_type rule must mute probe alerts; got %d alerts, want 0", n)
	}
}
