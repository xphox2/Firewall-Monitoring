package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// profile_chain_test.go — pins the v48 Default > Site > Device semantics:
// the eventToggleLocked kill-switch chain and the rule engine's layer-beats-
// priority walk.

func up(v uint) *uint { return &v }

// newTestManagerB mirrors newTestManager for benchmarks (*testing.B satisfies
// NewDatabaseForTesting's Helper/Fatal interface).
func newTestManagerB(b *testing.B) (*AlertManager, *database.Database) {
	b.Helper()
	db := database.NewDatabaseForTesting(b)
	cfg := &config.Config{}
	return NewAlertManager(cfg, notifier.NewNotifier(cfg), db), db
}

// chainCache installs a policy cache with three event profiles (Default=1,
// Site=2, Device=3), assignments (device 7 → profile 3; site 40 → profile 2),
// and the given toggle rows. Device 8 has a DANGLING profile assignment (99).
func chainCache(am *AlertManager, toggles map[uint]map[models.AlertType]bool) {
	def := &models.EventRuleProfile{ID: 1, Name: "Default", IsDefault: true}
	siteP := &models.EventRuleProfile{ID: 2, Name: "SiteProf"}
	devP := &models.EventRuleProfile{ID: 3, Name: "DevProf"}
	am.policyCache = PolicyCache{
		policyByID: map[uint]*models.AlertPolicy{},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{
			7: {DeviceID: 7, AlertsEnabled: true, EventProfileID: up(3)},
			8: {DeviceID: 8, AlertsEnabled: true, EventProfileID: up(99)}, // dangling
		},
		siteConfigs: map[uint]*models.SiteAlertConfig{
			40: {SiteID: 40, EventProfileID: up(2)},
		},
		eventProfiles:         map[uint]*models.EventRuleProfile{1: def, 2: siteP, 3: devP},
		defaultEventProfileID: 1,
		eventToggles:          toggles,
		loaded:                true,
	}
}

func TestEventToggle_ChainResolution(t *testing.T) {
	am, _ := newTestManager(t)
	site40 := uint(40)
	at := models.AlertTypeVPNTunnelDown

	cases := []struct {
		name      string
		toggles   map[uint]map[models.AlertType]bool
		deviceID  uint
		siteID    *uint
		wantOn    bool
		wantLayer string
	}{
		{"all-inherit implicit ON", map[uint]map[models.AlertType]bool{}, 7, &site40, true, ""},
		{"default Off reaches everything", map[uint]map[models.AlertType]bool{1: {at: false}}, 7, &site40, false, "default"},
		{"site Off beats default On", map[uint]map[models.AlertType]bool{1: {at: true}, 2: {at: false}}, 7, &site40, false, "site"},
		{"site On shields default Off", map[uint]map[models.AlertType]bool{1: {at: false}, 2: {at: true}}, 7, &site40, true, "site"},
		{"device Inherit falls to site Off", map[uint]map[models.AlertType]bool{2: {at: false}}, 7, &site40, false, "site"},
		{"device On beats site Off", map[uint]map[models.AlertType]bool{2: {at: false}, 3: {at: true}}, 7, &site40, true, "device"},
		{"device Off wins outright", map[uint]map[models.AlertType]bool{3: {at: false}}, 7, &site40, false, "device"},
		{"dangling device profile falls through to site", map[uint]map[models.AlertType]bool{2: {at: false}, 99: {at: true}}, 8, &site40, false, "site"},
		{"deviceID 0 skips device layer", map[uint]map[models.AlertType]bool{2: {at: false}, 3: {at: true}}, 0, &site40, false, "site"},
		{"deviceID 0 + nil site = Default only", map[uint]map[models.AlertType]bool{1: {at: false}, 2: {at: true}}, 0, nil, false, "default"},
		{"unrelated type stays ON", map[uint]map[models.AlertType]bool{1: {models.AlertTypeCPUHigh: false}}, 7, &site40, true, ""},
	}
	for _, tc := range cases {
		chainCache(am, tc.toggles)
		am.mu.Lock()
		on, layer := am.eventToggleLocked(tc.deviceID, tc.siteID, at)
		am.mu.Unlock()
		if on != tc.wantOn || layer != tc.wantLayer {
			t.Errorf("%s: got (on=%v, layer=%q), want (on=%v, layer=%q)", tc.name, on, layer, tc.wantOn, tc.wantLayer)
		}
	}
}

// The siteID fallback: a caller that doesn't thread a site still honors the
// device's cached site profile (evaluator parity via deviceMeta).
func TestEventToggle_SiteFallbackFromDeviceMeta(t *testing.T) {
	am, _ := newTestManager(t)
	chainCache(am, map[uint]map[models.AlertType]bool{2: {models.AlertTypeCPUHigh: false}})
	site40 := uint(40)
	am.deviceMeta = map[uint]database.DeviceRuleMeta{9: {Vendor: "fortigate", SiteID: &site40}}
	am.mu.Lock()
	on, layer := am.eventToggleLocked(9, nil, models.AlertTypeCPUHigh)
	am.mu.Unlock()
	if on || layer != "site" {
		t.Errorf("deviceMeta site fallback: got (on=%v, layer=%q), want (false, site)", on, layer)
	}
}

// Retirement pin: a stale AlertRule.Enabled=false row alone no longer
// disables a type — only a toggle can. (The resolver's rule consult still
// applies severity/threshold from that row.)
func TestResolveAlertConfig_StaleEnabledFalseIsInert(t *testing.T) {
	am, _ := newTestManager(t)
	policy := models.AlertPolicy{
		ID: 1, Name: "p", IsDefault: true,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: models.AlertTypeCPUHigh, Enabled: false, Threshold: 91}},
	}
	installPolicyCache(am, &policy, nil)
	am.mu.Lock()
	resolved := am.resolveAlertConfig(5, nil, models.AlertTypeCPUHigh)
	am.mu.Unlock()
	if !resolved.AlertEnabled {
		t.Fatal("stale Enabled=false must be inert post-v48 (toggles are the only per-type kill switch)")
	}
	if resolved.Threshold != 91 {
		t.Errorf("the stale row's threshold must still apply (it is live config now): got %v", resolved.Threshold)
	}
}

// installChainRulesDB seeds profiles/assignments/rules in the DB and runs the
// real refresh path (RefreshPolicyCache → single-swap install), so the walk is
// exercised end-to-end. Returns the Default profile ID.
func installChainRulesDB(t *testing.T, am *AlertManager, db *database.Database) uint {
	t.Helper()
	db.EnsureDefaultEventProfile()
	def, err := db.GetDefaultEventRuleProfile()
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	devProf := models.EventRuleProfile{Name: "DevProf"}
	if err := db.Gorm().Create(&devProf).Error; err != nil {
		t.Fatalf("create profile: %v", err)
	}
	// Device 1 lives in site 40 and carries DevProf; device 2 is bare.
	site := uint(40)
	for _, d := range []models.Device{
		{ID: 1, Name: "fw1", IPAddress: "10.0.0.1", Vendor: "fortigate", SiteID: &site},
		{ID: 2, Name: "fw2", IPAddress: "10.0.0.2", Vendor: "fortigate", SiteID: &site},
	} {
		if err := db.Gorm().Create(&d).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}
	if err := db.Gorm().Create(&models.DeviceAlertConfig{DeviceID: 1, AlertsEnabled: true, EventProfileID: &devProf.ID}).Error; err != nil {
		t.Fatalf("create device config: %v", err)
	}
	// Default layer: a priority-1 suppress-everything syslog rule.
	// Device layer: a priority-500 alert rule. Layer must beat priority.
	for _, r := range []models.EventRule{
		{Name: "default-mute-all", Enabled: true, Priority: 1, Source: "syslog", Action: "suppress",
			ProfileID: def.ID, MatchJSON: `{"op":"exists","field":"message"}`},
		{Name: "dev-alert", Enabled: true, Priority: 500, Source: "syslog", Action: "alert",
			ProfileID: devProf.ID, AlertType: models.AlertTypeSyslogCritical,
			MatchJSON: `{"op":"exists","field":"message"}`},
	} {
		rr := r
		if err := db.CreateEventRule(&rr); err != nil {
			t.Fatalf("create rule: %v", err)
		}
	}
	am.RefreshPolicyCache(db)
	return def.ID
}

func TestRuleLayering_DeviceLayerBeatsDefaultPriority(t *testing.T) {
	am, db := newTestManager(t)
	installChainRulesDB(t, am, db)

	msg := func(devID uint) *models.SyslogMessage {
		return &models.SyslogMessage{DeviceID: devID, Hostname: "h", Message: "link wobble", Timestamp: time.Now()}
	}

	// Device 1 (DevProf): its layer runs FIRST — the priority-500 alert rule
	// fires even though a priority-1 Default suppress exists.
	if err := am.EvaluateSyslog(msg(1), nil); err != nil {
		t.Fatalf("EvaluateSyslog dev1: %v", err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("device_id = ?", 1).Count(&n)
	if n != 1 {
		t.Fatalf("device-layer alert rule must out-rank the Default-layer suppress (layer beats priority): got %d alerts", n)
	}

	// Device 2 (no profile): only the Default layer applies — suppressed.
	if err := am.EvaluateSyslog(msg(2), nil); err != nil {
		t.Fatalf("EvaluateSyslog dev2: %v", err)
	}
	db.Gorm().Model(&models.Alert{}).Where("device_id = ?", 2).Count(&n)
	if n != 0 {
		t.Fatalf("bare device must be governed by the Default suppress: got %d alerts", n)
	}
}

// profile_id=0 rows (pre-v48 binary writes, unstamped seeds) evaluate in the
// Default layer — they can never silently detach from the chain.
func TestRuleLayering_ZeroProfileIDIsDefaultLayer(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	if err := db.Gorm().Create(&models.Device{ID: 3, Name: "fw3", IPAddress: "10.0.0.3", Vendor: "fortigate"}).Error; err != nil {
		t.Fatal(err)
	}
	r := models.EventRule{Name: "zero-profile-suppress", Enabled: true, Priority: 5, Source: "syslog",
		Action: "suppress", ProfileID: 0, MatchJSON: `{"op":"exists","field":"message"}`}
	if err := db.CreateEventRule(&r); err != nil {
		t.Fatal(err)
	}
	am.RefreshPolicyCache(db)

	am.mu.RLock()
	ch := am.chainRulesLocked(3, nil)
	am.mu.RUnlock()
	if ch.total != 1 {
		t.Fatalf("profile_id=0 rule must land in the Default partition and be reachable: chain total = %d", ch.total)
	}
	if err := am.EvaluateSyslog(&models.SyslogMessage{DeviceID: 3, Hostname: "h", Message: "x", Timestamp: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Count(&n)
	if n != 0 {
		t.Fatalf("zero-profile suppress must apply from the Default layer: got %d alerts", n)
	}
}

// Mid-flight toggle-off: an alert that fired while ON must still auto-resolve
// and emit its recovery companion after the type is toggled Off (recovery
// paths are deliberately ungated; only fires are).
func TestToggleOffMidFlight_RecoveryStillRuns(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{ID: 1, Name: "p", IsDefault: true}
	installPolicyCache(am, &policy, nil)

	dev := &models.Device{Name: "fw-mid", IPAddress: "10.9.9.9"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	// Fire while ON.
	if err := am.CheckTelemetryStale(dev, "no vitals for 90m"); err != nil {
		t.Fatal(err)
	}
	var open int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND resolved_at IS NULL", "TELEMETRY_STALE").Count(&open)
	if open != 1 {
		t.Fatalf("precondition: want 1 open TELEMETRY_STALE, got %d", open)
	}

	// Toggle Off mid-incident, then recover.
	installDefaultProfileToggles(am, map[models.AlertType]bool{models.AlertTypeTelemetryStale: false})
	am.CheckTelemetryRecovered(dev)

	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND resolved_at IS NULL", "TELEMETRY_STALE").Count(&open)
	if open != 0 {
		t.Fatal("toggled-off type stranded its open alert — recovery must stay ungated")
	}
	var companions int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "TELEMETRY_STALE_RESOLVED").Count(&companions)
	if companions != 1 {
		t.Fatalf("recovery companion rows = %d, want 1", companions)
	}
	// No re-fire while Off.
	if err := am.CheckTelemetryStale(dev, "no vitals for 90m"); err != nil {
		t.Fatal(err)
	}
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND resolved_at IS NULL", "TELEMETRY_STALE").Count(&open)
	if open != 0 {
		t.Fatalf("toggled-off type re-fired: %d open", open)
	}
}

// TRAFFIC_SPIKE gains the AlertEnabled gate (previously the ONLY per-scope-
// ungateable type): toggle Off → ProcessSpike is a no-op; ProcessSpikeResolve
// still closes an open row.
func TestSpike_ToggleOffGatesFireNotResolve(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{ID: 1, Name: "p", IsDefault: true}
	installPolicyCache(am, &policy, nil)

	dev := &models.Device{ID: 12, Name: "fw-sp", IPAddress: "10.4.4.4"}
	iface := &models.InterfaceStats{DeviceID: 12, Name: "wan1"}

	// Fire while ON, so a row exists to resolve.
	am.ProcessSpike(dev, iface, "warning", 100, 10, "spike up", nil)
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "TRAFFIC_SPIKE").Count(&n)
	if n != 1 {
		t.Fatalf("precondition: want 1 spike alert, got %d", n)
	}

	// Toggle Off: resolve must still close the open row…
	installDefaultProfileToggles(am, map[models.AlertType]bool{models.AlertTypeTrafficSpike: false})
	am.ProcessSpikeResolve(dev, iface, "spike cleared", nil)
	var open int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND resolved_at IS NULL", "TRAFFIC_SPIKE").Count(&open)
	if open != 0 {
		t.Fatal("ProcessSpikeResolve must stay ungated after a toggle-off")
	}
	// …and a new fire must be muted.
	am.ProcessSpike(dev, iface, "warning", 100, 10, "spike again", nil)
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND resolved_at IS NULL", "TRAFFIC_SPIKE").Count(&open)
	if open != 0 {
		t.Fatalf("toggled-off TRAFFIC_SPIKE fired: %d open rows", open)
	}
}

// Rule-generated alerts are toggle-killable (single authority — same behavior
// the retired AlertRule.Enabled had via fireEventAlert's gate).
func TestFireEventAlert_MutedByToggle(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{ID: 1, Name: "p", IsDefault: true}
	installPolicyCache(am, &policy, nil)
	installDefaultProfileToggles(am, map[models.AlertType]bool{models.AlertTypeSyslogCritical: false})

	r := models.EventRule{Name: "crit", Enabled: true, Priority: 10, Source: "syslog", Action: "alert",
		AlertType: models.AlertTypeSyslogCritical, MatchJSON: `{"op":"exists","field":"message"}`}
	if err := db.CreateEventRule(&r); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)

	if err := am.EvaluateSyslog(&models.SyslogMessage{DeviceID: 0, Hostname: "h", Message: "boom", Timestamp: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Count(&n)
	if n != 0 {
		t.Fatalf("toggle Off must mute rule-generated alerts too: got %d rows", n)
	}
}

// BenchmarkEvaluateSyslog_AllInDefault pins the hot path for the common
// install (every rule in Default — the pre-v48 shape).
func BenchmarkEvaluateSyslog_AllInDefault(b *testing.B) {
	am, db := newTestManagerB(b)
	db.EnsureDefaultEventProfile()
	for i := 0; i < 25; i++ {
		r := models.EventRule{Name: "r", Enabled: true, Priority: 100 + i, Source: "syslog", Action: "alert",
			MatchJSON: `{"op":"eq","field":"subtype","value":"never-matches"}`}
		if err := db.CreateEventRule(&r); err != nil {
			b.Fatal(err)
		}
	}
	am.RefreshPolicyCache(db)
	msg := &models.SyslogMessage{DeviceID: 0, Hostname: "h", Message: "type=traffic subtype=forward", Timestamp: time.Now()}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := am.EvaluateSyslog(msg, nil); err != nil {
			b.Fatal(err)
		}
	}
}
