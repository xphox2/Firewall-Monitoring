package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// Phase-1 state-rule engine: the episode/flap dampening in decideStateFire is
// the core of the "don't re-alert an acked down until it recovers and drops
// again; ≤1 alert/day while flapping; but fire if it was up for ≥1h" spec. These
// tests pin each branch.

func stateCand(deviceID uint, atype models.AlertType, metric string, minUp, dailyCap int) stateCandidate {
	return stateCandidate{
		deviceID:   deviceID,
		alertType:  atype,
		metricName: metric,
		dampen:     dampenParams{MinUpSeconds: minUp, DailyCap: dailyCap},
	}
}

func mkAlert(deviceID uint, atype models.AlertType, metric string, ts time.Time, suppressed bool, resolvedAt *time.Time, acked bool) *models.Alert {
	return &models.Alert{
		DeviceID: deviceID, AlertType: atype, MetricName: metric, Timestamp: ts,
		Suppressed: suppressed, ResolvedAt: resolvedAt, Acknowledged: acked,
	}
}

func TestDecideStateFire_FirstEver(t *testing.T) {
	am, _ := newTestManager(t)
	now := time.Now()
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateFire {
		t.Fatalf("first-ever down must fire, got %v", got)
	}
}

func TestDecideStateFire_OpenEpisodeSuppressed(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// An OPEN (unresolved) alert exists — same episode.
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-10*time.Minute), false, nil, false))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateSkip {
		t.Fatalf("open episode must skip, got %v", got)
	}
}

func TestDecideStateFire_AckedOpenStillSuppressed(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// Acked but still OPEN — the operator ack must NOT re-open the alert gate.
	seedAlert(t, db, mkAlert(1, "VPN_TUNNEL_DOWN", "vpn_t1", now.Add(-2*time.Hour), false, nil, true))
	c := stateCand(1, "VPN_TUNNEL_DOWN", "vpn_t1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateSkip {
		t.Fatalf("acked-open episode must skip, got %v", got)
	}
}

func TestDecideStateFire_UpOverAnHourFires(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// Previous down resolved 2h ago → the link was up ≥1h → fresh outage fires.
	resolved := now.Add(-2 * time.Hour)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-3*time.Hour), false, &resolved, true))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateFire {
		t.Fatalf("up ≥1h then down must fire, got %v", got)
	}
}

func TestDecideStateFire_FlapWithinCapSuppressed(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// Fired 5m ago, resolved 4m ago → up only ~4m (< 1h) and within 24h of the
	// last notification → flapping, suppress.
	resolved := now.Add(-4 * time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-5*time.Minute), false, &resolved, true))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateSuppressCapped {
		t.Fatalf("fast flap within cap must suppress, got %v", got)
	}
}

func TestDecideStateFire_DailyCapElapsedFires(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// Last NOTIFIED alert was >24h ago; since then only suppressed flap-evidence
	// rows (the most recent resolved 3m ago, so up-run < 1h). The daily window has
	// elapsed → fire once more.
	firedTS := now.Add(-25 * time.Hour)
	firedResolved := now.Add(-25*time.Hour + time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", firedTS, false, &firedResolved, true))
	// A more-recent SUPPRESSED flap row, resolved 3m ago.
	supResolved := now.Add(-3 * time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-4*time.Minute), true, &supResolved, false))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateFire {
		t.Fatalf("≥24h since last notification must fire, got %v", got)
	}
}

func TestDecideStateFire_ContinuousFlapNotFireBefore24h(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// Notified 10h ago, then flapping since; the most recent suppressed row
	// resolved 2m ago. Under 24h since the last notification → still suppress.
	firedTS := now.Add(-10 * time.Hour)
	firedResolved := now.Add(-10*time.Hour + time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", firedTS, false, &firedResolved, true))
	supResolved := now.Add(-2 * time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-3*time.Minute), true, &supResolved, false))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateSuppressCapped {
		t.Fatalf("<24h since last notification must suppress, got %v", got)
	}
}

func TestDecideStateFire_DailyCapDisabledAlwaysFires(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// dailyCap<=0 disables the cap: any new episode (no open row) fires.
	resolved := now.Add(-2 * time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-3*time.Minute), false, &resolved, true))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 0)
	if got := am.decideStateFire(c, now); got != stateFire {
		t.Fatalf("disabled cap must fire every episode, got %v", got)
	}
}

// TestBuildStateCandidate_DailyCapZeroHonored guards the UI promise that
// daily_cap 0 = "no cap": an explicitly-configured rule (refire_mode set) must
// keep 0, while a bare rule (empty dampen) falls back to the default cap of 1.
func TestBuildStateCandidate_DailyCapZeroHonored(t *testing.T) {
	am, _ := newTestManager(t)
	var nc notifier.NotifyConfig

	explicit := &compiledRule{source: "state", dampen: dampenParams{RefireMode: "episode", MinUpSeconds: 3600, DailyCap: 0}}
	c, ok := am.buildStateCandidateLocked(explicit, 1, nil, "k", "INTERFACE_DOWN", "interface_x", "down", nc)
	if !ok {
		t.Fatal("candidate should be enabled by default")
	}
	if c.dampen.DailyCap != 0 {
		t.Errorf("explicit daily_cap 0 must be honored as no-cap, got %d", c.dampen.DailyCap)
	}

	bare := &compiledRule{source: "state", dampen: dampenParams{}}
	c2, _ := am.buildStateCandidateLocked(bare, 1, nil, "k", "INTERFACE_DOWN", "interface_x", "down", nc)
	if c2.dampen.DailyCap != defaultStateDailyCap {
		t.Errorf("bare rule must default daily_cap to %d, got %d", defaultStateDailyCap, c2.dampen.DailyCap)
	}
	if c2.dampen.MinUpSeconds != defaultStateMinUpSeconds {
		t.Errorf("bare rule must default min_up to %d, got %d", defaultStateMinUpSeconds, c2.dampen.MinUpSeconds)
	}
}

// TestBuildStateCandidate_DisabledAlertSkipped covers Fable finding #1: when
// alerting is disabled for a device (AlertsEnabled=false), the owned path must
// NOT build a candidate — ownership must never resurrect an alert the operator
// turned off.
func TestBuildStateCandidate_DisabledAlertSkipped(t *testing.T) {
	am, db := newTestManager(t)
	var nc notifier.NotifyConfig
	// Load a policy cache with a device whose alerts are disabled. AlertsEnabled
	// has a `default:true` tag, so GORM omits the false zero-value on Create —
	// force it with an explicit column Update.
	if err := db.Gorm().Create(&models.DeviceAlertConfig{DeviceID: 7}).Error; err != nil {
		t.Fatalf("seed device config: %v", err)
	}
	if err := db.Gorm().Model(&models.DeviceAlertConfig{}).Where("device_id = ?", 7).Update("alerts_enabled", false).Error; err != nil {
		t.Fatalf("disable device alerts: %v", err)
	}
	am.RefreshPolicyCache(db)

	rule := &compiledRule{source: "state", dampen: dampenParams{RefireMode: "episode", MinUpSeconds: 3600, DailyCap: 1}}
	if _, ok := am.buildStateCandidateLocked(rule, 7, nil, "k", "INTERFACE_DOWN", "interface_x", "down", nc); ok {
		t.Fatal("candidate must NOT be built when device alerting is disabled")
	}
}

// TestDecideStateFire_StuckAfterFlapReEscalates covers Fable finding #2: a link
// that flapped (last notify within 24h) and then STAYED down leaves a suppressed
// open marker; once that marker is ≥24h old and the daily budget has room, the
// engine re-escalates so the outage isn't silent forever.
func TestDecideStateFire_StuckAfterFlapReEscalates(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	// Last NOTIFIED alert 30h ago (outside the 24h window) and resolved.
	firedResolved := now.Add(-30*time.Hour + time.Minute)
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-30*time.Hour), false, &firedResolved, true))
	// A suppressed OPEN marker created 25h ago that never recovered (stuck down).
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-25*time.Hour), true, nil, false))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateFire {
		t.Fatalf("stuck suppressed episode ≥24h with budget must re-escalate, got %v", got)
	}
}

// TestDecideStateFire_StuckSuppressedRecentStaysQuiet: the same stuck marker but
// only 2h old (and a notification already delivered this window) must NOT re-fire
// — the age guard prevents a per-cycle re-escalation loop.
func TestDecideStateFire_StuckSuppressedRecentStaysQuiet(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-3*time.Hour), false, ptrTime(now.Add(-2*time.Hour-50*time.Minute)), true))
	seedAlert(t, db, mkAlert(1, "INTERFACE_DOWN", "interface_port1", now.Add(-2*time.Hour), true, nil, false))
	c := stateCand(1, "INTERFACE_DOWN", "interface_port1", 3600, 1)
	if got := am.decideStateFire(c, now); got != stateSkip {
		t.Fatalf("recent stuck suppressed marker must stay quiet, got %v", got)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// seedStateRule installs an enabled source="state" alert rule matching one
// event_type and flips the ownership flag so CheckInterfaceStatus/CheckVPNStatus
// route through the state engine.
func seedStateRule(t *testing.T, db *database.Database, am *AlertManager, eventType, ownedCSV string) {
	t.Helper()
	rule := &models.EventRule{
		Name:       "Test " + eventType,
		Enabled:    true,
		Source:     "state",
		Action:     "alert",
		Severity:   models.SeverityWarning,
		MatchJSON:  `{"op":"eq","field":"event_type","value":"` + eventType + `"}`,
		DampenJSON: `{"refire_mode":"episode","min_up_seconds":3600,"daily_cap":1}`,
	}
	if err := db.Gorm().Create(rule).Error; err != nil {
		t.Fatalf("create state rule: %v", err)
	}
	if err := db.UpsertSetting(&models.SystemSetting{Key: stateOwnedTypesSetting, Value: ownedCSV}); err != nil {
		t.Fatalf("set ownership flag: %v", err)
	}
	am.RefreshEventRules(db)
}

func countOpenDownAlerts(t *testing.T, db *database.Database, atype models.AlertType, metric string) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND metric_name = ? AND resolved_at IS NULL", atype, metric).
		Count(&n).Error; err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

// TestCheckInterfaceStatus_StateOwnedRoutesAndDampens is the end-to-end proof:
// with the state engine owning interface_down, a down link that was previously
// up fires exactly once (episode), and stays silent while it remains down.
func TestCheckInterfaceStatus_StateOwnedRoutesAndDampens(t *testing.T) {
	am, db := newTestManager(t)
	seedStateRule(t, db, am, StateEventInterfaceDown, StateEventInterfaceDown)

	up := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "up", AdminStatus: "up"}}
	down := []models.InterfaceStats{{DeviceID: 1, Name: "port1", Status: "down", AdminStatus: "up"}}

	// Mark it up once so everUp is set (a real outage is "was up, now down").
	if err := am.CheckInterfaceStatus(up, nil); err != nil {
		t.Fatal(err)
	}
	// First down → one alert.
	if err := am.CheckInterfaceStatus(down, nil); err != nil {
		t.Fatal(err)
	}
	if got := countOpenDownAlerts(t, db, "INTERFACE_DOWN", "interface_port1"); got != 1 {
		t.Fatalf("first down: want 1 open alert, got %d", got)
	}
	// Still down (same episode) → no second alert.
	if err := am.CheckInterfaceStatus(down, nil); err != nil {
		t.Fatal(err)
	}
	if got := countOpenDownAlerts(t, db, "INTERFACE_DOWN", "interface_port1"); got != 1 {
		t.Fatalf("second down same episode: want 1 open alert, got %d", got)
	}
}

// TestCheckInterfaceStatus_NotOwnedUsesLegacy proves the ownership flag gates the
// path: without it, the legacy resolveAlertConfig path runs (no state rule
// consulted), so an enabled global toggle still fires. This is the no-gap
// guarantee during rollout.
func TestCheckInterfaceStatus_NotOwnedUsesLegacy(t *testing.T) {
	am, db := newTestManager(t)
	am.config.Alerts.InterfaceDownAlert = true
	// A state rule exists but the ownership flag is NOT set → legacy path.
	seedStateRule(t, db, am, StateEventInterfaceDown, "")

	up := []models.InterfaceStats{{DeviceID: 2, Name: "wan1", Status: "up", AdminStatus: "up"}}
	down := []models.InterfaceStats{{DeviceID: 2, Name: "wan1", Status: "down", AdminStatus: "up"}}
	if err := am.CheckInterfaceStatus(up, nil); err != nil {
		t.Fatal(err)
	}
	if err := am.CheckInterfaceStatus(down, nil); err != nil {
		t.Fatal(err)
	}
	if got := countOpenDownAlerts(t, db, "INTERFACE_DOWN", "interface_wan1"); got != 1 {
		t.Fatalf("legacy path: want 1 open alert, got %d", got)
	}
}
