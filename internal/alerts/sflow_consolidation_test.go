package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// newTestManager2 builds a fresh AlertManager over an EXISTING db, to simulate a
// process restart (empty in-memory cooldown, same persistent state).
func newTestManager2(t *testing.T, db *database.Database) (*AlertManager, *database.Database) {
	t.Helper()
	cfg := &config.Config{}
	return NewAlertManager(cfg, notifier.NewNotifier(cfg), db), db
}

// saveDet persists a flow detection (so it gets an ID the consolidation link can
// reference) and returns it.
func saveDet(t *testing.T, db interface {
	SaveFlowDetection(*models.FlowDetection) error
}, d *models.FlowDetection) *models.FlowDetection {
	t.Helper()
	if d.DetectedAt.IsZero() {
		d.DetectedAt = time.Now().UTC()
	}
	if err := db.SaveFlowDetection(d); err != nil {
		t.Fatalf("save detection: %v", err)
	}
	return d
}

// runSecurityCycle mimics the poller: process a group of security detections into
// one alert, then link the whole group (so the next cycle's link-lookup works).
func runSecurityCycle(t *testing.T, am *AlertManager, group []*models.FlowDetection) uint {
	t.Helper()
	alertID, err := am.ProcessSecurityEvent(group, nil)
	if err != nil {
		t.Fatalf("ProcessSecurityEvent: %v", err)
	}
	if alertID != 0 {
		ids := make([]uint, 0, len(group))
		for _, d := range group {
			ids = append(ids, d.ID)
		}
		if err := am.db.LinkFlowDetectionsToAlert(ids, alertID); err != nil {
			t.Fatalf("link detections: %v", err)
		}
	}
	return alertID
}

func countAlerts(t *testing.T, am *AlertManager) int64 {
	t.Helper()
	var n int64
	am.db.Gorm().Model(&models.Alert{}).Count(&n)
	return n
}

func secDet(src, detector, sev string) *models.FlowDetection {
	return &models.FlowDetection{
		DetectedAt: time.Now().UTC(),
		Detector:   detector,
		Category:   "security",
		Severity:   sev,
		DeviceID:   7,
		SrcAddr:    src,
		DstAddr:    "9.9.9.9",
		Message:    detector + " from " + src,
		DedupKey:   detector + "_" + src,
	}
}

// TestConsolidation_OneAlertPerSource_AcrossWinnerChange is the core single-feed
// guarantee: repeated cycles for the same source — even when the winning
// detector changes — must NOT open a second alert.
func TestConsolidation_OneAlertPerSource_AcrossWinnerChange(t *testing.T) {
	am, db := newTestManager(t)

	// Cycle 1: threat_intel (warning) wins.
	d1 := saveDet(t, db, secDet("1.2.3.4", "threat_intel", "warning"))
	id1 := runSecurityCycle(t, am, []*models.FlowDetection{d1})
	if id1 == 0 {
		t.Fatal("cycle 1 should create an alert")
	}
	if n := countAlerts(t, am); n != 1 {
		t.Fatalf("after cycle 1: %d alerts, want 1", n)
	}

	// Cycle 2: a different detector (port_scan) for the same source. Must fold
	// into the existing alert, not create a new one.
	d2 := saveDet(t, db, secDet("1.2.3.4", "port_scan", "warning"))
	id2 := runSecurityCycle(t, am, []*models.FlowDetection{d2})
	if id2 != id1 {
		t.Fatalf("cycle 2 alert id=%d, want same as cycle 1 (%d)", id2, id1)
	}
	if n := countAlerts(t, am); n != 1 {
		t.Fatalf("after cycle 2: %d alerts, want 1 (no duplicate)", n)
	}
	// The cycle-2 detection must be linked to the same alert (off the card).
	var linked models.FlowDetection
	db.Gorm().First(&linked, d2.ID)
	if linked.AlertID == nil || *linked.AlertID != id1 {
		t.Fatalf("cycle-2 detection alert_id=%v, want %d", linked.AlertID, id1)
	}
}

// TestConsolidation_PolicyRuleSeverityOverridesDetector: an explicit severity on
// a matching policy rule wins over the detector's own severity — so an operator
// can down/up-grade SFLOW_SECURITY from the Alert Policies editor.
func TestConsolidation_PolicyRuleSeverityOverridesDetector(t *testing.T) {
	am, db := newTestManager(t)
	policy := models.AlertPolicy{
		ID: 1, Name: "p", IsDefault: true,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: "SFLOW_SECURITY", Enabled: true, Severity: "info"}},
	}
	installPolicyCache(am, &policy, nil)

	// The detector rates this "warning"; the operator's rule says "info".
	d := saveDet(t, db, secDet("1.2.3.4", "threat_intel", "warning"))
	id := runSecurityCycle(t, am, []*models.FlowDetection{d})
	if id == 0 {
		t.Fatal("expected an alert")
	}
	if got := getAlert(t, db, id).Severity; got != "info" {
		t.Fatalf("alert severity = %q, want info (policy rule must override the detector's warning)", got)
	}
}

// TestConsolidation_SeverityEscalationBreaksCooldown: a mid-event critical must
// fire immediately and raise the open alert, never be swallowed by the warning's
// cooldown.
func TestConsolidation_SeverityEscalationBreaksCooldown(t *testing.T) {
	am, db := newTestManager(t)

	d1 := saveDet(t, db, secDet("5.5.5.5", "port_scan", "warning"))
	id1 := runSecurityCycle(t, am, []*models.FlowDetection{d1})

	// Same source, now critical (e.g. it landed on the threat feed).
	d2 := saveDet(t, db, secDet("5.5.5.5", "port_scan", "critical"))
	id2 := runSecurityCycle(t, am, []*models.FlowDetection{d2})

	if id2 != id1 {
		t.Fatalf("escalation should update the same alert, got %d vs %d", id2, id1)
	}
	if n := countAlerts(t, am); n != 1 {
		t.Fatalf("escalation must not create a new alert; got %d", n)
	}
	got := getAlert(t, db, id1)
	if got.Severity != "critical" {
		t.Fatalf("alert severity=%q after escalation, want critical", got.Severity)
	}
	if got.EscalationCount < 1 {
		t.Fatalf("escalation_count=%d, want >=1", got.EscalationCount)
	}
}

// TestConsolidation_RestartDoesNotDuplicate: a fresh AlertManager (empty
// in-memory cooldown) with a pre-existing open linked alert must NOT re-fire.
func TestConsolidation_RestartDoesNotDuplicate(t *testing.T) {
	am, db := newTestManager(t)

	// Pre-existing open alert + a detection linked to it (as a prior process
	// would have left behind).
	pre := &models.Alert{Timestamp: time.Now(), DeviceID: 7, AlertType: "SFLOW_SECURITY", Severity: "warning", MetricName: "sflow_port_scan"}
	seedAlert(t, db, pre)
	old := secDet("8.8.8.8", "port_scan", "warning")
	old.AlertID = &pre.ID
	saveDet(t, db, old)

	// "After restart": a fresh manager sees a new detection for the same source.
	am2, _ := newTestManager2(t, db)
	d := saveDet(t, db, secDet("8.8.8.8", "port_scan", "warning"))
	id := runSecurityCycle(t, am2, []*models.FlowDetection{d})
	if id != pre.ID {
		t.Fatalf("post-restart cycle should reuse the open alert %d, got %d", pre.ID, id)
	}
	if n := countAlerts(t, am2); n != 1 {
		t.Fatalf("post-restart: %d alerts, want 1 (no duplicate fire)", n)
	}
	_ = am
}

// TestConsolidation_TwoSourcesOneDevice_NoCrossLink: two distinct sources behind
// one device must yield two alerts with no cross-linking.
func TestConsolidation_TwoSourcesOneDevice_NoCrossLink(t *testing.T) {
	am, db := newTestManager(t)

	da := saveDet(t, db, secDet("10.0.0.1", "port_scan", "warning"))
	idA := runSecurityCycle(t, am, []*models.FlowDetection{da})
	db2 := saveDet(t, db, secDet("10.0.0.2", "port_scan", "warning"))
	idB := runSecurityCycle(t, am, []*models.FlowDetection{db2})

	if idA == 0 || idB == 0 || idA == idB {
		t.Fatalf("two sources should get two distinct alerts, got %d and %d", idA, idB)
	}
	if n := countAlerts(t, am); n != 2 {
		t.Fatalf("want 2 alerts, got %d", n)
	}
	var la, lb models.FlowDetection
	db.Gorm().First(&la, da.ID)
	db.Gorm().First(&lb, db2.ID)
	if la.AlertID == nil || *la.AlertID != idA || lb.AlertID == nil || *lb.AlertID != idB {
		t.Fatalf("cross-link: A.alert=%v (want %d), B.alert=%v (want %d)", la.AlertID, idA, lb.AlertID, idB)
	}
}

// TestSingleFeed_AlertedDetectionFilteredFromCard: a detection that produced an
// alert is excluded from the default detections list (sFlow card / NOC).
func TestSingleFeed_AlertedDetectionFilteredFromCard(t *testing.T) {
	am, db := newTestManager(t)

	// Non-security detection → 1:1 alert, then linked.
	d := saveDet(t, db, &models.FlowDetection{
		DetectedAt: time.Now().UTC(), Detector: "cleartext", Category: "operational",
		Severity: "warning", DeviceID: 7, DstPort: 23, Message: "cleartext", DedupKey: "cleartext_7_23",
	})
	alertID, err := am.ProcessFlowDetection(d, nil)
	if err != nil {
		t.Fatalf("ProcessFlowDetection: %v", err)
	}
	if alertID == 0 {
		t.Fatal("expected an alert")
	}
	if err := db.LinkFlowDetectionsToAlert([]uint{d.ID}, alertID); err != nil {
		t.Fatalf("link: %v", err)
	}

	since := time.Now().Add(-time.Hour)
	card, err := db.GetRecentDetections(since, 100, false, false) // default: exclude alerted
	if err != nil {
		t.Fatalf("GetRecentDetections: %v", err)
	}
	for _, r := range card {
		if r.ID == d.ID {
			t.Fatalf("alerted detection %d must be filtered from the card", d.ID)
		}
	}
	all, _ := db.GetRecentDetections(since, 100, false, true) // includeAlerted
	found := false
	for _, r := range all {
		if r.ID == d.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("includeAlerted=true should still return detection %d", d.ID)
	}
}
