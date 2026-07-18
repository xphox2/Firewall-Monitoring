package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func addFlowSecRule(t *testing.T, am *AlertManager, db *database.Database, name, action, severity, matchJSON string, priority int, expires *time.Time) {
	t.Helper()
	r := &models.EventRule{
		Name: name, Enabled: true, Source: "flow_security", Action: action,
		Severity: models.Severity(severity), Priority: priority,
		MatchJSON: matchJSON, ExpiresAt: expires,
	}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatalf("create flow_security rule: %v", err)
	}
	am.RefreshEventRules(db)
}

func fsFields(src, detector, severity string) map[string]string {
	return FlowSecFields(&models.FlowDetection{Detector: detector, Severity: severity, SrcAddr: src}, src, nil)
}

// F7: an "any"-source rule must NOT match flow_security events. A broad noise-
// suppress rule (with a missing-field neq that evaluates true) would otherwise
// silently start eating security detections.
func TestFlowSec_ExactSourceFilter(t *testing.T) {
	am, db := newTestManager(t)
	r := &models.EventRule{Name: "any-noise", Enabled: true, Source: "any", Action: "suppress",
		MatchJSON: `{"op":"neq","field":"nonexistent","value":"x"}`}
	if err := db.CreateEventRule(r); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	if _, _, matched := am.MatchFlowSecurityRule(fsFields("1.2.3.4", "port_scan", "warning"), 0, nil); matched {
		t.Fatal("an any-source rule must NOT match flow_security events (exact-source filter)")
	}
}

// A flow_security suppress rule keyed on source_ip mutes that source only.
func TestFlowSec_SuppressBySource(t *testing.T) {
	am, db := newTestManager(t)
	addFlowSecRule(t, am, db, "mute .9", "suppress", "", `{"op":"eq","field":"source_ip","value":"198.51.100.9"}`, 100, nil)
	action, _, matched := am.MatchFlowSecurityRule(fsFields("198.51.100.9", "port_scan", "warning"), 0, nil)
	if !matched || action != "suppress" {
		t.Fatalf("source_ip rule must suppress; matched=%v action=%q", matched, action)
	}
	if _, _, m := am.MatchFlowSecurityRule(fsFields("203.0.113.1", "port_scan", "warning"), 0, nil); m {
		t.Fatal("rule must not match a different source")
	}
}

// F2: first-match-any-action — a higher-priority alert/customize rule out-ranks a
// lower-priority suppress rule (priority ordering holds like every other source).
func TestFlowSec_PriorityFirstMatchAnyAction(t *testing.T) {
	am, db := newTestManager(t)
	addFlowSecRule(t, am, db, "low suppress", "suppress", "", `{"op":"eq","field":"detector","value":"port_scan"}`, 100, nil)
	addFlowSecRule(t, am, db, "high alert", "alert", "critical", `{"op":"eq","field":"detector","value":"port_scan"}`, 5, nil)
	action, _, matched := am.MatchFlowSecurityRule(fsFields("1.2.3.4", "port_scan", "warning"), 0, nil)
	if !matched || action != "alert" {
		t.Fatalf("priority-5 alert rule must win over priority-100 suppress; got matched=%v action=%q", matched, action)
	}
}

// F8: an expired temporary rule must not match (expiry enforced at match time,
// before the daily prune); a future-expiry rule still matches.
func TestFlowSec_ExpiryAtMatchTime(t *testing.T) {
	am, db := newTestManager(t)
	past := time.Now().Add(-time.Hour)
	addFlowSecRule(t, am, db, "expired mute", "suppress", "", `{"op":"eq","field":"source_ip","value":"1.2.3.4"}`, 50, &past)
	if _, _, matched := am.MatchFlowSecurityRule(fsFields("1.2.3.4", "port_scan", "warning"), 0, nil); matched {
		t.Fatal("an expired temp rule must not match")
	}

	am2, db2 := newTestManager(t)
	future := time.Now().Add(time.Hour)
	addFlowSecRule(t, am2, db2, "active mute", "suppress", "", `{"op":"eq","field":"source_ip","value":"1.2.3.4"}`, 50, &future)
	if _, _, matched := am2.MatchFlowSecurityRule(fsFields("1.2.3.4", "port_scan", "warning"), 0, nil); !matched {
		t.Fatal("a future-expiry temp rule must still match")
	}
}

// TestFlowSecFields_CategoryEventTypes pins the v0.11.111 generalization:
// event_type is category-mapped ("security_event" UNCHANGED for back-compat
// with pre-existing operator rules; policy/operational get their own), and
// dst_ip/dst_port/protocol surface only when the detection carries them.
func TestFlowSecFields_CategoryEventTypes(t *testing.T) {
	sec := FlowSecFields(&models.FlowDetection{Detector: "port_scan", Category: "security", SrcAddr: "1.2.3.4"}, "1.2.3.4", nil)
	if sec["event_type"] != "security_event" {
		t.Errorf("security category must stay security_event (operator rules exist), got %q", sec["event_type"])
	}
	// Legacy rows with an empty category (pre-taxonomy) stay security_event too.
	if f := FlowSecFields(&models.FlowDetection{Detector: "port_scan"}, "", nil); f["event_type"] != "security_event" {
		t.Errorf("empty category must default to security_event, got %q", f["event_type"])
	}
	pol := FlowSecFields(&models.FlowDetection{
		Detector: "cleartext", Category: "policy", SrcAddr: "10.0.0.5",
		DstAddr: "10.0.0.9", DstPort: 23, Protocol: 6,
	}, "10.0.0.5", nil)
	if pol["event_type"] != "policy_event" || pol["detector"] != "cleartext" {
		t.Errorf("policy detection fields wrong: %+v", pol)
	}
	if pol["dst_ip"] != "10.0.0.9" || pol["dst_port"] != "23" || pol["protocol"] != "6" {
		t.Errorf("dst fields missing/wrong: %+v", pol)
	}
	ops := FlowSecFields(&models.FlowDetection{Detector: "capacity", Category: "operational"}, "", nil)
	if ops["event_type"] != "operational_event" {
		t.Errorf("operational category must map to operational_event, got %q", ops["event_type"])
	}
	if _, ok := ops["dst_ip"]; ok {
		t.Error("absent dst fields must be omitted, not zero-valued (missing-field neq semantics)")
	}
}

// TestFlowSec_PolicyDetectionSuppress: a detector-scoped rule (the shape the
// suggester now emits for SFLOW_CLEARTEXT) matches a policy detection.
func TestFlowSec_PolicyDetectionSuppress(t *testing.T) {
	am, db := newTestManager(t)
	addFlowSecRule(t, am, db, "mute cleartext", "suppress", "",
		`{"op":"eq","field":"detector","value":"cleartext"}`, 50, nil)
	det := &models.FlowDetection{Detector: "cleartext", Category: "policy", Severity: "warning",
		SrcAddr: "10.0.0.5", DstAddr: "10.0.0.9", DstPort: 23, Protocol: 6}
	action, _, matched := am.MatchFlowSecurityRule(FlowSecFields(det, "10.0.0.5", nil), 0, nil)
	if !matched || action != "suppress" {
		t.Fatalf("detector-scoped rule must suppress the policy detection; matched=%v action=%q", matched, action)
	}
	// event_type-scoped rule matches the whole policy class…
	am2, db2 := newTestManager(t)
	addFlowSecRule(t, am2, db2, "mute policy class", "suppress", "",
		`{"op":"eq","field":"event_type","value":"policy_event"}`, 50, nil)
	if _, _, m := am2.MatchFlowSecurityRule(FlowSecFields(det, "10.0.0.5", nil), 0, nil); !m {
		t.Fatal("event_type=policy_event rule must match a policy detection")
	}
	// …but must NOT match a security detection (back-compat isolation).
	secDet := &models.FlowDetection{Detector: "port_scan", Category: "security", SrcAddr: "1.2.3.4"}
	if _, _, m := am2.MatchFlowSecurityRule(FlowSecFields(secDet, "1.2.3.4", nil), 0, nil); m {
		t.Fatal("a policy_event rule must not eat security detections")
	}
}

// TestProcessFlowDetection_RuleSuppressAndCustomize pins the per-detection
// alert path's new Event Rule consult: a suppress rule mutes (no alert), an
// alert rule overrides severity; the emitted alert carries the subject in
// SourceAddr so the suggested-rule endpoint can build a source-scoped matcher.
func TestProcessFlowDetection_RuleSuppressAndCustomize(t *testing.T) {
	det := func() *models.FlowDetection {
		return &models.FlowDetection{Detector: "cleartext", Category: "policy", Severity: "warning",
			DeviceID: 1, SrcAddr: "10.0.0.5", DstAddr: "10.0.0.9", DstPort: 23, Protocol: 6,
			DedupKey: "clr_10.0.0.5", Message: "telnet in the clear", DetectedAt: time.Now()}
	}
	// Suppress: no alert row.
	am, db := newTestManager(t)
	addFlowSecRule(t, am, db, "mute cleartext", "suppress", "",
		`{"op":"eq","field":"detector","value":"cleartext"}`, 50, nil)
	id, err := am.ProcessFlowDetection(det(), nil)
	if err != nil {
		t.Fatalf("ProcessFlowDetection: %v", err)
	}
	if id != 0 {
		t.Fatalf("suppress rule must mute the detection, got alert id %d", id)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Count(&n)
	if n != 0 {
		t.Fatalf("no alert row expected under a suppress rule, found %d", n)
	}

	// Customize: severity override + SourceAddr persisted.
	am2, db2 := newTestManager(t)
	addFlowSecRule(t, am2, db2, "escalate cleartext", "alert", "critical",
		`{"op":"eq","field":"detector","value":"cleartext"}`, 50, nil)
	id2, err := am2.ProcessFlowDetection(det(), nil)
	if err != nil {
		t.Fatalf("ProcessFlowDetection: %v", err)
	}
	if id2 == 0 {
		t.Fatal("alert-action rule must still emit an alert")
	}
	var a models.Alert
	if err := db2.Gorm().First(&a, id2).Error; err != nil {
		t.Fatalf("load alert: %v", err)
	}
	if a.Severity != "critical" {
		t.Errorf("rule severity override not applied: got %s want critical", a.Severity)
	}
	if a.SourceAddr != "10.0.0.5" {
		t.Errorf("alert must carry the detection subject in SourceAddr, got %q", a.SourceAddr)
	}
}
