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
