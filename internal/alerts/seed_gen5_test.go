package alerts

import (
	"reflect"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// gen5Exclusions are the alert types deliberately WITHOUT a shipped default
// rule: SFLOW_AGENT_DROPS has no emitter anywhere (nothing produces the alert,
// so a rule would be dead weight — add its seed when an emitter lands).
// LOG_RULE_MATCH / FLOW_RULE_MATCH are covered by DISABLED template rules
// (they're emitted BY operator-authored rules) — the guardrail accepts those.
var gen5Exclusions = map[models.AlertType]bool{
	models.AlertTypeSFlowAgentDrops: true,
}

// TestSeedGen5_CoverEveryAlertType is the coverage guardrail: after seeding,
// every registry alert type (minus documented exclusions) has a shipped
// default rule whose Source matches the engine's authoritative type→source
// map, so the toggle matrix's "customize" path always has a rule to open.
func TestSeedGen5_CoverEveryAlertType(t *testing.T) {
	_, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()

	rules, err := db.ListEventRules()
	if err != nil {
		t.Fatal(err)
	}
	byType := map[models.AlertType][]models.EventRule{}
	for _, r := range rules {
		if r.SeedVersion > 0 {
			byType[r.AlertType] = append(byType[r.AlertType], r)
		}
	}

	for _, info := range models.AllAlertTypes() {
		at := info.Type
		if gen5Exclusions[at] {
			if len(byType[at]) != 0 {
				t.Errorf("%s: excluded type unexpectedly has %d seed rules", at, len(byType[at]))
			}
			continue
		}
		seeds := byType[at]
		if len(seeds) == 0 {
			t.Errorf("%s: NO shipped default rule — every registry type needs a customization surface", at)
			continue
		}
		wantSource := ruleSourceForAlertType(at)
		found := false
		for _, s := range seeds {
			if s.Source == wantSource {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no seed rule with engine source %q (got %v)", at, wantSource, seeds[0].Source)
		}
	}

	// Gen-5 shape pins.
	var gen5 []models.EventRule
	for _, r := range rules {
		if r.SeedVersion == 5 {
			gen5 = append(gen5, r)
		}
	}
	if len(gen5) != 23 {
		t.Errorf("gen-5 seed count = %d, want 23", len(gen5))
	}
	for _, r := range gen5 {
		if r.Action != "alert" {
			t.Errorf("%s: gen-5 seeds are alert-action customize handles, got %q", r.Name, r.Action)
		}
		if r.Severity != "" || r.CooldownMinutes != nil || r.GroupBy != "" || r.DampenJSON != "" || r.PolicyID != nil {
			t.Errorf("%s: gen-5 seeds must ship with ALL overrides blank (behavior-neutral)", r.Name)
		}
		switch r.Name {
		case "Default: HA member up":
			if r.Enabled {
				t.Error("HA member up seed MUST ship disabled: the trap parses as info and the LC-14 gate would opt it into alerting")
			}
		case "Default: Custom log rule (template)", "Default: Custom flow rule (template)":
			if r.Enabled {
				t.Errorf("%s must ship disabled (custom-rule output template)", r.Name)
			}
		default:
			if !r.Enabled {
				t.Errorf("%s: unexpected disabled gen-5 seed", r.Name)
			}
		}
		// Detector-specific flow rules must outrank the broad card/digest rules.
		if r.Source == "flow_security" {
			isBroad := r.AlertType == models.AlertTypeSFlowSecurity || r.AlertType == models.AlertTypeSFlowSecurityDigest
			if isBroad && r.Priority != 210 {
				t.Errorf("%s: broad flow seed priority = %d, want 210", r.Name, r.Priority)
			}
			if !isBroad && r.Priority != 200 {
				t.Errorf("%s: detector flow seed priority = %d, want 200 (< broad 210)", r.Name, r.Priority)
			}
		} else if r.Priority != 200 {
			t.Errorf("%s: gen-5 priority = %d, want 200 (operator default 100 must always win)", r.Name, r.Priority)
		}
	}

	// Template lookup surface used by the UI's recreate path.
	if tpl, ok := db.DefaultRuleTemplate(models.AlertTypeDeviceOffline); !ok || tpl.Source != "device" {
		t.Error("DefaultRuleTemplate(DEVICE_OFFLINE) must return the device seed")
	}
	if _, ok := db.DefaultRuleTemplate(models.AlertTypeSFlowAgentDrops); ok {
		t.Error("DefaultRuleTemplate must not invent a rule for the excluded SFLOW_AGENT_DROPS")
	}
}

// TestSeedGen5_DeviceOverlayNeutral: a matched gen-5 device seed with blank
// overrides leaves the resolved config bit-for-bit identical (the seed is a
// customize HANDLE, not a behavior change).
func TestSeedGen5_DeviceOverlayNeutral(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()
	am.RefreshEventRules(db)

	resolved := am.resolveAlertConfig(1, nil, models.AlertTypeDeviceOffline)
	before := resolved

	am.mu.RLock()
	rule, suppressed := am.consultDeviceRuleLocked(models.AlertTypeDeviceOffline, 1, nil, "critical", nil, &resolved)
	am.mu.RUnlock()
	if rule == nil {
		t.Fatal("gen-5 device_offline seed did not match")
	}
	if suppressed {
		t.Fatal("alert-action seed must not suppress")
	}
	if !reflect.DeepEqual(before, resolved) {
		t.Errorf("blank seed mutated resolved config:\n before %+v\n after  %+v", before, resolved)
	}
}

// TestSeedGen5_TrapNeutralAndOptIn: with all gen-5 seeds loaded, a warning
// HA_STATE_CHANGE trap alerts exactly as before, an info HA_MEMBER_UP trap
// stays SILENT (its seed ships disabled), and enabling that seed opts the
// info trap into alerting — the documented feature.
func TestSeedGen5_TrapNeutralAndOptIn(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()
	am.RefreshEventRules(db)

	if err := am.ProcessTrap(&models.TrapEvent{
		Timestamp: time.Now(), TrapType: "HA_STATE_CHANGE", Severity: "warning",
		SourceIP: "192.0.2.20", Message: "ha state change",
	}, nil); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "HA_STATE_CHANGE").Count(&n)
	if n != 1 {
		t.Fatalf("warning HA_STATE_CHANGE with blank seed: alerts = %d, want 1 (unchanged)", n)
	}

	// Info trap: disabled seed → legacy drop preserved.
	if err := am.ProcessTrap(&models.TrapEvent{
		Timestamp: time.Now(), TrapType: "HA_MEMBER_UP", Severity: "info",
		SourceIP: "192.0.2.21", Message: "member up",
	}, nil); err != nil {
		t.Fatal(err)
	}
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "HA_MEMBER_UP").Count(&n)
	if n != 0 {
		t.Fatalf("info HA_MEMBER_UP with DISABLED seed: alerts = %d, want 0 (still muted)", n)
	}

	// Enable the seed → opt-in.
	if err := db.Gorm().Model(&models.EventRule{}).
		Where("name = ?", "Default: HA member up").Update("enabled", true).Error; err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	if err := am.ProcessTrap(&models.TrapEvent{
		Timestamp: time.Now(), TrapType: "HA_MEMBER_UP", Severity: "info",
		SourceIP: "192.0.2.22", Message: "member up",
	}, nil); err != nil {
		t.Fatal(err)
	}
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "HA_MEMBER_UP").Count(&n)
	if n != 1 {
		t.Fatalf("info HA_MEMBER_UP with ENABLED seed: alerts = %d, want 1 (opt-in)", n)
	}
}

// TestSeedGen5_FlowDetectionNeutralAndSuppressPriority: a cleartext detection
// alerts identically with the gen-5 seeds loaded (severity from the detection,
// dedup fold-in on repeat), and an operator suppress at priority 100 beats the
// seed at 200.
func TestSeedGen5_FlowDetectionNeutralAndSuppressPriority(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()
	am.RefreshEventRules(db)

	det := saveDet(t, db, &models.FlowDetection{
		DetectedAt: time.Now().UTC(), Detector: "cleartext", Category: "policy",
		Severity: "warning", DeviceID: 7, SrcAddr: "198.51.100.9",
		DstAddr: "10.0.0.5", DstPort: 23, Message: "telnet cleartext",
		DedupKey: "cleartext_198.51.100.9",
	})
	id, err := am.ProcessFlowDetection(det, nil)
	if err != nil || id == 0 {
		t.Fatalf("ProcessFlowDetection id=%d err=%v", id, err)
	}
	a := getAlert(t, db, id)
	if a.Severity != "warning" || a.AlertType != models.AlertTypeSFlowCleartext {
		t.Errorf("blank seed changed the alert: sev=%s type=%s", a.Severity, a.AlertType)
	}
	// Repeat within cooldown folds into the same alert (dedup key untouched).
	det2 := saveDet(t, db, &models.FlowDetection{
		DetectedAt: time.Now().UTC(), Detector: "cleartext", Category: "policy",
		Severity: "warning", DeviceID: 7, SrcAddr: "198.51.100.9",
		DstAddr: "10.0.0.5", DstPort: 23, Message: "telnet cleartext again",
		DedupKey: "cleartext_198.51.100.9",
	})
	id2, err := am.ProcessFlowDetection(det2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id {
		t.Errorf("repeat detection opened a NEW alert (%d vs %d) — dedup regressed", id2, id)
	}

	// Operator suppress at the editor default (100) must beat the seed (200).
	if err := db.CreateEventRule(&models.EventRule{
		Name: "op mute cleartext", Enabled: true, Priority: 100,
		Source: "flow_security", Action: "suppress",
		MatchJSON: `{"op":"eq","field":"detector","value":"cleartext"}`,
	}); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	det3 := saveDet(t, db, &models.FlowDetection{
		DetectedAt: time.Now().UTC(), Detector: "cleartext", Category: "policy",
		Severity: "warning", DeviceID: 7, SrcAddr: "203.0.113.4",
		DstAddr: "10.0.0.5", DstPort: 23, Message: "telnet cleartext",
		DedupKey: "cleartext_203.0.113.4",
	})
	id3, err := am.ProcessFlowDetection(det3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id3 != 0 {
		t.Errorf("operator suppress (pri 100) lost to the gen-5 seed (pri 200): alert %d fired", id3)
	}
}

// TestSeedGen5_DigestConsult: the new ProcessSecurityDigest rule consult —
// blank seed → identical digest; a security_digest suppress mutes the rollup
// AND acks the storm detections; a severity-carrying rule re-grades; and a
// per-source security_event suppress does NOT bleed onto digests.
func TestSeedGen5_DigestConsult(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultEventProfile()
	db.EnsureDefaultRules()
	am.RefreshEventRules(db)
	am.SetStormSourcesDefault(5)

	mkGroup := func(base string, n int) []*models.FlowDetection {
		var g []*models.FlowDetection
		for i := 0; i < n; i++ {
			g = append(g, saveDet(t, db, secDet(base+itoaTest(i), "port_scan", "warning")))
		}
		return g
	}

	// Blank gen-5 seeds → digest identical to the pre-consult behavior.
	id, err := am.ProcessSecurityDigest(nil, "port_scan", mkGroup("198.51.100.", 10))
	if err != nil || id == 0 {
		t.Fatalf("digest with blank seeds: id=%d err=%v", id, err)
	}
	a := getAlert(t, db, id)
	if a.AlertType != models.AlertTypeSFlowSecurityDigest || a.Severity != "warning" {
		t.Errorf("blank seed changed digest: type=%s sev=%s", a.AlertType, a.Severity)
	}

	// A per-source security_event suppress must NOT govern digests (dedicated
	// security_digest event_type).
	if err := db.CreateEventRule(&models.EventRule{
		Name: "op mute per-source cards", Enabled: true, Priority: 50,
		Source: "flow_security", Action: "suppress",
		MatchJSON: `{"op":"eq","field":"event_type","value":"security_event"}`,
	}); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	var site uint = 3
	id2, err := am.ProcessSecurityDigest(&site, "threat_intel", mkGroup("203.0.113.", 8))
	if err != nil || id2 == 0 {
		t.Fatalf("digest must survive a security_event suppress: id=%d err=%v", id2, err)
	}

	// A security_digest suppress mutes the rollup and acks the detections.
	if err := db.CreateEventRule(&models.EventRule{
		Name: "op mute digests", Enabled: true, Priority: 40,
		Source: "flow_security", Action: "suppress",
		MatchJSON: `{"op":"eq","field":"event_type","value":"security_digest"}`,
	}); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	group := mkGroup("192.0.2.", 6)
	id3, err := am.ProcessSecurityDigest(nil, "super_spreader", group)
	if err != nil {
		t.Fatal(err)
	}
	if id3 != 0 {
		t.Fatalf("security_digest suppress ignored: digest %d fired", id3)
	}
	var acked int64
	db.Gorm().Model(&models.FlowDetection{}).Where("id IN ? AND acknowledged = ?", detIDs(group), true).Count(&acked)
	if int(acked) != len(group) {
		t.Errorf("digest suppress must ack the storm detections: %d/%d acked", acked, len(group))
	}

	// Suppress must NOT burn the cooldown: after disabling the mute, the SAME
	// detector's next digest fires immediately (the suppress path returns
	// before recordCooldownLocked).
	if err := db.Gorm().Model(&models.EventRule{}).Where("name = ?", "op mute digests").
		Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	idRefire, err := am.ProcessSecurityDigest(nil, "super_spreader", mkGroup("198.19.0.", 6))
	if err != nil || idRefire == 0 {
		t.Fatalf("digest after un-suppressing must fire immediately (no burned cooldown): id=%d err=%v", idRefire, err)
	}
	if err := db.CreateEventRule(&models.EventRule{
		Name: "op escalate digests", Enabled: true, Priority: 30,
		Source: "flow_security", Action: "alert", Severity: "critical",
		MatchJSON: `{"op":"eq","field":"event_type","value":"security_digest"}`,
	}); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)
	id4, err := am.ProcessSecurityDigest(nil, "c2_beacon", mkGroup("198.18.0.", 7))
	if err != nil || id4 == 0 {
		t.Fatalf("re-grade digest: id=%d err=%v", id4, err)
	}
	if got := getAlert(t, db, id4); got.Severity != "critical" {
		t.Errorf("digest rule severity override ignored: sev=%s, want critical", got.Severity)
	}
}

func detIDs(group []*models.FlowDetection) []uint {
	ids := make([]uint, 0, len(group))
	for _, d := range group {
		ids = append(ids, d.ID)
	}
	return ids
}
