package main

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// installDefaultToggles wires a Default event profile with explicit toggle
// rows into the poller's AlertManager cache (mirrors the alerts-package
// helper; the cache is package-private so each test package wires via
// RefreshThresholds-equivalent state).
func installDefaultToggles(t *testing.T, p *Poller, toggles map[models.AlertType]bool) {
	t.Helper()
	db := p.db
	profile := &models.EventRuleProfile{Name: "Default", IsDefault: true}
	mustCreate(t, db, profile)
	for at, enabled := range toggles {
		row := &models.EventRuleProfileToggle{ProfileID: profile.ID, AlertType: at, Enabled: enabled}
		mustCreate(t, db, row)
		if !enabled {
			// GORM default:true trap: pin the false explicitly.
			if err := db.Gorm().Model(&models.EventRuleProfileToggle{}).
				Where("id = ?", row.ID).Update("enabled", false).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	p.alertManager.RefreshPolicyCache(db)
}

// TestFlowTogglePass_DropsToggledOffSubType pins the v0.11.122 fix for the
// user-reported bug: toggling SFLOW_DENY_STORM Off in the Default profile did
// NOTHING — deny-storm detections consolidate into SFLOW_SECURITY before any
// per-type gate saw them, so only a suppress rule worked. The poller pass now
// consults the detection's OWN sub-type toggle and drops+acks toggled-off
// detections before consolidation, while unrelated detectors survive.
func TestFlowTogglePass_DropsToggledOffSubType(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	installDefaultToggles(t, p, map[models.AlertType]bool{
		models.AlertTypeSFlowDenyStorm: false, // operator slid it Off
	})

	deny := &models.FlowDetection{Detector: "deny_storm", Category: "security", Severity: "warning",
		DeviceID: 1, SrcAddr: "203.0.113.7", DetectedAt: time.Now().UTC(), DedupKey: "ds_x"}
	mustCreate(t, db, deny)
	scan := &models.FlowDetection{Detector: "port_scan", Category: "security", Severity: "warning",
		DeviceID: 1, SrcAddr: "203.0.113.8", DetectedAt: time.Now().UTC(), DedupKey: "ps_x"}
	mustCreate(t, db, scan)

	bySubject := map[string][]*models.FlowDetection{
		deny.SrcAddr: {deny},
		scan.SrcAddr: {scan},
	}
	p.applyFlowSecuritySuppressRules(bySubject)

	if _, ok := bySubject[deny.SrcAddr]; ok {
		t.Error("toggled-off deny_storm detection must be dropped before consolidation")
	}
	if _, ok := bySubject[scan.SrcAddr]; !ok {
		t.Error("port_scan (no registry sub-type, implicit ON) must survive the pass")
	}
	var got models.FlowDetection
	if err := db.Gorm().First(&got, deny.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !got.Acknowledged {
		t.Error("toggled-off detection must be acked off the NOC card (parity with suppress)")
	}
}

// TestFlowTogglePass_MasterToggleDoesNotAckDetections: toggling the
// SFLOW_SECURITY MASTER type Off gates only the consolidated ALERT
// (ProcessSecurityEvent) — the poller pass must NOT ack/drop the underlying
// detections, so the NOC card keeps sub-threshold signal. Guards against a
// future "simplification" folding the master toggle into the per-detector
// check.
func TestFlowTogglePass_MasterToggleDoesNotAckDetections(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	installDefaultToggles(t, p, map[models.AlertType]bool{
		models.AlertTypeSFlowSecurity: false, // master Off
	})
	scan := &models.FlowDetection{Detector: "port_scan", Category: "security", Severity: "warning",
		DeviceID: 1, SrcAddr: "203.0.113.10", DetectedAt: time.Now().UTC(), DedupKey: "ps_m"}
	mustCreate(t, db, scan)
	bySubject := map[string][]*models.FlowDetection{scan.SrcAddr: {scan}}
	p.applyFlowSecuritySuppressRules(bySubject)
	if _, ok := bySubject[scan.SrcAddr]; !ok {
		t.Error("master SFLOW_SECURITY toggle must not drop detections at the poller pass")
	}
	var got models.FlowDetection
	if err := db.Gorm().First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Acknowledged {
		t.Error("master toggle Off must not ack detections — the card keeps sub-threshold signal")
	}
}

// TestStormRollup_ToggledOffDigestDoesNotSwallowPerSource is the end-to-end
// AUDIT-243 follow-up: with the SFLOW_SECURITY_DIGEST type toggled OFF, a live
// cross-source storm must NOT be consumed into a digest that ProcessSecurityDigest
// then drops (silent suppression) — the detections must survive rollUpSecurityStorms
// so the per-source SFLOW_SECURITY path fires them. Pre-fix, StormThreshold returned
// the (seeded/overridden) threshold even for a disabled digest, so the 10-source
// storm cleared it, got rolled up, and vanished.
func TestStormRollup_ToggledOffDigestDoesNotSwallowPerSource(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	installDefaultToggles(t, p, map[models.AlertType]bool{
		models.AlertTypeSFlowSecurityDigest: false, // digest slid Off
	})
	// A storm threshold of 5 that a 10-source storm clears — the rollup would
	// fire if the toggle-off did not force StormThreshold to 0.
	p.alertManager.SetStormSourcesDefault(5)

	bySubject := map[string][]*models.FlowDetection{}
	for i := 0; i < 10; i++ {
		src := "203.0.113." + itoa(i)
		d := &models.FlowDetection{Detector: "port_scan", Category: "security", Severity: "warning",
			DeviceID: 1, SrcAddr: src, DetectedAt: time.Now().UTC(), DedupKey: "ps_storm_" + itoa(i)}
		mustCreate(t, db, d)
		bySubject[src] = []*models.FlowDetection{d}
	}

	link := func(_ []uint, _ uint, _ string) {}
	p.rollUpSecurityStorms(bySubject, link)

	// Every source must survive (not consumed into a swallowed digest), so the
	// per-source loop fires 10 SFLOW_SECURITY alerts.
	if len(bySubject) != 10 {
		t.Fatalf("toggled-off digest swallowed the storm: %d of 10 sources survived rollUpSecurityStorms", len(bySubject))
	}
	// And no digest alert was written for the disabled type.
	var digests int64
	db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ?", models.AlertTypeSFlowSecurityDigest).Count(&digests)
	if digests != 0 {
		t.Errorf("a toggled-off digest wrote %d alert(s), want 0", digests)
	}
}

// itoa keeps the storm test independent of any package helper.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestFlowTogglePass_OnRowIsNoop: an explicit ON row (or no row) leaves
// detections untouched — the pass only ever REMOVES work.
func TestFlowTogglePass_OnRowIsNoop(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	installDefaultToggles(t, p, map[models.AlertType]bool{
		models.AlertTypeSFlowDenyStorm: true,
	})
	deny := &models.FlowDetection{Detector: "deny_storm", Category: "security", Severity: "warning",
		DeviceID: 1, SrcAddr: "203.0.113.9", DetectedAt: time.Now().UTC(), DedupKey: "ds_y"}
	mustCreate(t, db, deny)
	bySubject := map[string][]*models.FlowDetection{deny.SrcAddr: {deny}}
	p.applyFlowSecuritySuppressRules(bySubject)
	if _, ok := bySubject[deny.SrcAddr]; !ok {
		t.Error("explicit-ON deny_storm detection must survive the pass")
	}
}
