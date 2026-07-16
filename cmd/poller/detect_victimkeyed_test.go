package main

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// seedDDoSBurst seeds an inbound packet flood at dst that trips the pps
// threshold set below (test-friendly detect_ddos_pps=100 via system_settings).
func seedDDoSBurst(t *testing.T, p *Poller, dst string) {
	t.Helper()
	at := time.Now().Add(-3 * time.Minute)
	for i := 0; i < 150; i++ {
		s := models.FlowSample{
			DeviceID: 1, Protocol: 6,
			SrcAddr: fmt.Sprintf("203.0.113.%d", i%200+1), DstAddr: dst, DstPort: 443,
			Bytes: 60, Packets: 60,
			Direction: uint8(classify.DirInbound), FlowSource: models.FlowSourceNetFlowV9, SamplingRate: 1,
			Timestamp: at,
		}
		if err := p.db.Gorm().Create(&s).Error; err != nil {
			t.Fatalf("seed flow: %v", err)
		}
	}
}

func setDetectSetting(t *testing.T, p *Poller, key, value string) {
	t.Helper()
	if err := p.db.Gorm().Create(&models.SystemSetting{Key: key, Value: value, Category: "detection", Type: "string"}).Error; err != nil {
		t.Fatalf("seed setting %s: %v", key, err)
	}
}

// TestFlowDetectionCycle_VictimKeyedRouting: a victim-keyed security detection
// (ddos_volumetric) must route down the per-detection path — producing an
// SFLOW_DDOS_VOLUMETRIC alert — and must NOT enter the per-source
// SFLOW_SECURITY consolidation (whose subject would be a degenerate "" source).
func TestFlowDetectionCycle_VictimKeyedRouting(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	setDetectSetting(t, p, "detect_ddos_pps", "100")
	seedDDoSBurst(t, p, "192.0.2.50")

	p.runFlowDetectionCycle()

	var ddosAlerts, secAlerts int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SFLOW_DDOS_VOLUMETRIC").Count(&ddosAlerts)
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SFLOW_SECURITY").Count(&secAlerts)
	if ddosAlerts != 1 {
		t.Errorf("SFLOW_DDOS_VOLUMETRIC alerts = %d, want 1", ddosAlerts)
	}
	if secAlerts != 0 {
		t.Errorf("victim-keyed detection leaked into SFLOW_SECURITY consolidation: %d", secAlerts)
	}

	// The detection row is linked to the alert (single-feed contract).
	var det models.FlowDetection
	if err := db.Gorm().Where("detector = ?", "ddos_volumetric").First(&det).Error; err != nil {
		t.Fatalf("detection row missing: %v", err)
	}
	if det.AlertID == nil || *det.AlertID == 0 {
		t.Error("detection not linked to its alert")
	}
}

// TestFlowDetectionCycle_SuppressRuleHitsVictimKeyed: the flow_security
// Event-Rules hub stays the single silencing surface — a suppress rule whose
// source_ip matches the VICTIM address mutes a victim-keyed detection (acked,
// no alert).
func TestFlowDetectionCycle_SuppressRuleHitsVictimKeyed(t *testing.T) {
	p, db := newTelemetryTestPoller(t)
	setDetectSetting(t, p, "detect_ddos_pps", "100")
	seedDDoSBurst(t, p, "192.0.2.51")

	rule := &models.EventRule{
		Name: "mute ddos victim", Enabled: true, Source: "flow_security", Action: "suppress",
		MatchJSON: `{"op":"eq","field":"source_ip","value":"192.0.2.51"}`,
	}
	if err := db.CreateEventRule(rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	p.alertManager.RefreshEventRules(db)

	p.runFlowDetectionCycle()

	var alerts int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SFLOW_DDOS_VOLUMETRIC").Count(&alerts)
	if alerts != 0 {
		t.Errorf("suppress rule did not mute the victim-keyed detection: %d alerts", alerts)
	}
	var det models.FlowDetection
	if err := db.Gorm().Where("detector = ?", "ddos_volumetric").First(&det).Error; err != nil {
		t.Fatalf("detection row missing: %v", err)
	}
	if !det.Acknowledged {
		t.Error("suppressed detection must be acknowledged (off the NOC card)")
	}
}
