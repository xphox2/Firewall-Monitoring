//go:build integration

// DDoS detector end-to-end on real Postgres: the peak-minute bucketing uses a
// dialect-specific expression (EXTRACT(EPOCH ...) on PG vs strftime on the
// SQLite unit lane), so the PG branch is only exercised here. Also pins the
// victim-keyed routing through the real cycle on the engine prod runs.
package main

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/classify"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

func TestDDoSDetection_Postgres_EndToEnd(t *testing.T) {
	db := database.NewIntegrationDB(t) // skips if TEST_PG_DSN unset
	if err := db.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	cfg := &config.Config{}
	p := &Poller{
		cfg:            cfg,
		db:             db,
		alertManager:   alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db),
		notifier:       notifier.NewNotifier(cfg),
		prevIfaceStats: make(map[string]*models.InterfaceStats),
	}
	if err := db.Gorm().Create(&models.SystemSetting{Key: "detect_ddos_pps", Value: "100", Category: "detection", Type: "string"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	at := time.Now().Add(-3 * time.Minute)
	for i := 0; i < 150; i++ {
		s := models.FlowSample{
			DeviceID: 1, Protocol: 6,
			SrcAddr: fmt.Sprintf("203.0.113.%d", i%200+1), DstAddr: "192.0.2.60", DstPort: 443,
			Bytes: 60, Packets: 60,
			Direction: uint8(classify.DirInbound), FlowSource: models.FlowSourceNetFlowV9, SamplingRate: 1,
			Timestamp: at,
		}
		if err := db.Gorm().Create(&s).Error; err != nil {
			t.Fatalf("seed flow: %v", err)
		}
	}

	p.runFlowDetectionCycle()

	var ddosAlerts, secAlerts int64
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SFLOW_DDOS_VOLUMETRIC").Count(&ddosAlerts)
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ?", "SFLOW_SECURITY").Count(&secAlerts)
	if ddosAlerts != 1 {
		t.Errorf("SFLOW_DDOS_VOLUMETRIC on Postgres = %d, want 1", ddosAlerts)
	}
	if secAlerts != 0 {
		t.Errorf("victim-keyed detection leaked into SFLOW_SECURITY: %d", secAlerts)
	}
}
