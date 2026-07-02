package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// TestCleanupOldData_FlowAnalyticsTables_H4 is the regression for the
// 2026-07-01 audit H4 finding: flow_rollups ('1d' terminal rows),
// flow_detections, and flow_agent_drops had no retention path anywhere and
// grew without bound. CleanupOldData now ages flow_rollups on timestamp,
// flow_detections on detected_at, and flow_agent_drops on window_start, each
// behind its own RETENTION_* knob.
func TestCleanupOldData_FlowAnalyticsTables_H4(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(
		&models.FlowRollup{}, &models.FlowDetection{}, &models.AgentDrops{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Now()
	old := now.AddDate(0, 0, -400) // beyond every window below
	fresh := now.AddDate(0, 0, -1) // inside every window below

	seed := func(ts time.Time) {
		for _, iv := range []string{"5m", "1h", "1d"} {
			if err := d.db.Create(&models.FlowRollup{
				Timestamp: ts, DeviceID: 1, IntervalType: iv,
				SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", BytesSum: 1, FlowCount: 1,
			}).Error; err != nil {
				t.Fatalf("seed rollup: %v", err)
			}
		}
		if err := d.db.Create(&models.FlowDetection{
			DetectedAt: ts, Detector: "portscan", Category: "security",
			Severity: "warning", SrcAddr: "10.0.0.3",
		}).Error; err != nil {
			t.Fatalf("seed detection: %v", err)
		}
		if err := d.db.Create(&models.AgentDrops{
			AgentAddress: "10.0.0.4", SamplingRate: 512, WindowStart: ts, DropsCount: 5,
		}).Error; err != nil {
			t.Fatalf("seed agent drops: %v", err)
		}
	}
	seed(old)
	seed(fresh)

	ret := config.RetentionConfig{
		DefaultDays:       90,
		FlowRollupDays:    365,
		FlowDetectionDays: 90,
		AgentDropsDays:    30,
	}
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	assertCount := func(model interface{}, name string, want int64) {
		t.Helper()
		var n int64
		if err := d.db.Model(model).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		if n != want {
			t.Errorf("%s rows = %d, want %d (old rows must be deleted, fresh rows kept)", name, n, want)
		}
	}
	assertCount(&models.FlowRollup{}, "flow_rollups", 3)       // fresh 5m/1h/1d kept, all old deleted
	assertCount(&models.FlowDetection{}, "flow_detections", 1) // fresh kept
	assertCount(&models.AgentDrops{}, "flow_agent_drops", 1)   // fresh kept
}
