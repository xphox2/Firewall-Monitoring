package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// seedRateRows seeds n rows for (device, source, rate) at the given time.
func seedRateRows(t *testing.T, db *database.Database, device uint, source uint8, rate uint32, n int, at time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		seedFlow(t, db, models.FlowSample{
			DeviceID: device, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: fmt.Sprintf("10.0.1.%d", i%200+1), DstPort: 443,
			Bytes: 100, Packets: 1,
			FlowSource: source, SamplingRate: rate,
			Timestamp: at,
		})
	}
}

func sampRateWindow(now time.Time, db *database.Database) Window {
	w := Window{Start: now.Add(-15 * time.Minute), End: now}
	w.DB = db.Gorm()
	return w
}

// TestSamplingRateChange_Matrix covers stable / addition / removal-only /
// new-device / stray-row scenarios plus the NetFlow rate>1 escalation.
func TestSamplingRateChange_Matrix(t *testing.T) {
	t.Run("stable-set-silent", func(t *testing.T) {
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-20*time.Minute)) // prev window
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-5*time.Minute))  // cur window
		got, err := samplingRateChangeDetector{}.Detect(sampRateWindow(now, db))
		if err != nil || len(got) != 0 {
			t.Fatalf("stable set fired: %v / %d", err, len(got))
		}
	})

	t.Run("rate-addition-fires", func(t *testing.T) {
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-20*time.Minute))
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-5*time.Minute))
		seedRateRows(t, db, 1, 0, 512, 5, now.Add(-5*time.Minute)) // new rate
		got, err := samplingRateChangeDetector{}.Detect(sampRateWindow(now, db))
		if err != nil || len(got) != 1 {
			t.Fatalf("addition did not fire: %v / %d", err, len(got))
		}
		if got[0].DedupKey != "samprate_1_0" {
			t.Errorf("dedup = %s", got[0].DedupKey)
		}
		if !strings.Contains(got[0].Message, "512") {
			t.Errorf("message missing new rate: %s", got[0].Message)
		}
	})

	t.Run("rate-removal-silent", func(t *testing.T) {
		// A low-volume rate flickering OUT of the set must not page.
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-20*time.Minute))
		seedRateRows(t, db, 1, 0, 512, 5, now.Add(-20*time.Minute))
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-5*time.Minute)) // 512 gone
		got, err := samplingRateChangeDetector{}.Detect(sampRateWindow(now, db))
		if err != nil || len(got) != 0 {
			t.Fatalf("removal fired: %v / %d", err, len(got))
		}
	})

	t.Run("new-device-silent", func(t *testing.T) {
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 9, 2, 1, 5, now.Add(-5*time.Minute)) // cur only
		got, err := samplingRateChangeDetector{}.Detect(sampRateWindow(now, db))
		if err != nil || len(got) != 0 {
			t.Fatalf("first appearance fired: %v / %d", err, len(got))
		}
	})

	t.Run("stray-row-filtered", func(t *testing.T) {
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-20*time.Minute))
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-5*time.Minute))
		seedRateRows(t, db, 1, 0, 999, 2, now.Add(-5*time.Minute)) // < MinRows(3)
		got, err := samplingRateChangeDetector{}.Detect(sampRateWindow(now, db))
		if err != nil || len(got) != 0 {
			t.Fatalf("stray rows registered a rate: %v / %d", err, len(got))
		}
	})

	t.Run("netflow-sampling-escalation", func(t *testing.T) {
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 1, 2, 1, 5, now.Add(-20*time.Minute))
		seedRateRows(t, db, 1, 2, 1, 5, now.Add(-5*time.Minute))
		seedRateRows(t, db, 1, 2, 2000, 5, now.Add(-5*time.Minute)) // FortiGate 7.6 sampled NetFlow
		got, err := samplingRateChangeDetector{}.Detect(sampRateWindow(now, db))
		if err != nil || len(got) != 1 {
			t.Fatalf("escalation case did not fire: %v / %d", err, len(got))
		}
		if !strings.Contains(got[0].Message, "disables flow-count-based detectors") {
			t.Errorf("escalation text missing: %s", got[0].Message)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		db := database.NewDatabaseForTesting(t)
		now := time.Now()
		seedRateRows(t, db, 1, 0, 2000, 5, now.Add(-20*time.Minute))
		seedRateRows(t, db, 1, 0, 512, 5, now.Add(-5*time.Minute))
		w := sampRateWindow(now, db)
		w.Config.SamplingRateChangeDisabled = true
		got, err := samplingRateChangeDetector{}.Detect(w)
		if err != nil || len(got) != 0 {
			t.Fatalf("disabled detector fired: %v / %d", err, len(got))
		}
	})
}

// TestValidityGuardrails pins the T4-1 framework invariants: every Registry()
// detector declares a validity class, and RunAll stamps it into Details.
func TestValidityGuardrails(t *testing.T) {
	for _, det := range Registry() {
		if _, ok := detectorValidity[det.Name()]; !ok {
			t.Errorf("detector %q has no detectorValidity entry — declare its evidence class (T4-1)", det.Name())
		}
	}
}

// TestVictimKeyedGuardrail: victim-keyed detectors must be CategorySecurity
// (the routing split only inspects security detections), and every declared
// name must exist in the Registry.
func TestVictimKeyedGuardrail(t *testing.T) {
	byName := map[string]Detector{}
	for _, det := range Registry() {
		byName[det.Name()] = det
	}
	for name := range victimKeyed {
		det, ok := byName[name]
		if !ok {
			t.Errorf("VictimKeyed entry %q is not a registered detector", name)
			continue
		}
		if det.Category() != CategorySecurity {
			t.Errorf("VictimKeyed detector %q is %s — the poller split only routes security detections", name, det.Category())
		}
	}
}

// TestWindowLookbackClamp: Lookback never reads past the raw-retention floor.
func TestWindowLookbackClamp(t *testing.T) {
	now := time.Now()
	w := Window{End: now}
	if got := w.Lookback(45 * time.Minute); !got.Equal(now.Add(-45 * time.Minute)) {
		t.Errorf("45m lookback = %v", got)
	}
	if got := w.Lookback(4 * time.Hour); !got.Equal(now.Add(-60 * time.Minute)) {
		t.Errorf("4h lookback not clamped to 60m: %v", got)
	}
}

// TestRunAll_StampsValidity: persisted detections carry the declared class.
func TestRunAll_StampsValidity(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// Trigger the ddos_volumetric detector (rate_gated) with a small burst.
	seedBurst(t, db, "192.0.2.99", 150, 60, 60, models.FlowSourceNetFlowV9, 1, now.Add(-3*time.Minute))
	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = ddosTestConfig()

	out := RunAll(w, now)
	found := false
	for _, m := range out {
		if m.Detector == "ddos_volumetric" {
			found = true
			if !strings.Contains(m.Details, `"validity":"rate_gated"`) {
				t.Errorf("validity not stamped: %s", m.Details)
			}
		}
	}
	if !found {
		t.Fatal("expected a ddos_volumetric detection from RunAll")
	}
}
