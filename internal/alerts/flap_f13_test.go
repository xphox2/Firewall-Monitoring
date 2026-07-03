package alerts

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The flap detector counts short-lived fire→resolve cycles ACROSS cooldown
// windows (in prod: fire, resolve in <2min, refire after the 5-min cooldown —
// five of those inside an hour = flapping). Tests can't fast-forward
// time.Now(), so they seed the recorded short-resolve history directly and
// assert the two halves: recording (sendRecovery) and suppression
// (dispatchFired).

// latestCPUFire returns the newest non-recovery CPU alert row.
func latestCPUFire(t *testing.T, am *AlertManager, dev uint) models.Alert {
	t.Helper()
	var a models.Alert
	if err := am.db.Gorm().
		Where("device_id = ? AND alert_type = ? AND metric_name <> ?", dev, models.AlertTypeCPUHigh, "recovery").
		Order("id DESC").First(&a).Error; err != nil {
		t.Fatalf("latest fire: %v", err)
	}
	return a
}

func seedShortResolves(am *AlertManager, key string, n int, age time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	ts := make([]time.Time, n)
	for i := range ts {
		ts[i] = time.Now().Add(-age)
	}
	am.flapShortResolves[key] = ts
}

// TestFlapSuppression_F13: with the short-cycle budget already consumed inside
// the window, the next fire is saved suppressed with the [FLAPPING] tag.
func TestFlapSuppression_F13(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	am.config.Alerts.FlapMaxFires = 3
	am.config.Alerts.FlapWindowMinutes = 60
	am.config.Alerts.FlapMinActiveSeconds = 120
	const dev = 77
	seedShortResolves(am, "cpu_high_77", 3, time.Minute)

	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	got := latestCPUFire(t, am, dev)
	if !got.Suppressed {
		t.Errorf("flapping fire not suppressed: %+v", got)
	}
	if !strings.HasPrefix(got.Message, "[FLAPPING] ") {
		t.Errorf("flapping fire missing tag: %q", got.Message)
	}
}

// TestFlapRecording_ShortCycleCounts: one real fire→instant-recover cycle
// records exactly one short resolve and clears the fire-start stamp; the
// recovery notification for a flapping key is muted (companion row still
// saved).
func TestFlapRecording_ShortCycleCounts(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	am.config.Alerts.FlapMaxFires = 5
	am.config.Alerts.FlapWindowMinutes = 60
	am.config.Alerts.FlapMinActiveSeconds = 120
	const dev = 78

	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	if err := am.CheckSystemStatus(cpuStatus(dev, 50), nil); err != nil {
		t.Fatalf("recover: %v", err)
	}

	am.mu.RLock()
	shorts := len(am.flapShortResolves["cpu_high_78"])
	_, stampLeft := am.fireStart["cpu_high_78"]
	am.mu.RUnlock()
	if shorts != 1 {
		t.Errorf("short-resolve count = %d, want 1", shorts)
	}
	if stampLeft {
		t.Error("fireStart stamp must be cleared on recovery")
	}
}

// TestFlapSuppression_Disabled: FlapMaxFires=0 turns the detector off even
// with seeded history.
func TestFlapSuppression_Disabled(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	am.config.Alerts.FlapMaxFires = 0
	const dev = 79
	seedShortResolves(am, "cpu_high_79", 10, time.Minute)

	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	got := latestCPUFire(t, am, dev)
	if got.Suppressed || strings.HasPrefix(got.Message, "[FLAPPING]") {
		t.Errorf("flap suppression fired while disabled: %+v", got)
	}
}

// TestFlapSuppression_StaleHistoryIgnored: short cycles OUTSIDE the window
// don't suppress — slow flapping is legitimate alerting.
func TestFlapSuppression_StaleHistoryIgnored(t *testing.T) {
	am, _ := newTestManager(t)
	setHysteresisPolicy(am, 90, 0)
	am.config.Alerts.FlapMaxFires = 3
	am.config.Alerts.FlapWindowMinutes = 60
	const dev = 80
	seedShortResolves(am, "cpu_high_80", 5, 2*time.Hour) // all outside 60min

	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("fire: %v", err)
	}
	got := latestCPUFire(t, am, dev)
	if got.Suppressed {
		t.Errorf("stale flap history suppressed a legitimate alert: %+v", got)
	}
	am.mu.RLock()
	left := len(am.flapShortResolves["cpu_high_80"])
	am.mu.RUnlock()
	if left != 0 {
		t.Errorf("stale entries not pruned: %d left", left)
	}
}
