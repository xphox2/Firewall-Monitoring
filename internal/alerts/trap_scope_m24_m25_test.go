package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestProcessTrap_LinkUpScopedBySource_M24 pins the 2026-07-01 audit M24 fix: a
// LINK_UP from one source must NOT auto-resolve another source's still-open
// LINK_DOWN. Pre-fix every direct trap had DeviceID=0 + MetricName="snmp_trap",
// so one LINK_UP closed them all.
func TestProcessTrap_LinkUpScopedBySource_M24(t *testing.T) {
	am, db := newTestManager(t)

	// Two open LINK_DOWN alerts from two different source firewalls, saved the
	// way ProcessTrap now saves them (source-scoped metric_name, DeviceID=0
	// because neither IP maps to a seeded device).
	seed := func(ip string) {
		if err := db.Gorm().Create(&models.Alert{
			Timestamp: time.Now().Add(-2 * time.Minute), DeviceID: 0,
			AlertType: "LINK_DOWN", MetricName: trapMetricName(ip),
			Message: "link down", Severity: "critical",
		}).Error; err != nil {
			t.Fatalf("seed %s: %v", ip, err)
		}
	}
	seed("10.0.0.1")
	seed("10.0.0.2")

	// LINK_UP from firewall A only.
	if err := am.ProcessTrap(&models.TrapEvent{
		TrapType: "LINK_UP", SourceIP: "10.0.0.1", Message: "link up",
		Timestamp: time.Now(),
	}, nil); err != nil {
		t.Fatalf("ProcessTrap: %v", err)
	}

	// A's alert resolved; B's must remain open.
	openCount := func(ip string) int64 {
		var n int64
		db.Gorm().Model(&models.Alert{}).
			Where("metric_name = ? AND resolved_at IS NULL", trapMetricName(ip)).Count(&n)
		return n
	}
	if openCount("10.0.0.1") != 0 {
		t.Error("firewall A's LINK_DOWN should be auto-resolved by its own LINK_UP")
	}
	if openCount("10.0.0.2") != 1 {
		t.Error("firewall B's LINK_DOWN was wrongly closed by firewall A's LINK_UP (M24 cross-device resolve)")
	}
}

// TestRecordCooldownLocked_Bounded_M25 pins the hard cap on the cooldown map so
// a process that never prunes (the trap-receiver) can't grow it unbounded from
// spoofable source-IP keys.
func TestRecordCooldownLocked_Bounded_M25(t *testing.T) {
	am, _ := newTestManager(t)

	// All entries "fresh" (now) so the inline expired-prune frees nothing and
	// the oldest-eviction path must hold the cap.
	base := time.Now()
	for i := 0; i < maxLastAlertEntries+1500; i++ {
		am.mu.Lock()
		// Slightly increasing timestamps so eviction has a well-defined oldest.
		am.recordCooldownLocked(keyN(i), base.Add(time.Duration(i)*time.Millisecond))
		am.mu.Unlock()
	}

	am.mu.RLock()
	n := len(am.lastAlert)
	am.mu.RUnlock()
	if n > maxLastAlertEntries {
		t.Errorf("lastAlert grew to %d, want <= cap %d (unbounded spoof-IP growth)", n, maxLastAlertEntries)
	}
}

func keyN(i int) string {
	return "trap_LINK_DOWN_198.51." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [4]byte
	p := len(b)
	for v > 0 {
		p--
		b[p] = byte('0' + v%10)
		v /= 10
	}
	return string(b[p:])
}
