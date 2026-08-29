package uptime

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// buildSeries makes a per-device SystemStatus series from raw sysUpTime
// timeticks, spacing samples `step` apart starting at `base` (oldest→newest).
func buildSeries(base time.Time, step time.Duration, deviceID uint, ticks ...uint64) []models.SystemStatus {
	rows := make([]models.SystemStatus, len(ticks))
	for i, t := range ticks {
		rows[i] = models.SystemStatus{
			DeviceID:  deviceID,
			Timestamp: base.Add(time.Duration(i) * step),
			Uptime:    t,
		}
	}
	return rows
}

// TestComputeStats_RebootDetected: a counter that drops (100000→20000) is a
// reboot — DowntimeEvents must be 1 AND accumulated downtime > 0. Guards the
// historical bug where downtime was never incremented (only the event count).
func TestComputeStats_RebootDetected(t *testing.T) {
	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	// One-hour spacing (3600s). At the reboot the device reports 20000 ticks =
	// 200s already back up, so estimated downtime = 3600 - 200 = 3400s.
	rows := buildSeries(base, time.Hour, 1, 50000, 100000, 20000, 40000)

	got := ComputeStats(rows, rows[0].Timestamp)
	if got.DowntimeEvents != 1 {
		t.Fatalf("DowntimeEvents = %d, want 1", got.DowntimeEvents)
	}
	if got.TotalDowntime <= 0 {
		t.Fatalf("TotalDowntime = %f, want > 0 (downtime accumulation bug)", got.TotalDowntime)
	}
	if got.CurrentUptime != 40000 {
		t.Fatalf("CurrentUptime = %d, want 40000", got.CurrentUptime)
	}
}

// TestComputeStats_Monotonic: a strictly increasing counter has no reboots.
func TestComputeStats_Monotonic(t *testing.T) {
	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	rows := buildSeries(base, time.Minute, 1, 100000, 200000, 300000, 400000)

	got := ComputeStats(rows, rows[0].Timestamp)
	if got.DowntimeEvents != 0 {
		t.Fatalf("DowntimeEvents = %d, want 0 for a monotonic series", got.DowntimeEvents)
	}
	if got.TotalDowntime != 0 {
		t.Fatalf("TotalDowntime = %f, want 0 for a monotonic series", got.TotalDowntime)
	}
}

// TestComputeStats_PerDeviceIsolation: ComputeStats is called per device, so a
// reboot in device A's series must NOT show up in device B's independently
// computed stats. Proves there is no shared/global state across calls.
func TestComputeStats_PerDeviceIsolation(t *testing.T) {
	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	devA := buildSeries(base, time.Hour, 1, 500000, 900000, 10000, 50000) // reboots
	devB := buildSeries(base, time.Hour, 2, 100000, 200000, 300000)       // monotonic

	a := ComputeStats(devA, devA[0].Timestamp)
	b := ComputeStats(devB, devB[0].Timestamp)

	if a.DowntimeEvents != 1 {
		t.Fatalf("device A DowntimeEvents = %d, want 1", a.DowntimeEvents)
	}
	if b.DowntimeEvents != 0 {
		t.Fatalf("device B DowntimeEvents = %d, want 0 (device A's reboot leaked)", b.DowntimeEvents)
	}
}

// TestComputeStats_MovesOffZeroState: on real increasing samples the result is
// no longer frozen at the zero-state — UptimePercent > 0 and CurrentUptime != 0.
func TestComputeStats_MovesOffZeroState(t *testing.T) {
	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	rows := buildSeries(base, 5*time.Minute, 1, 8640000, 8670000, 8700000, 8730000)

	got := ComputeStats(rows, rows[0].Timestamp)
	if got.UptimePercent <= 0 {
		t.Fatalf("UptimePercent = %f, want > 0 (no longer frozen zero-state)", got.UptimePercent)
	}
	if got.CurrentUptime == 0 {
		t.Fatalf("CurrentUptime = 0, want the last sample's uptime")
	}
}

// TestCalculateFiveNines_NotConstant: the five-nines budget must MOVE as
// downtime accumulates — it is not the old constant "315.58 seconds remaining".
func TestCalculateFiveNines_NotConstant(t *testing.T) {
	// Both below the 99.999% threshold so neither short-circuits to "Achieved".
	noDowntime := CalculateFiveNines(UptimeStats{UptimePercent: 99.0, TotalDowntime: 0})
	withDowntime := CalculateFiveNines(UptimeStats{UptimePercent: 99.0, TotalDowntime: 100})

	if noDowntime == withDowntime {
		t.Fatalf("five-nines is constant across downtime: %q == %q", noDowntime, withDowntime)
	}
}

// TestNewRecord_DeviceIDSet: a persisted record must carry a non-zero DeviceID.
// Guards the GetUptimeRecord DeviceID=0 defect where every row collided on
// device 0.
func TestNewRecord_DeviceIDSet(t *testing.T) {
	rec := NewRecord(7, UptimeStats{CurrentUptime: 12345, UptimePercent: 99.5, TotalDowntime: 3, DowntimeEvents: 1})
	if rec.DeviceID != 7 {
		t.Fatalf("DeviceID = %d, want 7", rec.DeviceID)
	}
	if rec.DeviceUptime != 12345 || rec.UptimePercent != 99.5 || rec.DowntimeEvents != 1 {
		t.Fatalf("record fields not carried through: %+v", rec)
	}
}
