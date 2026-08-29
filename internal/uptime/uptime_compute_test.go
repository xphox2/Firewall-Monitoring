package uptime

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// row builds one SystemStatus sample at an absolute Unix second with a given
// sysUpTime in timeticks (hundredths of a second).
func row(unixSec int64, uptimeTicks uint64) models.SystemStatus {
	return models.SystemStatus{
		Timestamp: time.Unix(unixSec, 0).UTC(),
		Uptime:    uptimeTicks,
	}
}

// TestComputeStats_RebootDetected: a genuine reboot — the claimed boot instant
// jumps to recent while the device reports a small uptime after an 8-minute
// observation gap — is exactly one event with an EXACT downtime value.
//
// s1 last confirms the device up at T+60. s2 (T+600) reports 30s of uptime, so
// its claimed boot is T+570, which is 510s after T+60 → 1 reboot, downtime 510s.
func TestComputeStats_RebootDetected(t *testing.T) {
	const T = 1_700_000_000
	rows := []models.SystemStatus{
		row(T, 1_000_000),    // up 10000s, boot ≈ T-10000
		row(T+60, 1_006_000), // up 10060s, boot ≈ T-10000 (monotonic)
		row(T+600, 3_000),    // up 30s → boot T+570  → REBOOT (510s down)
		row(T+660, 9_000),    // up 90s → boot T+570  (same boot, no new event)
	}

	got := ComputeStats(rows, rows[0].Timestamp)
	if got.DowntimeEvents != 1 {
		t.Fatalf("DowntimeEvents = %d, want 1", got.DowntimeEvents)
	}
	if got.TotalDowntime != 510 {
		t.Fatalf("TotalDowntime = %v, want exactly 510", got.TotalDowntime)
	}
	if got.CurrentUptime != 9_000 {
		t.Fatalf("CurrentUptime = %d, want 9000", got.CurrentUptime)
	}
}

// TestComputeStats_Monotonic: a device whose uptime advances in step with the
// wall clock (constant claimed boot) has no reboots and no downtime.
func TestComputeStats_Monotonic(t *testing.T) {
	const T = 1_700_000_000
	// 60s apart, +6000 ticks (60s) each → claimed boot constant.
	rows := []models.SystemStatus{
		row(T, 1_000_000),
		row(T+60, 1_006_000),
		row(T+120, 1_012_000),
		row(T+180, 1_018_000),
	}
	got := ComputeStats(rows, rows[0].Timestamp)
	if got.DowntimeEvents != 0 {
		t.Fatalf("DowntimeEvents = %d, want 0", got.DowntimeEvents)
	}
	if got.TotalDowntime != 0 {
		t.Fatalf("TotalDowntime = %v, want 0", got.TotalDowntime)
	}
	if got.UptimePercent <= 0 {
		t.Fatalf("UptimePercent = %v, want > 0 (not frozen zero-state)", got.UptimePercent)
	}
}

// TestComputeStats_TruncatedInterleave_NoFalseReboots: the DUAL-WRITER case.
// SSH-perf rows carry minute-truncated uptime interleaved with exact SNMP rows,
// which produces raw counter DROPS on the SSH rows (a truncated value lands
// below the SNMP reading moments earlier). The OLD raw-value-drop detector
// counted each drop as a reboot (~48/day in prod); the claimed-boot detector
// sees the boot instant only jitter within slack and counts ZERO.
func TestComputeStats_TruncatedInterleave_NoFalseReboots(t *testing.T) {
	const B = 1_700_000_000 // device boot instant (Unix sec)
	// Interleave, ordered by timestamp. SNMP = exact; SSH = floor-to-minute.
	// At B+100000 the device has been up 100000s.
	rows := []models.SystemStatus{
		row(B+100000, 10_000_000), // SNMP: up 100000s exact → boot B
		row(B+100010, 9_996_000),  // SSH:  floor(100010/60)*60=99960s → boot B+50 (raw DROP vs prev)
		row(B+100060, 10_006_000), // SNMP: up 100060s exact → boot B
		row(B+100070, 10_002_000), // SSH:  floor(100070/60)*60=100020s → boot B+50 (raw DROP vs prev)
	}
	got := ComputeStats(rows, rows[0].Timestamp)
	if got.DowntimeEvents != 0 {
		t.Fatalf("DowntimeEvents = %d, want 0 — truncation jitter must NOT read as reboots", got.DowntimeEvents)
	}
	if got.TotalDowntime != 0 {
		t.Fatalf("TotalDowntime = %v, want 0", got.TotalDowntime)
	}
}

// TestComputeStats_ZeroUptimeRowNotDowntime: an Uptime==0 row (a failed poll
// during a long gap) must be SKIPPED, not treated as a reboot-to-zero. Without
// the skip, that zero row's claimed boot equals its own timestamp — far in the
// future of the previous good sample — and invents a large false outage.
func TestComputeStats_ZeroUptimeRowNotDowntime(t *testing.T) {
	const B = 1_700_000_000
	// Device booted at B-100000 and stays up throughout; one unreadable poll
	// sits in a ~2.8h gap.
	rows := []models.SystemStatus{
		row(B, 10_000_000),       // up 100000s → boot B-100000
		row(B+10000, 0),          // UNREADABLE — must be skipped
		row(B+10060, 11_006_000), // up 110060s → boot B-100000 (same boot)
	}
	got := ComputeStats(rows, rows[0].Timestamp)
	if got.DowntimeEvents != 0 {
		t.Fatalf("DowntimeEvents = %d, want 0 — a zero-uptime row must not invent downtime", got.DowntimeEvents)
	}
	if got.TotalDowntime != 0 {
		t.Fatalf("TotalDowntime = %v, want 0", got.TotalDowntime)
	}
	if got.SampleCount != 2 {
		t.Fatalf("SampleCount = %d, want 2 (zero row excluded)", got.SampleCount)
	}
	if got.UptimePercent != 100 {
		t.Fatalf("UptimePercent = %v, want 100 (device never went down)", got.UptimePercent)
	}
}

// TestComputeStats_AllZeros_NoData: an all-unreadable series is NO SIGNAL, and
// must report a no-data zero-state (SampleCount 0, UptimePercent 0) — never a
// false 100% synthesized from the absence of any observed downtime.
func TestComputeStats_AllZeros_NoData(t *testing.T) {
	const B = 1_700_000_000
	rows := []models.SystemStatus{row(B, 0), row(B+60, 0), row(B+120, 0)}
	got := ComputeStats(rows, rows[0].Timestamp)
	if got.SampleCount != 0 {
		t.Fatalf("SampleCount = %d, want 0", got.SampleCount)
	}
	if got.UptimePercent == 100 {
		t.Fatalf("UptimePercent = 100 from no signal — must be a no-data state, not 100%%")
	}
	if got.CurrentUptime != 0 {
		t.Fatalf("CurrentUptime = %d, want 0", got.CurrentUptime)
	}
}

// TestComputeStats_PerDeviceIsolation: computed per device, a reboot in one
// series never leaks into another independently computed series.
func TestComputeStats_PerDeviceIsolation(t *testing.T) {
	const T = 1_700_000_000
	rebooter := []models.SystemStatus{
		row(T, 1_000_000),
		row(T+60, 1_006_000),
		row(T+600, 3_000), // reboot
		row(T+660, 9_000),
	}
	steady := []models.SystemStatus{
		row(T, 1_000_000),
		row(T+60, 1_006_000),
		row(T+120, 1_012_000),
	}
	a := ComputeStats(rebooter, rebooter[0].Timestamp)
	b := ComputeStats(steady, steady[0].Timestamp)
	if a.DowntimeEvents != 1 {
		t.Fatalf("rebooter DowntimeEvents = %d, want 1", a.DowntimeEvents)
	}
	if b.DowntimeEvents != 0 {
		t.Fatalf("steady DowntimeEvents = %d, want 0 (leak)", b.DowntimeEvents)
	}
}

// TestCalculateFiveNines_NotConstant: the five-nines budget MOVES with
// accumulated downtime and is scaled to the OBSERVED window (not a mislabeled
// annual constant), and reports insufficient data when there is no window.
func TestCalculateFiveNines_NotConstant(t *testing.T) {
	// One year observed → budget ≈ 315.36s; both below 99.999% so neither
	// short-circuits to "Achieved".
	const yearSecs = 31_536_000
	noDowntime := CalculateFiveNines(UptimeStats{SampleCount: 5, ObservedSeconds: yearSecs, UptimePercent: 99.0, TotalDowntime: 0})
	withDowntime := CalculateFiveNines(UptimeStats{SampleCount: 5, ObservedSeconds: yearSecs, UptimePercent: 99.0, TotalDowntime: 100})
	if noDowntime == withDowntime {
		t.Fatalf("five-nines constant across downtime: %q == %q", noDowntime, withDowntime)
	}
	if got := CalculateFiveNines(UptimeStats{}); got != "Insufficient data" {
		t.Fatalf("no-window five-nines = %q, want %q", got, "Insufficient data")
	}
	// The budget must SCALE to the observed window, not be a fixed annual
	// constant: same (zero) downtime over two different windows → different
	// remaining budgets. Fails if the budget is hardcoded to the annual figure.
	shortWin := CalculateFiveNines(UptimeStats{SampleCount: 5, ObservedSeconds: 1_000_000, UptimePercent: 99.0, TotalDowntime: 0})
	longWin := CalculateFiveNines(UptimeStats{SampleCount: 5, ObservedSeconds: 100_000_000, UptimePercent: 99.0, TotalDowntime: 0})
	if shortWin == longWin {
		t.Fatalf("five-nines budget does not scale with the observed window: %q == %q", shortWin, longWin)
	}
}

// TestNewRecord_DeviceIDSet: a persisted record must carry a non-zero DeviceID.
func TestNewRecord_DeviceIDSet(t *testing.T) {
	rec := NewRecord(7, UptimeStats{CurrentUptime: 12345, UptimePercent: 99.5, TotalDowntime: 3, DowntimeEvents: 1})
	if rec.DeviceID != 7 {
		t.Fatalf("DeviceID = %d, want 7", rec.DeviceID)
	}
	if rec.DeviceUptime != 12345 || rec.UptimePercent != 99.5 || rec.DowntimeEvents != 1 {
		t.Fatalf("record fields not carried through: %+v", rec)
	}
}
