package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// seedTrafficConn creates a two-device ipsec connection whose tunnel set is
// matched via the TunnelNames field (same pattern as the single-endpoint dedup
// test).
func seedTrafficConn(t *testing.T, d *Database, tunnelNames string) models.DeviceConnection {
	t.Helper()
	if err := d.db.Create(&models.Device{ID: 1, Name: "HUB-FW1"}).Error; err != nil {
		t.Fatalf("dev1: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "SPOKE-FW1"}).Error; err != nil {
		t.Fatalf("dev2: %v", err)
	}
	conn := models.DeviceConnection{
		Name: "HUB-FW1 <-> SPOKE-FW1", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "ipsec", Status: "up", TunnelNames: tunnelNames,
		MatchMethod: "name_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("conn: %v", err)
	}
	return conn
}

func sumTraffic(t *testing.T, d *Database, connID uint, hours float64) (in, out float64) {
	t.Helper()
	rows, err := d.GetConnectionTraffic(connID, hours)
	if err != nil {
		t.Fatalf("GetConnectionTraffic: %v", err)
	}
	for _, r := range rows {
		in += r.InBytes
		out += r.OutBytes
	}
	return in, out
}

// TestGetConnectionTraffic_ZeroRowsExcluded pins the fix for the "climbing
// chart" prod incident: the collector's SSH phase1/phase2 poll writes
// status-only vpn_status rows (bytes_in=0, bytes_out=0, status=unknown) into
// the same table as the per-minute SNMP counter rows. Inside the LAG()
// partition each zero row read as a counter reset, and the next real sample
// then contributed the tunnel's FULL cumulative counter as one "delta" — on
// prod that injected ~181 GB per SSH poll into hourly buckets and made the
// series climb as the lifetime counter grew. Both-zero rows must be excluded
// from the delta window.
func TestGetConnectionTraffic_ZeroRowsExcluded(t *testing.T) {
	d := NewDatabaseForTesting(t)
	conn := seedTrafficConn(t, d, "tun1")

	base := time.Now().Add(-40 * time.Minute)
	// SNMP counter rows: deltas 1000+1000+1000 = 3000 in / half that out.
	counters := []uint64{10000, 11000, 12000, 13000}
	for i, b := range counters {
		if err := d.db.Create(&models.VPNStatus{
			DeviceID: 1, TunnelName: "tun1", TunnelType: "ipsec", Status: "up",
			BytesIn: b, BytesOut: b / 2, PacketsIn: b / 100, PacketsOut: b / 100,
			Timestamp: base.Add(time.Duration(i) * 5 * time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed counter row: %v", err)
		}
	}
	// SSH status rows interleaved between every SNMP sample. Pre-fix, each one
	// made the following counter row contribute its FULL value (12000/13000…)
	// instead of the 1000-byte delta.
	for i := 0; i < 3; i++ {
		if err := d.db.Create(&models.VPNStatus{
			DeviceID: 1, TunnelName: "tun1", TunnelType: "ipsec", Status: "unknown",
			BytesIn: 0, BytesOut: 0,
			Timestamp: base.Add(time.Duration(i)*5*time.Minute + 2*time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed zero row: %v", err)
		}
	}

	in, out := sumTraffic(t, d, conn.ID, 24)
	if !floatsClose(in, 3000) {
		t.Errorf("in_bytes = %v, want 3000 (zero rows must not inject cumulative counters)", in)
	}
	if !floatsClose(out, 1500) {
		t.Errorf("out_bytes = %v, want 1500", out)
	}
}

// TestGetVPNChartWindow_ZeroRowsExcluded pins the same zero-row exclusion in
// vpnDeltaQuery, which backs the device/connection tunnel charts.
func TestGetVPNChartWindow_ZeroRowsExcluded(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-40 * time.Minute)
	for i, b := range []uint64{10000, 11000, 12000, 13000} {
		if err := d.db.Create(&models.VPNStatus{
			DeviceID: 1, TunnelName: "tun1", Status: "up",
			BytesIn: b, BytesOut: b / 2,
			Timestamp: base.Add(time.Duration(i) * 5 * time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed counter row: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := d.db.Create(&models.VPNStatus{
			DeviceID: 1, TunnelName: "tun1", Status: "unknown",
			BytesIn: 0, BytesOut: 0,
			Timestamp: base.Add(time.Duration(i)*5*time.Minute + 2*time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed zero row: %v", err)
		}
	}
	rows, err := d.GetVPNChartWindow(1, "tun1", time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("GetVPNChartWindow: %v", err)
	}
	var in float64
	for _, r := range rows {
		in += r.InBytes
	}
	if !floatsClose(in, 3000) {
		t.Errorf("in_bytes = %v, want 3000 (zero rows must not inject cumulative counters)", in)
	}
}

// TestGetConnectionTraffic_DuplicateCounterStreamsCollapse pins the 4x
// inflation fix: FortiGate can surface ONE underlying counter under several
// tunnel names (observed live: DMZ/HUB/NUDAY_LAN/TL-IKEv2 to the same gateway,
// byte-identical at every sample). Byte-identical rows at the same timestamp
// must collapse to one partition; tunnels with genuinely distinct counters
// must keep their own partitions and still sum.
func TestGetConnectionTraffic_DuplicateCounterStreamsCollapse(t *testing.T) {
	d := NewDatabaseForTesting(t)
	conn := seedTrafficConn(t, d, "t1,t2,t3,t4,solo")

	base := time.Now().Add(-40 * time.Minute)
	seed := func(tunnel string, samples []uint64) {
		for i, b := range samples {
			if err := d.db.Create(&models.VPNStatus{
				DeviceID: 1, TunnelName: tunnel, TunnelType: "ipsec", Status: "up",
				BytesIn: b, BytesOut: b / 2, PacketsIn: b / 100, PacketsOut: b / 100,
				Timestamp: base.Add(time.Duration(i) * 5 * time.Minute),
			}).Error; err != nil {
				t.Fatalf("seed %s: %v", tunnel, err)
			}
		}
	}
	// Four byte-identical streams — one real counter reported under 4 names.
	// True deltas: 100+100+100 = 300; pre-fix SUM across partitions = 1200.
	for _, name := range []string{"t1", "t2", "t3", "t4"} {
		seed(name, []uint64{100, 200, 300, 400})
	}
	// A genuinely distinct stream at the same timestamps must still add its own
	// deltas: 50+50+50 = 150.
	seed("solo", []uint64{1000, 1050, 1100, 1150})

	in, _ := sumTraffic(t, d, conn.ID, 24)
	if !floatsClose(in, 450) {
		t.Errorf("in_bytes = %v, want 450 (300 collapsed duplicates + 150 distinct)", in)
	}
}

// TestTrafficWindow_HoursAndClamp pins the hours→window mapping the range
// selector now feeds end-to-end: numeric hours choose the adaptive bucket unit
// and a non-positive or oversized lookback clamps to maxChartWindow.
func TestTrafficWindow_HoursAndClamp(t *testing.T) {
	cases := []struct {
		hours float64
		dur   time.Duration
		unit  string
	}{
		{0.25, 15 * time.Minute, "minute"},
		{1, time.Hour, "minute"},
		{24, 24 * time.Hour, "5min"},
		{168, 168 * time.Hour, "hour"},
		{720, 720 * time.Hour, "6hour"},
		{8760, 8760 * time.Hour, "day"}, // 1y — inside the 400d cap
		{20000, maxChartWindow, "day"},  // beyond the cap → clamped
		{0, maxChartWindow, "day"},
		{-5, maxChartWindow, "day"},
	}
	for _, c := range cases {
		dur, unit := trafficWindow(c.hours)
		if dur != c.dur || unit != c.unit {
			t.Errorf("trafficWindow(%v) = (%v, %q), want (%v, %q)", c.hours, dur, unit, c.dur, c.unit)
		}
	}
}
