package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetVPNChartData_WindowDeltas_AUDIT043 closes the AUDIT-043 gap: the
// LAG()/`WINDOW w AS (...)` delta queries (GetVPNChartData and the identical
// pattern in GetConnectionTraffic) were untested on the SQLite test backend.
// The audit assumed SQLite couldn't run them — but the modern (modernc) SQLite
// backend supports window functions, so no dialect gating is needed; the fix is
// the missing coverage. This verifies the delta math runs on SQLite and that
// cumulative SNMP counters are turned into per-sample deltas, including the
// counter-reset clamp (a drop in the cumulative value uses the raw value).
func TestGetVPNChartData_WindowDeltas_AUDIT043(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-3 * time.Minute)

	seed := func(tunnel string, bytesIn []uint64) {
		for i, b := range bytesIn {
			if err := d.db.Create(&models.VPNStatus{
				DeviceID: 1, TunnelName: tunnel,
				BytesIn: b, BytesOut: b / 2, PacketsIn: b / 100, PacketsOut: b / 100,
				Timestamp: base.Add(time.Duration(i) * time.Second),
			}).Error; err != nil {
				t.Fatalf("seed %s: %v", tunnel, err)
			}
		}
	}
	// Monotonic counter: deltas 250-100... first sample's delta is NULL (dropped).
	// 100 -> 200 -> 350: deltas 100 + 150 = 250.
	seed("inc", []uint64{100, 200, 350})
	// Counter reset: 100 -> 200 -> 50. Row2 delta = 100; row3 50 < 200 => raw 50. Sum 150.
	seed("reset", []uint64{100, 200, 50})

	sumIn := func(tunnel string) float64 {
		rows, err := d.GetVPNChartData(1, tunnel, "24h")
		if err != nil {
			t.Fatalf("GetVPNChartData(%s) errored on SQLite (window clause?): %v", tunnel, err)
		}
		var total float64
		for _, r := range rows {
			total += r.InBytes
		}
		return total
	}

	if got := sumIn("inc"); got != 250 {
		t.Errorf("monotonic deltas: sum in_bytes = %v, want 250 (100 + 150; first sample dropped)", got)
	}
	if got := sumIn("reset"); got != 150 {
		t.Errorf("counter-reset clamp: sum in_bytes = %v, want 150 (delta 100 + raw 50 on reset)", got)
	}
}
