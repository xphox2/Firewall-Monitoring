package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestMigrateFlowScopeLocalBackfill exercises the v34 backfill predicate on the
// SQLite (GLOB) branch: every scope-local address form flips scope_local to
// true, every routed address stays false. The PG regex branch rides the
// integration-postgres CI lane. Matching is on canonical net.IP.String() forms.
func TestMigrateFlowScopeLocalBackfill(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	// addr -> want scope_local after backfill. Each seeded with the addr as src
	// and a routed public dst, so the flag is driven purely by the addr.
	want := map[string]bool{
		// scope-local
		"fe80::1":         true,
		"febf::5":         true,
		"ff02::fb":        true,
		"224.0.0.251":     true,
		"239.255.255.250": true,
		"169.254.1.1":     true,
		"127.0.0.1":       true,
		"255.255.255.255": true,
		"0.0.0.0":         true,
		"::1":             true,
		// routed — must stay false
		"fe8::1":   false, // 3-hex first group -> global, not link-local
		"fec0::1":  false, // deprecated site-local, not link-local
		"8.8.8.8":  false,
		"10.0.0.1": false,
	}

	var samples []models.FlowSample
	var rollups []models.FlowRollup
	for addr := range want {
		samples = append(samples, models.FlowSample{
			Timestamp: now, DeviceID: 1, Protocol: 6, SrcAddr: addr, DstAddr: "203.0.113.9",
			SrcPort: 1234, DstPort: 443, Bytes: 100, Packets: 1, ScopeLocal: false,
		})
		rollups = append(rollups, models.FlowRollup{
			Timestamp: now, DeviceID: 1, IntervalType: "5m", Protocol: 6, SrcAddr: addr, DstAddr: "203.0.113.9",
			DstPort: 443, BytesSum: 100, PacketsSum: 1, FlowCount: 1, ScopeLocal: false,
		})
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flow samples: %v", err)
	}
	if err := db.Gorm().Create(&rollups).Error; err != nil {
		t.Fatalf("seed flow rollups: %v", err)
	}

	if err := db.migrateFlowScopeLocal(); err != nil {
		t.Fatalf("migrateFlowScopeLocal: %v", err)
	}

	for addr, expect := range want {
		var s models.FlowSample
		if err := db.Gorm().Where("src_addr = ?", addr).First(&s).Error; err != nil {
			t.Fatalf("reload sample %s: %v", addr, err)
		}
		if s.ScopeLocal != expect {
			t.Errorf("flow_samples %s: scope_local = %v, want %v", addr, s.ScopeLocal, expect)
		}
		var r models.FlowRollup
		if err := db.Gorm().Where("src_addr = ?", addr).First(&r).Error; err != nil {
			t.Fatalf("reload rollup %s: %v", addr, err)
		}
		if r.ScopeLocal != expect {
			t.Errorf("flow_rollups %s: scope_local = %v, want %v", addr, r.ScopeLocal, expect)
		}
	}

	// Idempotent: a second run must not error and must not change flags.
	if err := db.migrateFlowScopeLocal(); err != nil {
		t.Fatalf("migrateFlowScopeLocal (second run): %v", err)
	}
}
