package detect

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// denyTestConfig returns small thresholds so fixtures stay tiny.
func denyTestConfig() Config {
	return Config{
		DenyStormExternal: 5, DenyStormInternal: 3,
		DenyVictimSources: 4, DenyVictimCount: 1000,
		DeniedThenAllowedMin: 2,
	}
}

func seedDeny(t *testing.T, db *database.Database, ev models.DeniedEvent) {
	t.Helper()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.Signal == 0 {
		ev.Signal = models.DenySignalAction
	}
	if err := db.Gorm().Create(&ev).Error; err != nil {
		t.Fatalf("seed denied_event: %v", err)
	}
}

func denyWindow(db *database.Database, cfg Config, now time.Time) Window {
	return Window{Start: now.Add(-15 * time.Minute), End: now.Add(time.Minute), DB: db.Gorm(), Config: cfg}
}

// TestDenyStorm_ExternalFires: a WAN source over threshold fires the external
// variant; an under-threshold source does not.
func TestDenyStorm_ExternalFires(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for i := 0; i < 6; i++ {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "203.0.113.9", DstAddr: "66.179.9.150",
			DstPort: uint16(1000 + i), Protocol: 6, SrcIntfRole: models.IntfRoleWAN, Subtype: models.DenySubtypeLocal,
			Timestamp: now.Add(-time.Duration(i) * time.Second)})
	}
	seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "203.0.113.10", DstAddr: "66.179.9.150",
		DstPort: 22, Protocol: 6, SrcIntfRole: models.IntfRoleWAN, Timestamp: now})

	got, err := denyStormDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].SrcAddr != "203.0.113.9" {
		t.Fatalf("want 1 detection for 203.0.113.9, got %+v", got)
	}
	if got[0].DedupKey != "denystorm_ext_203.0.113.9" {
		t.Errorf("dedup key = %q", got[0].DedupKey)
	}
}

// TestDenyStorm_InternalLowerFloor: a LAN source fires at the lower internal
// floor; direction split keys on src_intf_role.
func TestDenyStorm_InternalLowerFloor(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for i := 0; i < 3; i++ { // == internal floor 3, below external floor 5
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "192.168.25.50", DstAddr: "10.0.0.9",
			DstPort: uint16(3000 + i), Protocol: 6, SrcIntfRole: models.IntfRoleLAN,
			Subtype: models.DenySubtypeForward, Timestamp: now.Add(-time.Duration(i) * time.Second)})
	}
	got, err := denyStormDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DedupKey != "denystorm_int_192.168.25.50" {
		t.Fatalf("want 1 internal detection, got %+v", got)
	}
}

// TestDenyStorm_ThreatEscalates: a source on the threat feed (bit 0) escalates
// to critical.
func TestDenyStorm_ThreatEscalates(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for i := 0; i < 6; i++ {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "203.0.113.66", DstAddr: "66.179.9.150",
			DstPort: uint16(1000 + i), Protocol: 6, SrcIntfRole: models.IntfRoleWAN, ThreatFlag: 1,
			Timestamp: now.Add(-time.Duration(i) * time.Second)})
	}
	got, err := denyStormDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want critical, got %+v", got)
	}
}

// TestDenyStorm_Disabled: the kill switch suppresses all output.
func TestDenyStorm_Disabled(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for i := 0; i < 6; i++ {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "203.0.113.9", DstAddr: "66.179.9.150",
			DstPort: uint16(1000 + i), SrcIntfRole: models.IntfRoleWAN, Timestamp: now})
	}
	cfg := denyTestConfig()
	cfg.DenyStormDisabled = true
	got, err := denyStormDetector{}.Detect(denyWindow(db, cfg, now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("disabled detector produced %d detections", len(got))
	}
}

// TestDenyStormVictim_ManySources: a victim hit by >= threshold distinct
// sources fires, keyed by DstAddr with empty SrcAddr.
func TestDenyStormVictim_ManySources(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for i := 0; i < 5; i++ { // 5 distinct sources >= victim floor 4
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: fmt.Sprintf("198.51.100.%d", i+1),
			DstAddr: "66.179.9.151", DstPort: 3389, Protocol: 6, SrcIntfRole: models.IntfRoleWAN,
			Timestamp: now.Add(-time.Duration(i) * time.Second)})
	}
	got, err := denyStormVictimDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DstAddr != "66.179.9.151" || got[0].SrcAddr != "" {
		t.Fatalf("want 1 victim-keyed detection (empty SrcAddr), got %+v", got)
	}
	if got[0].DedupKey != "denyvictim_66.179.9.151" {
		t.Errorf("dedup key = %q", got[0].DedupKey)
	}
}

// TestDeniedThenAllowed_PolicyGap: a tuple denied >= min times in the lookback
// and now allowed (flow_samples) fires; sensitive port escalates to critical.
func TestDeniedThenAllowed_PolicyGap(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// 3 prior denies of 198.51.100.5 -> 10.0.0.20:3389 (RDP, sensitive), 40m ago.
	for i := 0; i < 3; i++ {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "198.51.100.5", DstAddr: "10.0.0.20",
			DstPort: 3389, Protocol: 6, SrcIntfRole: models.IntfRoleWAN,
			Timestamp: now.Add(-40 * time.Minute).Add(time.Duration(i) * time.Second)})
	}
	// Now an ALLOWED forwarded flow for the same tuple, inside the 15m window.
	if err := db.Gorm().Create(&models.FlowSample{DeviceID: 1, SrcAddr: "198.51.100.5", DstAddr: "10.0.0.20",
		DstPort: 3389, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-2 * time.Minute)}).Error; err != nil {
		t.Fatalf("seed allow: %v", err)
	}
	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 policy-gap detection, got %+v", got)
	}
	if got[0].Severity != "critical" { // 3389 is sensitive
		t.Errorf("want critical (RDP), got %q", got[0].Severity)
	}
	if got[0].DedupKey != "denyallow_198.51.100.5_10.0.0.20_3389" {
		t.Errorf("dedup key = %q", got[0].DedupKey)
	}
}

// TestDeniedThenAllowed_NoDenyHistory: an allowed tuple with fewer than min
// prior denies does not fire.
func TestDeniedThenAllowed_NoDenyHistory(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "198.51.100.6", DstAddr: "10.0.0.21",
		DstPort: 8080, Protocol: 6, Timestamp: now.Add(-30 * time.Minute)}) // only 1 deny < min 2
	if err := db.Gorm().Create(&models.FlowSample{DeviceID: 1, SrcAddr: "198.51.100.6", DstAddr: "10.0.0.21",
		DstPort: 8080, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-2 * time.Minute)}).Error; err != nil {
		t.Fatalf("seed allow: %v", err)
	}
	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 detections (deny history below min), got %+v", got)
	}
}
