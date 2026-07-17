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

// TestDeniedThenAllowed_ConcurrentDenies_NoFire pins the v0.11.107 prod
// false-positive flood: FortiOS exports NetFlow records for DENIED traffic
// with firewall_event=0, so verdict-less flow rows co-occur with the syslog
// denies for the same scanner tuple. With denies still arriving inside the
// quiet margin, no amount of verdict-less flow rows may fire the detector.
// (This scenario produced "blocked 193x, now ALLOWED" CRITICALs pre-fix.)
func TestDeniedThenAllowed_ConcurrentDenies_NoFire(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// Denies spanning the lookback, the newest 1m ago (well inside the margin).
	for _, ago := range []time.Duration{50 * time.Minute, 30 * time.Minute, 10 * time.Minute, time.Minute} {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "80.251.153.178", DstAddr: "66.179.9.152",
			DstPort: 23, Protocol: 6, SrcIntfRole: models.IntfRoleWAN, Timestamp: now.Add(-ago)})
	}
	// The same denied traffic seen through the flow pipe: verdict-less rows
	// throughout the window, newest also ~now.
	for _, ago := range []time.Duration{12 * time.Minute, 6 * time.Minute, 30 * time.Second} {
		seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: "80.251.153.178", DstAddr: "66.179.9.152",
			DstPort: 23, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-ago)})
	}
	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 detections (denies still active, flows verdict-less), got %+v", got)
	}
}

// TestDeniedThenAllowed_PositiveVerdict_FiresDespiteActiveDenies: an exporter
// that explicitly reports a session lifecycle event (IE 233 Created/Deleted/
// Update) is real allow-evidence and fires immediately, even while denies for
// the tuple are still arriving on another path.
func TestDeniedThenAllowed_PositiveVerdict_FiresDespiteActiveDenies(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for _, ago := range []time.Duration{20 * time.Minute, time.Minute} {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "198.51.100.7", DstAddr: "10.0.0.30",
			DstPort: 3389, Protocol: 6, SrcIntfRole: models.IntfRoleWAN, Timestamp: now.Add(-ago)})
	}
	seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: "198.51.100.7", DstAddr: "10.0.0.30",
		DstPort: 3389, Protocol: 6, FirewallEvent: models.FirewallEventDeleted, Timestamp: now.Add(-30 * time.Second)})
	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 detection (positive verdict overrides quiet margin), got %+v", got)
	}
	if got[0].Severity != "critical" { // 3389 is sensitive
		t.Errorf("want critical (RDP), got %q", got[0].Severity)
	}
}

// TestDeniedThenAllowed_QuietMarginBoundary: verdict-less flow evidence counts
// only once the tuple's denies have been quiet for denyAllowQuietMargin.
func TestDeniedThenAllowed_QuietMarginBoundary(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	seed := func(src string, denyAgo time.Duration) {
		for i := 0; i < 2; i++ { // min 2 denies
			seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: src, DstAddr: "10.0.0.40",
				DstPort: 445, Protocol: 6, SrcIntfRole: models.IntfRoleWAN,
				Timestamp: now.Add(-denyAgo).Add(-time.Duration(i) * time.Second)})
		}
		seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: src, DstAddr: "10.0.0.40",
			DstPort: 445, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-time.Minute)})
	}
	seed("198.51.100.8", 5*time.Minute)  // denies quiet only 4m before the flow -> inside margin, no fire
	seed("198.51.100.9", 25*time.Minute) // denies quiet 24m before the flow -> fires
	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 detection (only the quiet tuple), got %+v", got)
	}
	if got[0].SrcAddr != "198.51.100.9" {
		t.Errorf("fired tuple src = %q, want 198.51.100.9 (the one whose denies stopped)", got[0].SrcAddr)
	}
}

// TestDeniedThenAllowed_SprayCannotStarveGenuineGap pins the candidate-cap
// starvation fix: gated scanner noise must not crowd a genuine gap out of the
// detector. Pre-fix, candidates were the top-50 tuples by sensitive-port
// ordering (tie-break dst_port ASC, so Telnet 23 outranked RDP 3389) chosen
// BEFORE deny history or the evidence gate were known — 60 gated Telnet
// tuples filled every slot and the real RDP gap was never even considered.
// The gate now runs in SQL over ALL tuples and the LIMIT caps emitted
// findings instead.
func TestDeniedThenAllowed_SprayCannotStarveGenuineGap(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// 60 distinct gated Telnet scanner tuples: denies still active (newest
	// ~now), verdict-less flows co-occurring — none may fire, but pre-fix they
	// consumed the whole candidate window.
	for i := 0; i < 60; i++ {
		src := fmt.Sprintf("203.0.113.%d", i+1)
		for _, ago := range []time.Duration{20 * time.Minute, time.Minute} {
			seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: src, DstAddr: "66.179.9.152",
				DstPort: 23, Protocol: 6, SrcIntfRole: models.IntfRoleWAN, Timestamp: now.Add(-ago)})
		}
		seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: src, DstAddr: "66.179.9.152",
			DstPort: 23, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-90 * time.Second)})
	}
	// One genuine quiet-gap RDP tuple: denies stopped 25m ago, traffic still
	// flowing 1m ago.
	for i := 0; i < 2; i++ {
		seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: "198.51.100.10", DstAddr: "10.0.0.50",
			DstPort: 3389, Protocol: 6, SrcIntfRole: models.IntfRoleWAN,
			Timestamp: now.Add(-25 * time.Minute).Add(-time.Duration(i) * time.Second)})
	}
	seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: "198.51.100.10", DstAddr: "10.0.0.50",
		DstPort: 3389, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-time.Minute)})

	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 detection (the RDP gap; spray is gated), got %d: %+v", len(got), got)
	}
	if got[0].SrcAddr != "198.51.100.10" || got[0].DstPort != 3389 {
		t.Errorf("fired tuple = %s:%d, want 198.51.100.10 dst_port 3389", got[0].SrcAddr, got[0].DstPort)
	}
}

// TestDeniedThenAllowed_FindingsCapAndOrdering: with more than 50 genuinely
// gated findings, the 50-cap keeps sensitive-port tuples ahead of
// non-sensitive ones.
func TestDeniedThenAllowed_FindingsCapAndOrdering(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	seedGap := func(src string, port uint16) {
		for i := 0; i < 2; i++ {
			seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: src, DstAddr: "10.0.0.60",
				DstPort: port, Protocol: 6, SrcIntfRole: models.IntfRoleWAN,
				Timestamp: now.Add(-25 * time.Minute).Add(-time.Duration(i) * time.Second)})
		}
		seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: src, DstAddr: "10.0.0.60",
			DstPort: port, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-time.Minute)})
	}
	for i := 0; i < 51; i++ { // 51 sensitive (SMB) quiet gaps
		seedGap(fmt.Sprintf("198.51.101.%d", i+1), 445)
	}
	seedGap("198.51.102.1", 8080) // 1 non-sensitive quiet gap — must lose the cap race

	got, err := deniedThenAllowedDetector{}.Detect(denyWindow(db, denyTestConfig(), now))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("want 50 findings (cap), got %d", len(got))
	}
	for _, g := range got {
		if g.DstPort == 8080 {
			t.Errorf("non-sensitive tuple made the cap ahead of sensitive ones: %+v", g)
		}
	}
}

// TestDeniedThenAllowed_IngestGraceExcludesFreshFlows pins denyAllowIngestGrace:
// a flow row younger than the grace window is not yet allow-evidence (its
// paired syslog deny may still be in flight — the resume-after-pause race),
// while the same tuple fires once its flow evidence is older than the grace.
func TestDeniedThenAllowed_IngestGraceExcludesFreshFlows(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// Window ending exactly at now so the grace trim is observable.
	w := Window{Start: now.Add(-15 * time.Minute), End: now, DB: db.Gorm(), Config: denyTestConfig()}

	seed := func(src string, flowAgo time.Duration) {
		for i := 0; i < 2; i++ {
			seedDeny(t, db, models.DeniedEvent{DeviceID: 1, SrcAddr: src, DstAddr: "10.0.0.70",
				DstPort: 445, Protocol: 6, SrcIntfRole: models.IntfRoleWAN,
				Timestamp: now.Add(-15 * time.Minute).Add(-time.Duration(i) * time.Second)})
		}
		seedFlow(t, db, models.FlowSample{DeviceID: 1, SrcAddr: src, DstAddr: "10.0.0.70",
			DstPort: 445, Protocol: 6, FirewallEvent: 0, Timestamp: now.Add(-flowAgo)})
	}
	seed("198.51.103.1", 10*time.Second) // flow inside the grace window -> not evidence yet
	seed("198.51.103.2", 2*time.Minute)  // flow past the grace, denies quiet 13m -> fires

	got, err := deniedThenAllowedDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 detection (grace must exclude the fresh flow), got %d: %+v", len(got), got)
	}
	if got[0].SrcAddr != "198.51.103.2" {
		t.Errorf("fired tuple src = %q, want 198.51.103.2", got[0].SrcAddr)
	}
}
