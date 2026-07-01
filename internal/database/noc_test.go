package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetNOCSnapshot verifies the live snapshot aggregates recent flows over the
// window (throughput, top talkers, threat-flow count) and excludes flows older
// than the window.
func TestGetNOCSnapshot(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	recent := now.Add(-1 * time.Minute)
	old := now.Add(-30 * time.Minute) // outside a 5-min window

	mk := func(ts time.Time, src, dst string, bytes uint64, threat uint8) models.FlowSample {
		return models.FlowSample{
			Timestamp: ts, DeviceID: 1, Protocol: 6, SrcAddr: src, DstAddr: dst,
			SrcPort: 40000, DstPort: 443, Bytes: bytes, Packets: 1,
			AppCategory: 1, Direction: 2, ThreatFlag: threat,
		}
	}
	rows := []models.FlowSample{
		mk(recent, "10.0.0.5", "8.8.8.8", 1000, 0),
		mk(recent, "10.0.0.5", "8.8.4.4", 2000, 2), // threat-flagged dst
		mk(recent, "10.0.0.6", "1.1.1.1", 500, 0),
		mk(old, "10.0.0.9", "9.9.9.9", 999999, 0), // outside window — must be excluded
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	snap, err := db.GetNOCSnapshot(5 * time.Minute)
	if err != nil {
		t.Fatalf("GetNOCSnapshot: %v", err)
	}
	if snap.TotalFlows != 3 {
		t.Errorf("TotalFlows = %d, want 3 (old flow excluded)", snap.TotalFlows)
	}
	if snap.TotalBytes != 3500 {
		t.Errorf("TotalBytes = %d, want 3500 (1000+2000+500)", snap.TotalBytes)
	}
	if snap.ThreatFlows != 1 {
		t.Errorf("ThreatFlows = %d, want 1", snap.ThreatFlows)
	}
	if snap.UniqueSources != 2 {
		t.Errorf("UniqueSources = %d, want 2", snap.UniqueSources)
	}
	if snap.BitsPerSecond <= 0 {
		t.Errorf("BitsPerSecond = %v, want > 0", snap.BitsPerSecond)
	}
	if len(snap.TopSources) == 0 || snap.TopSources[0].Key != "10.0.0.5" {
		t.Errorf("TopSources[0] = %+v, want 10.0.0.5 first", snap.TopSources)
	}
	if snap.WindowSeconds != 300 {
		t.Errorf("WindowSeconds = %d, want 300", snap.WindowSeconds)
	}
}

// findSite returns the SiteBreakdown for a site name (or the Unassigned bucket
// when name=="Unassigned"), or nil.
func findSiteBreakdown(sites []SiteBreakdown, name string) *SiteBreakdown {
	for i := range sites {
		if sites[i].SiteName == name {
			return &sites[i]
		}
	}
	return nil
}

// TestGetNOCBreakdown verifies the per-site → per-device rollup: bucketing
// (including the Unassigned bucket), online/offline counts, the composite worst
// severity (open alert vs. offline device), and that acked/snoozed alerts are
// excluded exactly as the Alerts list excludes them.
func TestGetNOCBreakdown(t *testing.T) {
	db := NewDatabaseForTesting(t)
	future := time.Now().Add(time.Hour)

	hq := models.Site{Name: "HQ"}
	branch := models.Site{Name: "Branch"}
	if err := db.Gorm().Create(&hq).Error; err != nil {
		t.Fatalf("create hq: %v", err)
	}
	if err := db.Gorm().Create(&branch).Error; err != nil {
		t.Fatalf("create branch: %v", err)
	}

	// HQ: fw1 online (will get a critical alert), fw2 offline (→ warning via status).
	// Branch: fw3 online, no issues. Plus an unsited device fw4 online.
	fw1 := models.Device{Name: "fw1", IPAddress: "10.0.0.1", SiteID: &hq.ID, Status: "online"}
	fw2 := models.Device{Name: "fw2", IPAddress: "10.0.0.2", SiteID: &hq.ID, Status: "offline"}
	fw3 := models.Device{Name: "fw3", IPAddress: "10.1.0.1", SiteID: &branch.ID, Status: "online"}
	fw4 := models.Device{Name: "fw4", IPAddress: "10.9.0.1", Status: "online"} // no site
	for _, d := range []*models.Device{&fw1, &fw2, &fw3, &fw4} {
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("create device %s: %v", d.Name, err)
		}
	}

	// Alerts: one open critical on fw1 (counts), plus an acknowledged and a
	// snoozed alert on fw3 that must BOTH be ignored (fw3/Branch stays healthy).
	alerts := []models.Alert{
		{DeviceID: fw1.ID, Severity: models.SeverityCritical, Message: "cpu", Timestamp: time.Now()},
		{DeviceID: fw3.ID, Severity: models.SeverityCritical, Message: "acked", Acknowledged: true, Timestamp: time.Now()},
		{DeviceID: fw3.ID, Severity: models.SeverityWarning, Message: "snoozed", SnoozedUntil: &future, Timestamp: time.Now()},
	}
	if err := db.Gorm().Create(&alerts).Error; err != nil {
		t.Fatalf("create alerts: %v", err)
	}

	snap, err := db.GetNOCSnapshot(5 * time.Minute)
	if err != nil {
		t.Fatalf("GetNOCSnapshot: %v", err)
	}

	hqB := findSiteBreakdown(snap.Sites, "HQ")
	if hqB == nil {
		t.Fatalf("HQ bucket missing; sites=%+v", snap.Sites)
	}
	if hqB.DevicesOnline != 1 || hqB.DevicesOffline != 1 {
		t.Errorf("HQ online/offline = %d/%d, want 1/1", hqB.DevicesOnline, hqB.DevicesOffline)
	}
	if hqB.AlertsCritical != 1 {
		t.Errorf("HQ AlertsCritical = %d, want 1", hqB.AlertsCritical)
	}
	if hqB.WorstSeverity != string(models.SeverityCritical) {
		t.Errorf("HQ WorstSeverity = %q, want critical", hqB.WorstSeverity)
	}

	branchB := findSiteBreakdown(snap.Sites, "Branch")
	if branchB == nil {
		t.Fatalf("Branch bucket missing")
	}
	if branchB.AlertsCritical != 0 || branchB.AlertsWarning != 0 {
		t.Errorf("Branch alert counts = %d/%d, want 0/0 (acked+snoozed excluded)", branchB.AlertsCritical, branchB.AlertsWarning)
	}
	if branchB.WorstSeverity != "" {
		t.Errorf("Branch WorstSeverity = %q, want empty (healthy)", branchB.WorstSeverity)
	}

	un := findSiteBreakdown(snap.Sites, "Unassigned")
	if un == nil {
		t.Fatalf("Unassigned bucket missing (fw4 has no site)")
	}
	if un.SiteID != nil {
		t.Errorf("Unassigned SiteID = %v, want nil", un.SiteID)
	}
	if len(un.Devices) != 1 || un.Devices[0].Name != "fw4" {
		t.Errorf("Unassigned devices = %+v, want [fw4]", un.Devices)
	}

	// Sites sorted worst-severity-first: HQ (critical) precedes Branch (healthy);
	// Unassigned always last.
	if len(snap.Sites) < 2 || snap.Sites[0].SiteName != "HQ" {
		t.Errorf("expected HQ first (most severe); got %+v", snap.Sites)
	}
	if snap.Sites[len(snap.Sites)-1].SiteName != "Unassigned" {
		t.Errorf("expected Unassigned last; got %+v", snap.Sites)
	}
}

// TestGetDeviceAlertSeverities verifies the map feeding the connection-map node
// pulse carries the worst open-alert severity per device and excludes
// resolved / acknowledged / suppressed / snoozed alerts.
func TestGetDeviceAlertSeverities(t *testing.T) {
	db := NewDatabaseForTesting(t)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	alerts := []models.Alert{
		{DeviceID: 1, Severity: models.SeverityWarning, Timestamp: time.Now()},
		{DeviceID: 1, Severity: models.SeverityCritical, Timestamp: time.Now()}, // worst for dev 1
		{DeviceID: 2, Severity: models.SeverityCritical, Acknowledged: true, Timestamp: time.Now()},
		{DeviceID: 3, Severity: models.SeverityCritical, Suppressed: true, Timestamp: time.Now()},
		{DeviceID: 4, Severity: models.SeverityCritical, SnoozedUntil: &future, Timestamp: time.Now()},
		{DeviceID: 5, Severity: models.SeverityWarning, ResolvedAt: &past, Timestamp: time.Now()},
	}
	if err := db.Gorm().Create(&alerts).Error; err != nil {
		t.Fatalf("seed alerts: %v", err)
	}

	sev, err := db.GetDeviceAlertSeverities()
	if err != nil {
		t.Fatalf("GetDeviceAlertSeverities: %v", err)
	}
	if sev[1] != string(models.SeverityCritical) {
		t.Errorf("dev1 = %q, want critical (worst of warning+critical)", sev[1])
	}
	for _, id := range []uint{2, 3, 4, 5} {
		if s, ok := sev[id]; ok {
			t.Errorf("dev%d = %q, want absent (acked/suppressed/snoozed/resolved excluded)", id, s)
		}
	}
}

// TestGetNOCSnapshotFiltered_Site verifies the site filter scopes flow aggregates
// to only the devices in that site (the same device_id-subquery the Flows page
// site filter uses).
func TestGetNOCSnapshotFiltered_Site(t *testing.T) {
	db := NewDatabaseForTesting(t)

	hq := models.Site{Name: "HQ"}
	branch := models.Site{Name: "Branch"}
	db.Gorm().Create(&hq)
	db.Gorm().Create(&branch)
	d1 := models.Device{Name: "d1", IPAddress: "10.0.0.1", SiteID: &hq.ID, Status: "online"}
	d2 := models.Device{Name: "d2", IPAddress: "10.1.0.1", SiteID: &branch.ID, Status: "online"}
	db.Gorm().Create(&d1)
	db.Gorm().Create(&d2)

	now := time.Now().Add(-1 * time.Minute)
	rows := []models.FlowSample{
		{Timestamp: now, DeviceID: d1.ID, SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", Bytes: 1000, Packets: 1},
		{Timestamp: now, DeviceID: d2.ID, SrcAddr: "10.1.0.1", DstAddr: "8.8.8.8", Bytes: 4000, Packets: 1},
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed flows: %v", err)
	}

	snap, err := db.GetNOCSnapshotFiltered(5*time.Minute, NOCFilter{SiteID: &hq.ID})
	if err != nil {
		t.Fatalf("GetNOCSnapshotFiltered: %v", err)
	}
	if snap.TotalBytes != 1000 {
		t.Errorf("filtered TotalBytes = %d, want 1000 (HQ device only, not Branch's 4000)", snap.TotalBytes)
	}
	if snap.TotalFlows != 1 {
		t.Errorf("filtered TotalFlows = %d, want 1", snap.TotalFlows)
	}
	// Filtered snapshot omits the fleet-only site breakdown.
	if snap.Sites != nil {
		t.Errorf("filtered snapshot should not carry Sites breakdown; got %d", len(snap.Sites))
	}
}
