package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestFlowSuppression_LifecycleAndExpiry covers the silence-a-source model
// (v0.11.46): suppress → active → prune once expired.
func TestFlowSuppression_LifecycleAndExpiry(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()

	if err := db.SuppressFlowSource("203.0.113.7", now.Add(time.Hour), "alice", "scan"); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	on, err := db.IsFlowSourceSuppressed("203.0.113.7", now)
	if err != nil || !on {
		t.Fatalf("expected active suppression, got on=%v err=%v", on, err)
	}
	active, _ := db.ListActiveFlowSuppressions()
	if len(active) != 1 {
		t.Fatalf("ListActiveFlowSuppressions = %d, want 1", len(active))
	}

	// A source with no row is not suppressed.
	if on, _ := db.IsFlowSourceSuppressed("198.51.100.1", now); on {
		t.Fatal("unrelated source must not be suppressed")
	}

	// Expired rows are pruned and no longer active.
	if err := db.SuppressFlowSource("203.0.113.8", now.Add(-time.Minute), "bob", "old"); err != nil {
		t.Fatalf("suppress expired: %v", err)
	}
	if err := db.PruneExpiredFlowSuppressions(); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if on, _ := db.IsFlowSourceSuppressed("203.0.113.8", now); on {
		t.Fatal("expired suppression must be gone after prune")
	}
	if on, _ := db.IsFlowSourceSuppressed("203.0.113.7", now); !on {
		t.Fatal("unexpired suppression must survive prune")
	}
}

// TestFlowSuppression_UpsertExtends: re-silencing a source extends the window to
// the later time and never shortens it (upsert on unique src_addr).
func TestFlowSuppression_UpsertExtends(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	long := now.Add(48 * time.Hour)
	short := now.Add(time.Hour)

	if err := db.SuppressFlowSource("203.0.113.9", long, "a", "first"); err != nil {
		t.Fatalf("suppress long: %v", err)
	}
	// A shorter re-silence must NOT shorten the window.
	if err := db.SuppressFlowSource("203.0.113.9", short, "b", "second"); err != nil {
		t.Fatalf("suppress short: %v", err)
	}
	rows, _ := db.ListActiveFlowSuppressions()
	if len(rows) != 1 {
		t.Fatalf("want 1 row (upsert), got %d", len(rows))
	}
	if rows[0].SuppressedUntil.Before(long.Add(-time.Minute)) {
		t.Fatalf("window shortened to %v, want ~%v (extend-only)", rows[0].SuppressedUntil, long)
	}
}

// TestFlowSuppression_IPv6Normalization: the same IPv6 address in different
// textual forms resolves to one suppression (net.ParseIP canonicalization).
func TestFlowSuppression_IPv6Normalization(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	if err := db.SuppressFlowSource("2001:0db8:0000:0000:0000:0000:0000:0001", now.Add(time.Hour), "a", "v6"); err != nil {
		t.Fatalf("suppress v6: %v", err)
	}
	// Compressed form of the same address must match.
	on, err := db.IsFlowSourceSuppressed("2001:db8::1", now)
	if err != nil || !on {
		t.Fatalf("IPv6 compressed form should match, got on=%v err=%v", on, err)
	}
	rows, _ := db.ListActiveFlowSuppressions()
	if len(rows) != 1 {
		t.Fatalf("want 1 normalized row, got %d", len(rows))
	}
}

// TestGetActiveThreatIntel_ExcludesDisabledFeed: a disabled feed's indicators
// are excluded from the matcher build; manual entries (no status row) survive.
func TestGetActiveThreatIntel_ExcludesDisabledFeed(t *testing.T) {
	db := NewDatabaseForTesting(t)
	// Two feed sources + a manual entry.
	seed := []models.ThreatIntel{
		{CIDR: "10.0.0.0/24", Source: "feodo", Category: "c2"},
		{CIDR: "10.0.1.0/24", Source: "spamhaus", Category: "drop"},
		{CIDR: "10.0.2.0/24", Source: "manual", Category: "manual"},
	}
	if err := db.Gorm().Create(&seed).Error; err != nil {
		t.Fatalf("seed intel: %v", err)
	}
	// Register both feeds, disable one.
	for _, s := range []string{"feodo", "spamhaus"} {
		if err := db.UpsertThreatFeedStatus(&models.ThreatFeedStatus{Source: s, Enabled: true}); err != nil {
			t.Fatalf("upsert status %s: %v", s, err)
		}
	}
	if err := db.SetThreatFeedEnabled("feodo", false); err != nil {
		t.Fatalf("disable feodo: %v", err)
	}

	rows, err := db.GetActiveThreatIntel()
	if err != nil {
		t.Fatalf("GetActiveThreatIntel: %v", err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.Source] = true
	}
	if got["feodo"] {
		t.Error("disabled feed feodo must be excluded from the matcher")
	}
	if !got["spamhaus"] || !got["manual"] {
		t.Errorf("enabled feed + manual entry must survive, got %v", got)
	}
}

// TestDeleteThreatIntelBySource_PreservesManual: purging a feed deletes only its
// rows; a distinct source (manual) is untouched.
func TestDeleteThreatIntelBySource_PreservesManual(t *testing.T) {
	db := NewDatabaseForTesting(t)
	seed := []models.ThreatIntel{
		{CIDR: "10.0.0.0/24", Source: "feodo"},
		{CIDR: "10.0.0.1/32", Source: "feodo"},
		{CIDR: "10.0.2.0/24", Source: "manual"},
	}
	db.Gorm().Create(&seed)
	n, err := db.DeleteThreatIntelBySource("feodo")
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	var remaining int64
	db.Gorm().Model(&models.ThreatIntel{}).Count(&remaining)
	if remaining != 1 {
		t.Fatalf("remaining %d, want 1 (manual preserved)", remaining)
	}
}

// TestSettingHelpers covers the read-through GetBoolSetting/GetIntSetting used by
// the UI-managed toggles (env-default when absent, parsed when set).
func TestSettingHelpers(t *testing.T) {
	db := NewDatabaseForTesting(t)
	// Absent → default.
	if !db.GetBoolSetting("threat_feeds_enabled", true) {
		t.Error("absent bool should follow default true")
	}
	if db.GetIntSetting("detect_security_storm_sources", 25) != 25 {
		t.Error("absent int should return default 25")
	}
	// Present → parsed.
	db.UpsertSetting(&models.SystemSetting{Key: "threat_feeds_enabled", Value: "false"})
	db.UpsertSetting(&models.SystemSetting{Key: "detect_security_storm_sources", Value: "10"})
	if db.GetBoolSetting("threat_feeds_enabled", true) {
		t.Error("set bool false should override default true")
	}
	if db.GetIntSetting("detect_security_storm_sources", 25) != 10 {
		t.Error("set int should override default")
	}
}
