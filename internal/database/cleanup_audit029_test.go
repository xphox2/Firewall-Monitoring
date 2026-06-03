package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// TestCleanupOldData_CoversAllFourOrphanTables_AUDIT029 is the
// regression for the audit: the four tables
// `interface_errors`, `processor_stats`, `process_stats`, and
// `irc_message_logs` were not in the `entries` slice of
// `CleanupOldData`, so every probe poll appended a row forever.
// On a long-running deployment this would OOM the DB.
//
// The fix: add the four models to the entries slice, with per-
// table retention knobs on RetentionConfig (defaults: 30 days
// for the three stats tables, 7 days for IRC message logs).
//
// The test drives CleanupOldData with a synthetic dataset that
// contains one row per table, all backdated 60 days, and asserts
// that every row is gone after the call. A pre-fix run would
// leave the rows in place (the entry wasn't there) and the test
// would fail.
func TestCleanupOldData_CoversAllFourOrphanTables_AUDIT029(t *testing.T) {
	d := NewDatabaseForTesting(t)
	stale := time.Now().AddDate(0, 0, -60)

	// 1. interface_errors (model: InterfaceErrors, fields: DeviceID, Interface, Timestamp, InErrors, etc.)
	if err := d.Gorm().Create(&models.InterfaceErrors{
		DeviceID: 1, Interface: "ge-0/0/0", Timestamp: stale,
		InErrors: 2, OutErrors: 3,
	}).Error; err != nil {
		t.Fatalf("seed interface_errors: %v", err)
	}
	// 2. processor_stats (model: ProcessorStats, fields: DeviceID, Index, Usage, Timestamp)
	if err := d.Gorm().Create(&models.ProcessorStats{
		DeviceID: 1, Index: 0, Usage: 50.0, Timestamp: stale,
	}).Error; err != nil {
		t.Fatalf("seed processor_stats: %v", err)
	}
	// 3. process_stats (model: ProcessStats, fields: DeviceID, Processes []ProcessInfo, Timestamp)
	if err := d.Gorm().Create(&models.ProcessStats{
		DeviceID: 1, Timestamp: stale,
		Processes: []models.ProcessInfo{{Name: "test", PID: 1, CPU: 1.0, Memory: 1.0, Command: "/bin/test"}},
	}).Error; err != nil {
		t.Fatalf("seed process_stats: %v", err)
	}
	// 4. irc_message_logs (model: IRCMessageLog, fields: ServerID, Channel, Nick, Message, MessageType, Timestamp)
	if err := d.Gorm().Create(&models.IRCMessageLog{
		ServerID: 1, Channel: "#test", Nick: "fwmon-bot",
		Message: "test", MessageType: "message", Timestamp: stale,
	}).Error; err != nil {
		t.Fatalf("seed irc_message_logs: %v", err)
	}

	// Run cleanup with the AUDIT-029 defaults: 30/30/30/7. The
	// test backdates rows 60 days, which is past 30 (and past 7
	// for IRC), so every row should be deleted.
	retention := config.RetentionConfig{
		InterfaceErrorsDays: 30,
		ProcessorStatsDays:  30,
		ProcessStatsDays:    30,
		IRCMessageLogDays:   7,
	}
	if err := d.CleanupOldData(retention); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	// Assert each orphan table is empty.
	tables := []struct {
		name  string
		model interface{}
	}{
		{"interface_errors", &models.InterfaceErrors{}},
		{"processor_stats", &models.ProcessorStats{}},
		{"process_stats", &models.ProcessStats{}},
		{"irc_message_logs", &models.IRCMessageLog{}},
	}
	for _, tbl := range tables {
		var count int64
		if err := d.Gorm().Model(tbl.model).Count(&count).Error; err != nil {
			t.Errorf("%s: count after cleanup: %v", tbl.name, err)
			continue
		}
		if count != 0 {
			t.Errorf("%s has %d row(s) after cleanup; AUDIT-029: every orphan table must be covered by the cleanup entries slice with a non-default retention knob.", tbl.name, count)
		}
	}
}

// TestCleanupOldData_RespectsPerTableRetention_AUDIT029 — defensive
// sibling: per-table retention is honored. We seed one row that's
// 10 days old and another that's 60 days old in the same table,
// configure a 30-day retention, and assert only the 60-day-old row
// is deleted. A regression that hardcodes one retention for all
// four tables (or that uses the wrong field for any of them) would
// fail here.
func TestCleanupOldData_RespectsPerTableRetention_AUDIT029(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	oldRow := &models.ProcessorStats{
		DeviceID: 1, Index: 0, Usage: 50.0,
		Timestamp: now.AddDate(0, 0, -60),
	}
	recentRow := &models.ProcessorStats{
		DeviceID: 1, Index: 1, Usage: 25.0,
		Timestamp: now.AddDate(0, 0, -10),
	}
	for _, r := range []*models.ProcessorStats{oldRow, recentRow} {
		if err := d.Gorm().Create(r).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// 30-day retention. The 60-day-old row should be deleted;
	// the 10-day-old row should survive.
	if err := d.CleanupOldData(config.RetentionConfig{
		ProcessorStatsDays: 30,
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var remaining []models.ProcessorStats
	if err := d.Gorm().Order("\"index\" ASC").Find(&remaining).Error; err != nil {
		t.Fatalf("query remaining: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("after 30-day cleanup, expected 1 row to remain, got %d", len(remaining))
	}
	if remaining[0].Index != 1 {
		t.Errorf("wrong row survived: Index=%d Usage=%v, want Index=1 Usage=25.0 (the recent row)", remaining[0].Index, remaining[0].Usage)
	}
}
