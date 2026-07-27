package database

import (
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// Per-severity retention has three distinct values and they are easy to
// conflate: blank inherits, 0 keeps forever, N deletes at N days. Conflating
// blank with 0 is the failure that silently deletes logs an operator chose to
// keep indefinitely.

func setRetention(t *testing.T, d *Database, key, value string) {
	t.Helper()
	if err := d.Gorm().Create(&models.SystemSetting{Key: key, Value: value}).Error; err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

// prodLike mirrors production: only RETENTION_SYSLOG_CRITICAL_DAYS is set.
func prodLike() config.RetentionConfig {
	return config.RetentionConfig{SyslogCriticalDays: 30, SyslogInfoDays: 7}
}

// An operator who has never opened the UI must keep exactly what they have.
func TestSyslogRetention_UntouchedMatchesLegacyModel(t *testing.T) {
	d := NewDatabaseForTesting(t)
	days := d.SyslogRetentionDays(prodLike())

	for sev := 0; sev <= 5; sev++ {
		if days[sev] != 30 {
			t.Errorf("severity %d = %d days, want 30 — the legacy critical band", sev, days[sev])
		}
	}
	for sev := 6; sev <= 7; sev++ {
		if days[sev] != 7 {
			t.Errorf("severity %d = %d days, want 7 — the legacy informational band", sev, days[sev])
		}
	}
}

// THE ASYMMETRY. In the legacy model SyslogCriticalDays==0 means forever, but
// SyslogInfoDays<=0 is clamped to 7. Folding both into the new uniform
// "0 = forever" would invert an explicit RETENTION_SYSLOG_INFO_DAYS=0.
func TestSyslogRetention_LegacyZeroIsAsymmetric(t *testing.T) {
	d := NewDatabaseForTesting(t)
	days := d.SyslogRetentionDays(config.RetentionConfig{
		SyslogCriticalDays: 0, // forever
		SyslogInfoDays:     0, // NOT forever — clamps to 7
	})

	if days[0] != 0 {
		t.Errorf("severity 0 = %d, want 0 (keep forever) — SyslogCriticalDays==0 means forever", days[0])
	}
	if days[6] != 7 {
		t.Errorf("severity 6 = %d, want 7 — SyslogInfoDays<=0 clamps to 7 and must NOT become "+
			"keep-forever, which would invert today's aggregate-and-delete", days[6])
	}
}

func TestSyslogRetention_DefaultAppliesToEverythingNotUncoupled(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionDefaultKey, "45")

	days := d.SyslogRetentionDays(prodLike())
	for sev := 0; sev < SyslogSeverityCount; sev++ {
		if days[sev] != 45 {
			t.Errorf("severity %d = %d, want 45 — the default covers every severity that "+
				"has not been uncoupled", sev, days[sev])
		}
	}
}

// The point of the feature: cut the noisy severity, extend the rest.
func TestSyslogRetention_PerSeverityOverridesTheDefault(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionDefaultKey, "90")
	setRetention(t, d, SyslogRetentionKey(5), "7") // notice is the spammy one

	days := d.SyslogRetentionDays(prodLike())
	if days[5] != 7 {
		t.Errorf("severity 5 = %d, want 7 — an uncoupled severity must override the default", days[5])
	}
	if days[4] != 90 {
		t.Errorf("severity 4 = %d, want 90 — untouched severities keep the default", days[4])
	}
}

// 0 must survive as keep-forever through the whole chain, at every level.
func TestSyslogRetention_ZeroMeansForeverNotInherit(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionDefaultKey, "30")
	setRetention(t, d, SyslogRetentionKey(0), "0") // emerg: keep forever

	days := d.SyslogRetentionDays(prodLike())
	if days[0] != 0 {
		t.Errorf("severity 0 = %d, want 0 — an explicit 0 means KEEP FOREVER. Reading it as "+
			"'blank, inherit the default' would delete emergency logs at 30 days", days[0])
	}
	if days[1] != 30 {
		t.Errorf("severity 1 = %d, want 30", days[1])
	}
}

// Blank is not 0. This is the distinction GetIntSetting cannot express without
// the sentinel, and getting it wrong deletes data.
func TestSyslogRetention_BlankInheritsRatherThanKeepingForever(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionDefaultKey, "14")
	setRetention(t, d, SyslogRetentionKey(3), "") // cleared, not zeroed

	days := d.SyslogRetentionDays(prodLike())
	if days[3] != 14 {
		t.Errorf("severity 3 = %d, want 14 — a CLEARED field inherits the default; reading "+
			"blank as 0 would silently switch it to keep-forever", days[3])
	}
}

// A stored negative other than the sentinel must not become a negative window.
func TestSyslogRetention_NegativeFallsBackRatherThanGoingNegative(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionKey(4), "-5")

	days := d.SyslogRetentionDays(prodLike())
	if days[4] < 0 {
		t.Errorf("severity 4 = %d — a negative window would make every cutoff a FUTURE "+
			"timestamp and delete everything", days[4])
	}
}

func TestSyslogRetention_WindowGroupsCollapseAndOmitForever(t *testing.T) {
	var days [SyslogSeverityCount]int
	for i := range days {
		days[i] = 30
	}
	days[5] = 7
	days[0] = 0 // forever

	groups := syslogWindowGroups(days)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (30 and 7) — severities sharing a window must "+
			"collapse into one delete", len(groups))
	}
	if len(groups[7]) != 1 || groups[7][0] != 5 {
		t.Errorf("the 7-day group = %v, want [5]", groups[7])
	}
	for _, sevs := range groups {
		for _, s := range sevs {
			if s == 0 {
				t.Error("severity 0 is keep-forever and must never appear in a delete group")
			}
		}
	}
}

func TestSyslogRetention_MaxWindowIsZeroIfAnySeverityIsForever(t *testing.T) {
	if got := syslogMaxWindow([]int{30, 7, 90}); got != 90 {
		t.Errorf("max = %d, want 90", got)
	}
	if got := syslogMaxWindow([]int{30, 0, 90}); got != 0 {
		t.Errorf("max = %d, want 0 — one keep-forever severity pins every partition, because "+
			"dropping it would take that severity's rows with it", got)
	}
}

// Guard the sentinel itself: it must not be a value an operator could store.
func TestSyslogRetention_SentinelIsOutOfBand(t *testing.T) {
	if syslogRetentionInherit >= 0 {
		t.Fatalf("the inherit sentinel is %d — a non-negative sentinel is indistinguishable "+
			"from a real window", syslogRetentionInherit)
	}
	if _, err := strconv.Atoi(""); err == nil {
		t.Fatal("empty parses as a number; the sentinel design assumes it does not")
	}
}

// ---- end-to-end through CleanupOldData and the aggregation cycle ----------

func seedSyslog(t *testing.T, d *Database, severity, daysOld int) {
	t.Helper()
	if err := d.Gorm().Create(&models.SyslogMessage{
		DeviceID: 1, Severity: severity, Message: "m",
		Timestamp: timeNowAddDays(-daysOld),
	}).Error; err != nil {
		t.Fatalf("seed sev%d: %v", severity, err)
	}
}

func countSyslog(t *testing.T, d *Database, severity int) int64 {
	t.Helper()
	var n int64
	d.Gorm().Model(&models.SyslogMessage{}).Where("severity = ?", severity).Count(&n)
	return n
}

// The headline behaviour: cut the noisy severity, keep the important ones
// longer — the whole reason this feature exists.
func TestSyslogRetention_CleanupHonoursPerSeverityWindows(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionDefaultKey, "90")
	setRetention(t, d, SyslogRetentionKey(5), "7")

	seedSyslog(t, d, 5, 30) // notice, 30d old — past its 7-day window
	seedSyslog(t, d, 4, 30) // warning, 30d old — inside the 90-day default

	if err := d.CleanupOldData(prodLike()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if n := countSyslog(t, d, 5); n != 0 {
		t.Errorf("severity 5 survived its own 7-day window (%d rows) — the per-severity "+
			"override is not reaching cleanup", n)
	}
	if n := countSyslog(t, d, 4); n != 1 {
		t.Errorf("severity 4 was deleted despite a 90-day window (%d rows) — a severity "+
			"is being trimmed by another severity's window", n)
	}
}

// Keep-forever must survive cleanup, not merely the resolver.
func TestSyslogRetention_CleanupNeverDeletesKeepForever(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionDefaultKey, "7")
	setRetention(t, d, SyslogRetentionKey(0), "0")

	seedSyslog(t, d, 0, 3650) // ten years old, kept forever
	seedSyslog(t, d, 1, 3650)

	if err := d.CleanupOldData(prodLike()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n := countSyslog(t, d, 0); n != 1 {
		t.Errorf("a keep-forever severity was deleted (%d rows left) — 0 must mean forever, "+
			"not 'zero days'", n)
	}
	if n := countSyslog(t, d, 1); n != 0 {
		t.Errorf("severity 1 survived the 7-day default (%d rows)", n)
	}
}

// THE AGGREGATION PATH. Aggregation runs every 5 minutes against severities 6-7
// while cleanup runs daily, so it is the effective owner of those severities.
// A per-severity window that only reaches cleanup does nothing for them.
func TestSyslogRetention_AggregationHonoursPerSeverityWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionKey(6), "3")

	// 5 days old: past the 3-day per-severity window, but INSIDE the legacy
	// 7-day one. Seeding it older than 7 days would let this test pass against
	// a hard-coded window too, proving nothing.
	seedSyslog(t, d, 6, 5)

	if err := d.RunSyslogAggregationCycle(prodLike()); err != nil {
		t.Fatalf("aggregation: %v", err)
	}
	if n := countSyslog(t, d, 6); n != 0 {
		t.Errorf("severity 6 was not consumed at its own 3-day window (%d raw rows) — the "+
			"window is reaching cleanup but not syslog_agg.go, which owns this severity", n)
	}
	var summaries int64
	d.Gorm().Model(&models.SyslogSummary{}).Where("severity = ?", 6).Count(&summaries)
	if summaries == 0 {
		t.Error("the rows were deleted without being summarised — aggregation must summarise " +
			"then delete, atomically")
	}
}

// Keep-forever on an AGGREGATED severity must skip the pass entirely: it is not
// summarised and not deleted, it just stays raw. Summarise-but-not-delete would
// double-count, because every reader unions raw and summary counts.
func TestSyslogRetention_AggregationSkipsKeepForever(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, SyslogRetentionKey(6), "0")

	seedSyslog(t, d, 6, 3650)

	if err := d.RunSyslogAggregationCycle(prodLike()); err != nil {
		t.Fatalf("aggregation: %v", err)
	}
	if n := countSyslog(t, d, 6); n != 1 {
		t.Errorf("a keep-forever severity was consumed by aggregation (%d raw rows) — this is "+
			"the silent inversion: naive wiring turns 'keep forever' into 'delete at 7 days'", n)
	}
	var summaries int64
	d.Gorm().Model(&models.SyslogSummary{}).Where("severity = ?", 6).Count(&summaries)
	if summaries != 0 {
		t.Errorf("keep-forever rows were summarised (%d summaries) — the raw rows still exist, "+
			"so every reader that unions raw and summary counts would double-count them", summaries)
	}
}

func timeNowAddDays(d int) time.Time { return time.Now().AddDate(0, 0, d) }
