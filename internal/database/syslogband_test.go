package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// The syslog critical/informational split was hard-coded at severity 6, which
// put NOTICE (5) in the critical band. On a real fleet that is ~97% of all
// syslog by volume, so the long critical window was spent almost entirely on
// noise while the genuinely critical severities (0-3) were a few megabytes.

func setBoundary(t *testing.T, d *Database, v string) {
	t.Helper()
	if err := d.Gorm().Create(&models.SystemSetting{
		Key: SyslogSeverityBoundaryKey, Value: v,
	}).Error; err != nil {
		t.Fatalf("set boundary: %v", err)
	}
}

func TestSyslogCriticalBelow_DefaultsToHistoricSplit(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if got := d.SyslogCriticalBelow(); got != 6 {
		t.Errorf("boundary = %d, want 6 — an upgrade must not silently move the band", got)
	}
}

func TestSyslogCriticalBelow_HonoursTheSetting(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setBoundary(t, d, "5")
	if got := d.SyslogCriticalBelow(); got != 5 {
		t.Errorf("boundary = %d, want 5", got)
	}
}

// THE CLAMP, and the reason it exists. Aggregation summarises-then-deletes
// severity >= 6 on its own cadence and deliberately does not read this setting.
// A boundary above 6 would promise severity 6 the long critical window while
// aggregation kept deleting it at the informational age — the setting would
// silently break the guarantee it advertises.
func TestSyslogCriticalBelow_ClampsAboveAggregationThreshold(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setBoundary(t, d, "7")
	if got := d.SyslogCriticalBelow(); got != 6 {
		t.Fatalf("boundary = %d, want 6 — a boundary above the aggregation threshold "+
			"would grant severity 6 the critical window here while aggregation keeps "+
			"deleting it at the informational age", got)
	}
}

func TestSyslogCriticalBelow_ClampsBelowOne(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setBoundary(t, d, "0")
	if got := d.SyslogCriticalBelow(); got != 1 {
		t.Errorf("boundary = %d, want 1 — at least EMERG stays in the critical band", got)
	}
}

// The bands must remain complete and disjoint at every legal boundary: no row
// may escape both deletes, and none may be claimed by both windows in a way
// that contradicts the operator's policy.
func TestSyslogBands_AreCompleteAndDisjoint(t *testing.T) {
	for _, boundary := range []string{"1", "4", "5", "6"} {
		t.Run("boundary="+boundary, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			setBoundary(t, d, boundary)
			b := d.SyslogCriticalBelow()

			old := time.Now().AddDate(0, 0, -60)
			rows := make([]models.SyslogMessage, 0, 8)
			for sev := 0; sev <= 7; sev++ {
				rows = append(rows, models.SyslogMessage{
					DeviceID: 1, Severity: sev, Message: "m", Timestamp: old,
				})
			}
			if err := d.Gorm().Create(&rows).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}

			// Both windows far in the past, so everything old is eligible.
			if err := d.CleanupOldData(config.RetentionConfig{
				SyslogCriticalDays: 1, SyslogInfoDays: 1,
			}); err != nil {
				t.Fatalf("cleanup: %v", err)
			}

			var left int64
			d.Gorm().Model(&models.SyslogMessage{}).Count(&left)
			if left != 0 {
				var survivors []int
				d.Gorm().Model(&models.SyslogMessage{}).Pluck("severity", &survivors)
				t.Errorf("boundary %d left severities %v undeleted — a severity that falls "+
					"into neither band is retained forever", b, survivors)
			}
		})
	}
}

// The band test above passes at ANY boundary, so it cannot detect the setting
// being ignored. This one discriminates: with the boundary at 5, a NOTICE row
// belongs to the SHORT informational window and must be deleted; under the old
// hard-coded 6 it would be critical and survive.
//
// That distinction is the entire point of the change — it is what moves ~97% of
// syslog volume off the long window.
func TestSyslogBands_CleanupActuallyUsesTheBoundary(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setBoundary(t, d, "5")

	tenDaysOld := time.Now().AddDate(0, 0, -10)
	if err := d.Gorm().Create(&[]models.SyslogMessage{
		{DeviceID: 1, Severity: 5, Message: "notice", Timestamp: tenDaysOld},
		{DeviceID: 1, Severity: 4, Message: "warning", Timestamp: tenDaysOld},
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Critical window generous (30d), informational window short (1d).
	if err := d.CleanupOldData(config.RetentionConfig{
		SyslogCriticalDays: 30, SyslogInfoDays: 1,
	}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var notices, warnings int64
	d.Gorm().Model(&models.SyslogMessage{}).Where("severity = 5").Count(&notices)
	d.Gorm().Model(&models.SyslogMessage{}).Where("severity = 4").Count(&warnings)

	if notices != 0 {
		t.Errorf("a 10-day-old NOTICE survived a 1-day informational window — cleanup is "+
			"ignoring the boundary and still treating severity 5 as critical (got %d)", notices)
	}
	if warnings != 1 {
		t.Errorf("a 10-day-old WARNING was deleted under a 30-day critical window — the "+
			"boundary moved too far and is eating genuinely critical logs (got %d)", warnings)
	}
}

// The test above is named for disjointness but only proves COMPLETENESS — the
// bands `< B` and `>= B` cover [0,7] for every B, so it passes even if one
// predicate ignores the boundary. A concrete surviving mutation: leave the
// CRITICAL predicate as a literal `severity < 6` while info uses B. The bands
// then OVERLAP on [B,5], and a row in that overlap is deleted by whichever
// window is shorter — not the one the operator was promised.
//
// Detect it by making the critical window the SHORT one: with B=5 a NOTICE row
// belongs solely to the 30-day info band and must survive a 1-day critical
// window. Under the literal-6 mutation it also matches `< 6` and dies at 1 day.
func TestSyslogBands_DoNotOverlap(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setBoundary(t, d, "5")

	tenDaysOld := time.Now().AddDate(0, 0, -10)
	if err := d.Gorm().Create(&[]models.SyslogMessage{
		{DeviceID: 1, Severity: 5, Message: "notice", Timestamp: tenDaysOld},
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Critical window SHORT, informational window LONG — the reverse of the
	// other test, which is what exposes an overlap.
	if err := d.CleanupOldData(config.RetentionConfig{
		SyslogCriticalDays: 1, SyslogInfoDays: 30,
	}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var notices int64
	d.Gorm().Model(&models.SyslogMessage{}).Where("severity = 5").Count(&notices)
	if notices != 1 {
		t.Errorf("a NOTICE was deleted by the 1-day CRITICAL window despite the boundary " +
			"placing it in the 30-day informational band — the bands overlap, so the " +
			"shorter window silently wins")
	}
}
