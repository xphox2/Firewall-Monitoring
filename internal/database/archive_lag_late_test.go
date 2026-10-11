package database

import (
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"
)

// Migration v81: the daily lag thresholds converted once from hours of age
// to hours late. Synthetic settings only.

// TestArchiveLagLate_NeverNoisier: for every minimum age 1..168 h and every
// stored value 1..100, the converted threshold fires — at an age of period +
// minimum age + slack + T — no sooner than the old alert did (v + 1 h: it
// also waited an hour above its threshold); 0 (off) stays off; the old
// default 26 becomes the new default 3 at the default minimum age.
func TestArchiveLagLate_NeverNoisier(t *testing.T) {
	for m := 1; m <= 168; m++ {
		for _, table := range []string{export.TableSyslog, export.TableCounters} {
			period, minAge, ok := ArchiveSchedule(table, m)
			if !ok || minAge != time.Duration(m)*time.Hour {
				t.Fatalf("%s schedule with min age %d: %s %s %v", table, m, period, minAge, ok)
			}
			for v := 1; v <= 100; v++ {
				late := ArchiveLagLate(v, minAge)
				newFire := period + minAge + ArchiveScheduleSlack + time.Duration(late)*time.Hour
				oldFire := time.Duration(v)*time.Hour + time.Hour
				if newFire < oldFire || late < ArchiveLagDefault {
					t.Fatalf("%s min age %d, stored %d → %d h late: fires at %s, the old alert at %s", table, m, v, late, newFire, oldFire)
				}
			}
		}
	}
	if ArchiveLagLate(0, 2*time.Hour) != 0 || ArchiveLagLate(26, 2*time.Hour) != 3 || ArchiveLagLate(48, 2*time.Hour) != 23 {
		t.Errorf("0 → %d, 26 → %d, 48 → %d", ArchiveLagLate(0, 2*time.Hour), ArchiveLagLate(26, 2*time.Hour), ArchiveLagLate(48, 2*time.Hour))
	}
}

func setting(t *testing.T, d *Database, key string) (string, bool) {
	t.Helper()
	var rows []models.SystemSetting
	if err := d.Gorm().Where("\"key\" = ?", key).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].Value, true
}

// testArchiveLagMigration is the migration's behaviour, on SQLite and on
// PostgreSQL (the integration lane): stored daily values are rewritten with
// the minimum age in effect (the admin setting wins over the environment),
// flows and absent keys are left alone (no default is inserted), the marker
// is written, a re-run converts nothing twice, and a value saved afterwards
// (48 h late) is never touched by a later run.
func testArchiveLagMigration(t *testing.T, d *Database) {
	t.Helper()
	// A PostgreSQL test database ran every migration (RunMigrations) on an
	// empty table: only the marker exists. Start from a pre-0.11.317 install.
	if v, ok := setting(t, d, ArchiveLagUnitKey); d.dialect.IsPostgres() && (!ok || v != "late") {
		t.Fatalf("marker after a fresh migration: %q %v", v, ok)
	}
	for _, k := range []string{ArchiveLagUnitKey, "archive_lag_alert_hours_syslog", "archive_lag_alert_hours_counters", "archive_lag_alert_hours_flows"} {
		if err := d.Gorm().Where("\"key\" = ?", k).Delete(&models.SystemSetting{}).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ARCHIVE_MIN_AGE_HOURS", "6")
	for k, v := range map[string]string{"archive_lag_alert_hours_syslog": "40", "archive_lag_alert_hours_flows": "5", "archive_min_age_hours": "4"} {
		if err := d.UpsertSetting(&models.SystemSetting{Key: k, Value: v}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.migrateArchiveLagHoursLate(); err != nil {
		t.Fatal(err)
	}
	// 40 h of age with the admin's minimum age 4 h (not the environment's 6):
	// ⌈40 + 1 − 24 − 4 − 1/6⌉ = 13 h late.
	if v, _ := setting(t, d, "archive_lag_alert_hours_syslog"); v != "13" {
		t.Errorf("syslog: %q, want 13", v)
	}
	if v, _ := setting(t, d, "archive_lag_alert_hours_flows"); v != "5" {
		t.Errorf("flows: %q, want 5 (kept)", v)
	}
	if _, ok := setting(t, d, "archive_lag_alert_hours_counters"); ok {
		t.Error("counters: a default was inserted")
	}
	if v, ok := setting(t, d, ArchiveLagUnitKey); !ok || v != "late" {
		t.Fatalf("no marker: %q", v)
	}
	// A re-run (a crash before the schema_migrations row) converts nothing
	// twice; a value entered afterwards is read as entered.
	if err := d.migrateArchiveLagHoursLate(); err != nil {
		t.Fatal(err)
	}
	if v, _ := setting(t, d, "archive_lag_alert_hours_syslog"); v != "13" {
		t.Errorf("syslog after a re-run: %q", v)
	}
	if err := d.UpsertSetting(&models.SystemSetting{Key: "archive_lag_alert_hours_counters", Value: "48"}); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateArchiveLagHoursLate(); err != nil {
		t.Fatal(err)
	}
	if d.dialect.IsPostgres() {
		// v81 is recorded in schema_migrations: a later start runs nothing.
		if err := d.RunMigrations(); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := setting(t, d, "archive_lag_alert_hours_counters"); v != "48" {
		t.Errorf("a value saved after the migration: %q, want 48", v)
	}

	// Without an admin minimum age, the environment's applies.
	for _, k := range []string{ArchiveLagUnitKey, "archive_min_age_hours"} {
		if err := d.Gorm().Where("\"key\" = ?", k).Delete(&models.SystemSetting{}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := d.UpsertSetting(&models.SystemSetting{Key: "archive_lag_alert_hours_syslog", Value: "40"}); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateArchiveLagHoursLate(); err != nil {
		t.Fatal(err)
	}
	if v, _ := setting(t, d, "archive_lag_alert_hours_syslog"); v != strconv.Itoa(ArchiveLagLate(40, 6*time.Hour)) || v != "11" {
		t.Errorf("syslog with the environment's 6 h: %q, want 11", v)
	}
}

func TestArchiveLagMigration(t *testing.T) {
	testArchiveLagMigration(t, NewDatabaseForTesting(t))
}
