package database

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Migration v81 (0.11.316): the archive lag alert thresholds change meaning.
// Before, archive_lag_alert_hours_* were hours of AGE of a table's verified
// data (default 26 for the daily syslog and counters tables, which also had
// to stay above it for an hour; 3 for flows). From 0.11.316 they are hours
// LATE past the schedule of the table's next chunk (status.ScheduleView):
// due = verified end + period + minimum age + ArchiveScheduleSlack.
//
// A stored daily value v fired the old alert at an age of v + 1 h. The new
// alert fires at an age of 24 h + minimum age + slack + T, so the value is
// rewritten once to
//
//	T = max(3, ⌈v + 1 h − 24 h − minimum age − slack⌉ hours)
//
// with the minimum age configured now (the admin setting, else
// ARCHIVE_MIN_AGE_HOURS, else 2): never sooner than before, for any minimum
// age. 0 (off) stays 0. A flows value is kept: it fired at an age of v, the
// new alert at 1 h + 5 min + slack + v — always later. Only stored rows are
// rewritten (absent keys keep the new default 3), and the marker
// ArchiveLagUnitKey is written in the same transaction: a re-run (a crash
// between run() and its schema_migrations row) converts nothing twice.

// ArchiveScheduleSlack is the settle window a cut chunk may take before its
// export starts — part of a table's schedule (status.SettleSlack is it).
const ArchiveScheduleSlack = 10 * time.Minute

// ArchiveLagUnitKey marks that the stored lag thresholds are hours late.
const ArchiveLagUnitKey = "archive_lag_alert_hours_unit"

// ArchiveLagDailyKeys are the daily tables' lag threshold settings
// (status.LagHoursSyslogKey, status.LagHoursCountersKey); ArchiveLagDefault
// the new default.
var ArchiveLagDailyKeys = []string{"archive_lag_alert_hours_syslog", "archive_lag_alert_hours_counters"}

const ArchiveLagDefault = 3

// ArchiveLagLate is a stored daily lag threshold v (hours of age) as hours
// late with minAge (see above).
func ArchiveLagLate(v int, minAge time.Duration) int {
	if v <= 0 {
		return v
	}
	late := time.Duration(v)*time.Hour + time.Hour - 24*time.Hour - minAge - ArchiveScheduleSlack
	return max(ArchiveLagDefault, int(math.Ceil(late.Hours())))
}

// archiveMinAgeNow is ARCHIVE_MIN_AGE_HOURS in effect: the admin setting,
// else the environment, else the default.
func (d *Database) archiveMinAgeNow(tx *gorm.DB) time.Duration {
	parse := func(s string) (int, bool) {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		return n, err == nil && n >= 1 && n <= 168
	}
	if f, ok := config.ArchiveFieldByEnv("ARCHIVE_MIN_AGE_HOURS"); ok {
		var rows []models.SystemSetting
		if err := tx.Where("\"key\" = ?", f.Setting()).Limit(1).Find(&rows).Error; err == nil && len(rows) == 1 {
			if n, ok := parse(rows[0].Value); ok {
				return time.Duration(n) * time.Hour
			}
		}
	}
	if n, ok := parse(os.Getenv("ARCHIVE_MIN_AGE_HOURS")); ok {
		return time.Duration(n) * time.Hour
	}
	return 2 * time.Hour
}

func (d *Database) migrateArchiveLagHoursLate() error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		var marker []models.SystemSetting
		if err := tx.Where("\"key\" = ?", ArchiveLagUnitKey).Limit(1).Find(&marker).Error; err != nil {
			return fmt.Errorf("migrate v81: read %s: %w", ArchiveLagUnitKey, err)
		}
		if len(marker) > 0 {
			return nil // converted already
		}
		minAge := d.archiveMinAgeNow(tx)
		var rows []models.SystemSetting
		if err := tx.Where("\"key\" IN ?", ArchiveLagDailyKeys).Find(&rows).Error; err != nil {
			return fmt.Errorf("migrate v81: read the lag thresholds: %w", err)
		}
		for _, r := range rows {
			v, err := strconv.Atoi(strings.TrimSpace(r.Value))
			if err != nil || v < 0 {
				continue // malformed or blank: read as the default, as before
			}
			nv := strconv.Itoa(ArchiveLagLate(v, minAge))
			if nv == r.Value {
				continue
			}
			if err := tx.Model(&models.SystemSetting{}).Where("\"key\" = ?", r.Key).Update("value", nv).Error; err != nil {
				return fmt.Errorf("migrate v81: rewrite %s: %w", r.Key, err)
			}
			log.Printf("migrate v81: %s %d h of age → %s h late (minimum age %s)", r.Key, v, nv, minAge)
		}
		m := models.SystemSetting{Key: ArchiveLagUnitKey, Value: "late", Type: "string", Category: "archive",
			Label: "Raw archive: the lag thresholds are hours late (converted from hours of age by migration v81)"}
		if err := tx.Create(&m).Error; err != nil {
			return fmt.Errorf("migrate v81: write %s: %w", ArchiveLagUnitKey, err)
		}
		return nil
	})
}
