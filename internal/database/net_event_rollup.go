package database

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The net_events daily rollup (v72; roadmap §1.2 net_event_rollups). Runs on
// the poller's 5-minute rollup tick under the maintenance lock, beside the
// flow rollup ladder and the syslog aggregation pass, in two steps:
//
//  1. Hour fold. Every completed hour since the watermark setting is grouped
//     by (UTC day, device, rule_key, action, direction, app_cat, ruleset) and
//     upserted ADDITIVELY into the day's rows (hits / bytes add, last_ts and
//     distinct_src take the greater). An hour is complete once it is
//     netEventRollupLag old, which covers the collector's batching delay. The
//     watermark moves in the fold's own transaction, so a crash re-folds
//     nothing and skips nothing. distinct_src is a LOWER BOUND here (the max
//     over single hours), which is what "approx until day close" means.
//  2. Day close. Once every hour of a UTC day is folded and the day is
//     netEventRollupCloseLag old, the day is recomputed EXACTLY from its own
//     partition in one transaction — delete the day's rows, insert the fresh
//     GROUP BY with a true COUNT(DISTINCT src_ip) — and recorded in the
//     closed-day setting. Besides making distinct_src exact, this absorbs any
//     row that arrived late for an hour already folded (a collector replaying
//     its backlog), so a closed day is correct whatever the arrival order.
//
// The syslog and flow passes key their watermark on MAX(id) and delete what
// they consume; here nothing is consumed (net_events keep their own
// retention), so the watermark is the hour boundary and late rows are the
// day close's job. Both settings are plain system_settings rows so the S-5
// backfill can rewind them: setting net_event_rollup_closed_day to the day
// before the backfill window makes the next cycles recompute every backfilled
// day; the hourly watermark needs no change.
//
// Zones: net_events.ts is written in UTC and the rollup day is a UTC midnight,
// so every bound here is UTC (walkAggregationWindows' SQLite caveat — bounds
// must render in the writers' zone — is satisfied by construction).
const (
	// netEventRollupWatermarkKey holds the UTC hour boundary (RFC 3339) up to
	// which net_events have been folded: every row with ts < watermark is in
	// the rollups (modulo late arrivals, which the day close picks up).
	netEventRollupWatermarkKey = "net_event_rollup_watermark"
	// netEventRollupClosedDayKey holds the newest UTC day (YYYY-MM-DD) whose
	// rollup rows were recomputed exactly from its partition.
	netEventRollupClosedDayKey = "net_event_rollup_closed_day"
)

var (
	// netEventRollupLag is how old an hour must be before it is folded, so a
	// collector batch (30 s) or a brief outage does not leave rows behind the
	// watermark for the day close to catch.
	netEventRollupLag = 15 * time.Minute
	// netEventRollupCloseLag is how far past a UTC day's end its exact
	// recompute waits, for backlog replays that span the midnight boundary.
	netEventRollupCloseLag = 2 * time.Hour
	// maxNetEventRollupHoursPerCycle bounds one tick's hour folds (a week-long
	// stall drains in seven ticks); maxNetEventRollupDaysPerCycle bounds the
	// whole-partition recomputes, which read a day's rows each.
	maxNetEventRollupHoursPerCycle = 24
	maxNetEventRollupDaysPerCycle  = 2
	// netEventRollupInsertBatch sizes the rollup upsert INSERTs (13 columns;
	// well under the 65535-parameter limit). A var so a test can shrink it
	// to exercise the multi-statement path.
	netEventRollupInsertBatch = 500
)

// RunNetEventRollupCycle is the poller entry point (see the file comment).
// Errors are logged, never returned: every hour and day that committed stays
// committed and the next tick resumes from the settings.
func (d *Database) RunNetEventRollupCycle() {
	hours, days, err := d.runNetEventRollupCycle(time.Now())
	switch {
	case err != nil:
		log.Printf("Net event rollup: %v (%d hour(s) folded and %d day(s) closed before the error were kept; will resume next cycle)", err, hours, days)
	case hours > 0 || days > 0:
		log.Printf("Net event rollup: folded %d hour(s), closed %d day(s)", hours, days)
	}
}

// runNetEventRollupCycle is RunNetEventRollupCycle with an injectable clock.
func (d *Database) runNetEventRollupCycle(now time.Time) (hours, days int, err error) {
	now = now.UTC()
	// Hours ending at or before `limit` are complete.
	limit := now.Add(-netEventRollupLag).Truncate(time.Hour)

	wm, ok, err := d.netEventRollupWatermark()
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		// First run: start at the oldest event's hour. MIN(ts) is the first
		// tuple of each leaf's (ts) index, merged — cheap however large the
		// table (and empty on an install that has not normalized anything yet).
		start, found, err := oldestEligibleOn(d.db.Model(&models.NetEvent{}).Where("ts < ?", limit), "ts")
		if err != nil {
			return 0, 0, fmt.Errorf("oldest net_event: %w", err)
		}
		if !found {
			return 0, 0, nil
		}
		wm = start.UTC().Truncate(time.Hour)
	}

	for hours < maxNetEventRollupHoursPerCycle && !wm.Add(time.Hour).After(limit) {
		groups, err := d.foldNetEventRollupHour(wm)
		if err != nil {
			return hours, days, err
		}
		hours++
		wm = wm.Add(time.Hour)
		if groups > 0 {
			continue
		}
		// An empty hour: jump the watermark to the next populated hour (or to
		// the limit) instead of folding empty hours one tick at a time after an
		// outage. Folding nothing commits nothing, so the jump is a plain
		// setting write.
		next, found, err := oldestEligibleOn(d.db.Model(&models.NetEvent{}).Where("ts >= ? AND ts < ?", wm, limit), "ts")
		if err != nil {
			return hours, days, fmt.Errorf("next populated hour: %w", err)
		}
		if !found {
			next = limit
		} else {
			next = next.UTC().Truncate(time.Hour)
		}
		if next.After(wm) {
			if err := d.setSetting(d.db, netEventRollupWatermarkKey, next.Format(time.RFC3339)); err != nil {
				return hours, days, fmt.Errorf("advance watermark: %w", err)
			}
			wm = next
		}
	}

	// Day close: a UTC day is closable once every one of its hours is folded
	// (its end is at or before the watermark) and the close lag has passed.
	cand, ok, err := d.netEventRollupClosedDay()
	if err != nil {
		return hours, days, err
	}
	if ok {
		cand = cand.AddDate(0, 0, 1)
	} else {
		start, found, err := oldestEligibleOn(d.db.Model(&models.NetEvent{}), "ts")
		if err != nil {
			return hours, days, fmt.Errorf("oldest net_event: %w", err)
		}
		if !found {
			return hours, days, nil
		}
		cand = utcDay(start)
	}
	for days < maxNetEventRollupDaysPerCycle {
		end := cand.AddDate(0, 0, 1)
		if end.After(wm) || end.Add(netEventRollupCloseLag).After(now) {
			break
		}
		if err := d.closeNetEventRollupDay(cand); err != nil {
			return hours, days, err
		}
		days++
		cand = end
	}
	return hours, days, nil
}

// netEventRollupGroup is one GROUP BY row of the rollup SELECT. LastTs is
// scanned as text because an aggregate loses the column's declared type (the
// SQLite driver hands back a string, Postgres a time that database/sql
// renders as RFC 3339 into a *string) — coerceDBTime reads both.
type netEventRollupGroup struct {
	Bucket      string
	DeviceID    uint
	RuleKey     string
	Action      int16
	Direction   int16
	AppCat      string
	Ruleset     string
	Hits        int64
	BytesIn     int64
	BytesOut    int64
	DistinctSrc int64
	LastTs      string
}

// selectNetEventRollupGroups groups net_events in [start, end) by the rollup
// key. The key columns are COALESCEd to the NOT NULL sentinels the rollup
// table stores (the empty string / 0) so a NULL and a sentinel never become two rows,
// and the SUMs are cast to BIGINT (Postgres sums bigint into numeric).
func (d *Database) selectNetEventRollupGroups(tx *gorm.DB, start, end time.Time) ([]netEventRollupGroup, error) {
	var groups []netEventRollupGroup
	err := tx.Raw(`SELECT `+d.dialect.TimeBucket("day", "ts")+` AS bucket, device_id,
			COALESCE(rule_key, '') AS rule_key, action, COALESCE(direction, 0) AS direction,
			COALESCE(app_cat, '') AS app_cat, COALESCE(ruleset, '') AS ruleset,
			COUNT(*) AS hits,
			CAST(COALESCE(SUM(bytes_in), 0) AS BIGINT) AS bytes_in,
			CAST(COALESCE(SUM(bytes_out), 0) AS BIGINT) AS bytes_out,
			COUNT(DISTINCT src_ip) AS distinct_src,
			MAX(ts) AS last_ts
		FROM net_events WHERE ts >= ? AND ts < ?
		GROUP BY 1, 2, 3, 4, 5, 6, 7`, start, end).Scan(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("group net_events [%s, %s): %w", start.Format(time.RFC3339), end.Format(time.RFC3339), err)
	}
	return groups, nil
}

// rollupRows turns GROUP BY rows into net_event_rollups rows; a group whose
// bucket or last_ts cannot be read is reported rather than written as a zero
// day (which would merge every bad group into one bogus row).
func rollupRows(groups []netEventRollupGroup) ([]models.NetEventRollup, error) {
	rows := make([]models.NetEventRollup, 0, len(groups))
	for _, g := range groups {
		day, err := time.Parse("2006-01-02", g.Bucket)
		if err != nil {
			return nil, fmt.Errorf("rollup bucket %q: %w", g.Bucket, err)
		}
		last, ok := coerceDBTime(g.LastTs)
		if !ok {
			return nil, fmt.Errorf("rollup last_ts %q: unreadable", g.LastTs)
		}
		rows = append(rows, models.NetEventRollup{
			Day: day, DeviceID: g.DeviceID, RuleKey: g.RuleKey, Action: g.Action, Direction: g.Direction,
			AppCat: g.AppCat, Ruleset: g.Ruleset, Hits: g.Hits, BytesIn: g.BytesIn, BytesOut: g.BytesOut,
			DistinctSrc: g.DistinctSrc, LastTs: last.UTC(),
		})
	}
	return rows, nil
}

// foldNetEventRollupHour upserts the hour [h, h+1h) into the rollups and
// advances the watermark to h+1h, in one transaction. Returns the number of
// groups the hour held.
func (d *Database) foldNetEventRollupHour(h time.Time) (int, error) {
	end := h.Add(time.Hour)
	n := 0
	err := d.db.Transaction(func(tx *gorm.DB) error {
		groups, err := d.selectNetEventRollupGroups(tx, h, end)
		if err != nil {
			return err
		}
		n = len(groups)
		if n > 0 {
			rows, err := rollupRows(groups)
			if err != nil {
				return err
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "day"}, {Name: "device_id"}, {Name: "rule_key"}, {Name: "action"},
					{Name: "direction"}, {Name: "app_cat"}, {Name: "ruleset"}},
				DoUpdates: clause.Assignments(map[string]interface{}{
					"hits":         gorm.Expr("net_event_rollups.hits + excluded.hits"),
					"bytes_in":     gorm.Expr("net_event_rollups.bytes_in + excluded.bytes_in"),
					"bytes_out":    gorm.Expr("net_event_rollups.bytes_out + excluded.bytes_out"),
					"distinct_src": gorm.Expr(d.dialect.Greatest("net_event_rollups.distinct_src", "excluded.distinct_src")),
					"last_ts":      gorm.Expr(d.dialect.Greatest("net_event_rollups.last_ts", "excluded.last_ts")),
				}),
			}).CreateInBatches(&rows, netEventRollupInsertBatch).Error; err != nil {
				return fmt.Errorf("upsert %d rollup rows for hour %s: %w", len(rows), h.Format(time.RFC3339), err)
			}
		}
		return d.setSetting(tx, netEventRollupWatermarkKey, end.Format(time.RFC3339))
	})
	return n, err
}

// closeNetEventRollupDay replaces the UTC day's rollup rows with an exact
// recompute from net_events and records the day as closed, in one transaction.
func (d *Database) closeNetEventRollupDay(day time.Time) error {
	end := day.AddDate(0, 0, 1)
	return d.db.Transaction(func(tx *gorm.DB) error {
		groups, err := d.selectNetEventRollupGroups(tx, day, end)
		if err != nil {
			return err
		}
		rows, err := rollupRows(groups)
		if err != nil {
			return err
		}
		if err := tx.Where("day = ?", day).Delete(&models.NetEventRollup{}).Error; err != nil {
			return fmt.Errorf("clear rollups for %s: %w", day.Format("2006-01-02"), err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, netEventRollupInsertBatch).Error; err != nil {
				return fmt.Errorf("write %d rollup rows for %s: %w", len(rows), day.Format("2006-01-02"), err)
			}
		}
		return d.setSetting(tx, netEventRollupClosedDayKey, day.Format("2006-01-02"))
	})
}

// netEventRollupWatermark reads the hour watermark; ok is false when unset.
func (d *Database) netEventRollupWatermark() (time.Time, bool, error) {
	v, ok := d.GetSettingValue(netEventRollupWatermarkKey)
	if !ok || v == "" {
		return time.Time{}, false, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("setting %s = %q: %w", netEventRollupWatermarkKey, v, err)
	}
	return t.UTC(), true, nil
}

// netEventRollupClosedDay reads the closed-day marker; ok is false when unset.
func (d *Database) netEventRollupClosedDay() (time.Time, bool, error) {
	v, ok := d.GetSettingValue(netEventRollupClosedDayKey)
	if !ok || v == "" {
		return time.Time{}, false, nil
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("setting %s = %q: %w", netEventRollupClosedDayKey, v, err)
	}
	return t, true, nil
}

// setSetting upserts one system_settings value on the given handle (a
// transaction, so the write commits with the work it records). A portable
// ON CONFLICT on the key's unique index — UpsertSetting's FirstOrCreate+Save
// is two round trips and not transaction-aware.
func (d *Database) setSetting(tx *gorm.DB, key, value string) error {
	row := models.SystemSetting{Key: key, Value: value, Type: "string", Category: "system", UpdatedAt: time.Now()}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&row).Error
}

// utcDay is the UTC midnight of t's UTC day.
func utcDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}
