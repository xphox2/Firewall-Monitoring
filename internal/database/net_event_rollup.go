package database

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/metrics"
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
//     netEventRollupCloseLag old, the day is recomputed EXACTLY and its rows
//     replaced in one transaction, then recorded in the closed-day setting.
//     The recompute never issues one statement over the whole day — at
//     production volume (millions of rows per day) that is the GROUP BY shape
//     that blew the 30 s statement_timeout every cycle in syslog_agg.go. It
//     reads the day HOUR BY HOUR, each read a bounded transaction (120 s
//     statement_timeout, 5 s lock_timeout), and accumulates in memory: hits /
//     bytes / last_ts are exact by addition; distinct_src is exact by merging
//     each hour's (group, src_ip) set, up to netEventRollupDistinctBudget
//     pairs for the day — past that the day degrades to the hour folds' lower
//     bound and is flagged distinct_src_exact = false. Besides making
//     distinct_src exact, the close absorbs any row that arrived late for an
//     hour already folded (a collector replaying its backlog), so a closed day
//     is correct whatever the arrival order.
//
// A day whose close keeps failing (a read that cannot finish even hour by
// hour, a broken partition) must not pin the cursor forever: after
// netEventRollupCloseGiveUp consecutive failures the day is SKIPPED — its
// hour-fold rows stay as they are, the cursor advances, a WARNING is logged
// and fwmon_net_event_rollup_day_skips_total counts it. The cursor also never
// starts before the retention window (a stray row dated 2000 in the DEFAULT
// partition would otherwise put it ~9,500 days back) and jumps over days with
// no rows instead of closing them one cycle at a time.
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
	netEventRollupWatermarkKey = "net_event_rollup_watermark" // #nosec G101 -- a system_settings key name, not a credential
	// netEventRollupClosedDayKey holds the newest UTC day (YYYY-MM-DD) whose
	// rollup rows were recomputed exactly from its partition (or skipped).
	netEventRollupClosedDayKey = "net_event_rollup_closed_day"
	// netEventRollupCloseFailuresKey holds "YYYY-MM-DD:n": n consecutive
	// failed closes of that day. Persisted so a restart does not reset the
	// give-up count.
	netEventRollupCloseFailuresKey = "net_event_rollup_close_failures"
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
	// day closes, which read a day's rows each (hour by hour).
	maxNetEventRollupHoursPerCycle = 24
	maxNetEventRollupDaysPerCycle  = 2
	// netEventRollupDistinctBudget caps the per-hour (group, src_ip) GROUP BY
	// rows a day close reads before it stops merging distinct sources — a
	// source seen in several hours counts once per hour. Each retained entry
	// is a map key of ~100 bytes resident, so ~50 MB at the cap, plus the
	// transient scan of one hour's group rows. Past it the day keeps the hour
	// folds' lower bound.
	netEventRollupDistinctBudget = 500000
	// netEventRollupCloseGiveUp is the number of consecutive failed closes of
	// one day after which it is skipped (see the file comment). Failures
	// closer together than netEventRollupFailureSpacing count once, so a
	// transient outage spanning a few 5-minute ticks cannot spend the budget
	// by itself.
	netEventRollupCloseGiveUp    = 3
	netEventRollupFailureSpacing = 10 * time.Minute
	// netEventRollupInsertBatch sizes the rollup upsert INSERTs (14 columns;
	// well under the 65535-parameter limit). A var so a test can shrink it
	// to exercise the multi-statement path.
	netEventRollupInsertBatch = 500
	// netEventRollupCloseHook, when non-nil, runs before every hour read of a
	// day close and can fail it — the seam the give-up path is tested through.
	netEventRollupCloseHook func(day, hour time.Time) error
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
	// Nothing older than the retention window is rolled up: its leaf is being
	// dropped (or a stray in the DEFAULT child is being trimmed), and a stray
	// dated years back must not drag either cursor there.
	floor := utcDay(now).AddDate(0, 0, -d.partitionLookbackDays(partitionDef{"net_events", "ts"}))

	wm, ok, err := d.netEventRollupWatermark()
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		// First run: start at the oldest event's hour (MIN(ts) is the first
		// tuple of each leaf's (ts) index, merged — cheap however large the
		// table), no earlier than the retention floor.
		start, found, err := oldestEligibleOn(d.db.Model(&models.NetEvent{}).Where("ts >= ? AND ts < ?", floor, limit), "ts")
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
	// The candidate starts after the last closed day — never before the
	// retention floor — and jumps to the next day that has rows.
	cand, ok, err := d.netEventRollupClosedDay()
	if err != nil {
		return hours, days, err
	}
	if ok {
		cand = cand.AddDate(0, 0, 1)
	}
	if cand.Before(floor) {
		cand = floor
	}
	for days < maxNetEventRollupDaysPerCycle {
		next, found, err := oldestEligibleOn(d.db.Model(&models.NetEvent{}).Where("ts >= ?", cand), "ts")
		if err != nil {
			return hours, days, fmt.Errorf("next populated day: %w", err)
		}
		if !found {
			break
		}
		if nd := utcDay(next); nd.After(cand) {
			cand = nd
		}
		end := cand.AddDate(0, 0, 1)
		if end.After(wm) || end.Add(netEventRollupCloseLag).After(now) {
			break
		}
		if err := d.closeNetEventRollupDay(cand); err != nil {
			skipped, ferr := d.noteNetEventRollupCloseFailure(cand, now, err)
			if ferr != nil {
				return hours, days, ferr
			}
			if !skipped {
				return hours, days, err
			}
		}
		days++
		cand = end
	}
	return hours, days, nil
}

// netEventRollupGroup is one GROUP BY row of the rollup SELECTs. LastTs is
// scanned as text because an aggregate loses the column's declared type (the
// SQLite driver hands back a string, Postgres a time that database/sql
// renders as RFC 3339 into a *string) — coerceDBTime reads both. Src is set
// only by the per-source query of the day close.
type netEventRollupGroup struct {
	Bucket      string
	DeviceID    uint
	RuleKey     string
	Action      int16
	Direction   int16
	AppCat      string
	Ruleset     string
	Src         string
	Hits        int64
	BytesIn     int64
	BytesOut    int64
	DistinctSrc int64
	LastTs      string
}

// netRollupKey is the rollup table's natural key, as the accumulators index it.
type netRollupKey struct {
	bucket    string
	deviceID  uint
	ruleKey   string
	action    int16
	direction int16
	appCat    string
	ruleset   string
}

func (g netEventRollupGroup) key() netRollupKey {
	return netRollupKey{g.Bucket, g.DeviceID, g.RuleKey, g.Action, g.Direction, g.AppCat, g.Ruleset}
}

// rollupSelectHead is the shared SELECT list of both rollup reads: the key
// columns COALESCEd to the NOT NULL sentinels the rollup table stores (the
// empty string / 0) so a NULL and a sentinel can never become two rows.
func (d *Database) rollupSelectHead() string {
	return `SELECT ` + d.dialect.TimeBucket("day", "ts") + ` AS bucket, device_id,
			COALESCE(rule_key, '') AS rule_key, action, COALESCE(direction, 0) AS direction,
			COALESCE(app_cat, '') AS app_cat, COALESCE(ruleset, '') AS ruleset, `
}

// selectNetEventRollupGroups groups net_events in [start, end) by the rollup
// key with a per-window COUNT(DISTINCT src_ip). The SUMs are cast to BIGINT
// (Postgres sums bigint into numeric).
func (d *Database) selectNetEventRollupGroups(tx *gorm.DB, start, end time.Time) ([]netEventRollupGroup, error) {
	var groups []netEventRollupGroup
	err := tx.Raw(d.rollupSelectHead()+`
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

// selectNetEventRollupPairs is selectNetEventRollupGroups with src_ip in the
// key (as text; the empty string for NULL), the day close's exact-distinct
// read: merging the pairs of every hour of a day gives the day's distinct
// sources without one statement over the whole day.
func (d *Database) selectNetEventRollupPairs(tx *gorm.DB, start, end time.Time) ([]netEventRollupGroup, error) {
	var groups []netEventRollupGroup
	err := tx.Raw(d.rollupSelectHead()+`
			COALESCE(`+d.dialect.CastText("src_ip")+`, '') AS src,
			COUNT(*) AS hits,
			CAST(COALESCE(SUM(bytes_in), 0) AS BIGINT) AS bytes_in,
			CAST(COALESCE(SUM(bytes_out), 0) AS BIGINT) AS bytes_out,
			MAX(ts) AS last_ts
		FROM net_events WHERE ts >= ? AND ts < ?
		GROUP BY 1, 2, 3, 4, 5, 6, 7, 8`, start, end).Scan(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("group net_events by source [%s, %s): %w", start.Format(time.RFC3339), end.Format(time.RFC3339), err)
	}
	return groups, nil
}

// boundedRead runs fn in a transaction with the retention pass's statement
// discipline on Postgres (120 s statement_timeout over the DSN's 30 s, 5 s
// lock_timeout) — one hour of net_events per statement, never the day.
func (d *Database) boundedRead(fn func(tx *gorm.DB) error) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if err := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; err != nil {
				return err
			}
			if err := tx.Exec("SET LOCAL statement_timeout = '120s'").Error; err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// netRollupRow turns one GROUP BY row (its key columns and last_ts) into the
// rollup row shape; counters are filled by the caller.
func netRollupRow(g netEventRollupGroup) (models.NetEventRollup, error) {
	day, err := time.Parse("2006-01-02", g.Bucket)
	if err != nil {
		return models.NetEventRollup{}, fmt.Errorf("rollup bucket %q: %w", g.Bucket, err)
	}
	last, ok := coerceDBTime(g.LastTs)
	if !ok {
		return models.NetEventRollup{}, fmt.Errorf("rollup last_ts %q: unreadable", g.LastTs)
	}
	return models.NetEventRollup{
		Day: day, DeviceID: g.DeviceID, RuleKey: g.RuleKey, Action: g.Action, Direction: g.Direction,
		AppCat: g.AppCat, Ruleset: g.Ruleset, LastTs: last.UTC(),
	}, nil
}

// foldNetEventRollupHour upserts the hour [h, h+1h) into the rollups and
// advances the watermark to h+1h, in one transaction. Returns the number of
// groups the hour held.
func (d *Database) foldNetEventRollupHour(h time.Time) (int, error) {
	end := h.Add(time.Hour)
	n := 0
	err := d.boundedRead(func(tx *gorm.DB) error {
		groups, err := d.selectNetEventRollupGroups(tx, h, end)
		if err != nil {
			return err
		}
		n = len(groups)
		if n > 0 {
			rows := make([]models.NetEventRollup, 0, n)
			for _, g := range groups {
				r, err := netRollupRow(g)
				if err != nil {
					return err
				}
				r.Hits, r.BytesIn, r.BytesOut, r.DistinctSrc = g.Hits, g.BytesIn, g.BytesOut, g.DistinctSrc
				rows = append(rows, r)
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

// netRollupAcc accumulates one rollup key over a day's hours.
type netRollupAcc struct {
	row  models.NetEventRollup
	srcs map[string]struct{} // distinct sources while the exact budget holds
	hmax int64               // lower bound: the largest single-hour (or so-far) distinct count
}

// closeNetEventRollupDay recomputes the UTC day's rollup rows — hour by hour,
// never one statement over the whole day — and replaces the day's rows in
// one transaction, recording the day as closed. See the file comment for the
// distinct_src budget.
func (d *Database) closeNetEventRollupDay(day time.Time) error {
	end := day.AddDate(0, 0, 1)
	acc := map[netRollupKey]*netRollupAcc{}
	get := func(g netEventRollupGroup) (*netRollupAcc, error) {
		k := g.key()
		a, ok := acc[k]
		if !ok {
			r, err := netRollupRow(g)
			if err != nil {
				return nil, err
			}
			a = &netRollupAcc{row: r, srcs: map[string]struct{}{}}
			acc[k] = a
		}
		a.row.Hits += g.Hits
		a.row.BytesIn += g.BytesIn
		a.row.BytesOut += g.BytesOut
		if last, ok := coerceDBTime(g.LastTs); ok && last.After(a.row.LastTs) {
			a.row.LastTs = last.UTC()
		}
		return a, nil
	}
	exact := true
	pairs := 0
	for h := day; h.Before(end); h = h.Add(time.Hour) {
		if netEventRollupCloseHook != nil {
			if err := netEventRollupCloseHook(day, h); err != nil {
				return err
			}
		}
		var groups []netEventRollupGroup
		if err := d.boundedRead(func(tx *gorm.DB) error {
			var err error
			if exact {
				groups, err = d.selectNetEventRollupPairs(tx, h, h.Add(time.Hour))
			} else {
				groups, err = d.selectNetEventRollupGroups(tx, h, h.Add(time.Hour))
			}
			return err
		}); err != nil {
			return err
		}
		for _, g := range groups {
			a, err := get(g)
			if err != nil {
				return err
			}
			if exact {
				if g.Src != "" {
					a.srcs[g.Src] = struct{}{}
				}
			} else if g.DistinctSrc > a.hmax {
				a.hmax = g.DistinctSrc
			}
		}
		if exact {
			pairs += len(groups)
			if pairs > netEventRollupDistinctBudget {
				// Over budget: keep what the sets say so far as the lower
				// bound and read the remaining hours the cheap way.
				exact = false
				for _, a := range acc {
					if n := int64(len(a.srcs)); n > a.hmax {
						a.hmax = n
					}
					a.srcs = nil
				}
			}
		}
	}
	rows := make([]models.NetEventRollup, 0, len(acc))
	for _, a := range acc {
		if exact {
			a.row.DistinctSrc = int64(len(a.srcs))
		} else {
			a.row.DistinctSrc = a.hmax
		}
		a.row.DistinctSrcExact = exact
		rows = append(rows, a.row)
	}
	if !exact {
		log.Printf("WARNING: Net event rollup: day %s exceeded the %d-pair distinct_src budget; its distinct_src is the hour folds' lower bound (distinct_src_exact = false)",
			day.Format("2006-01-02"), netEventRollupDistinctBudget)
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("day = ?", day).Delete(&models.NetEventRollup{}).Error; err != nil {
			return fmt.Errorf("clear rollups for %s: %w", day.Format("2006-01-02"), err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, netEventRollupInsertBatch).Error; err != nil {
				return fmt.Errorf("write %d rollup rows for %s: %w", len(rows), day.Format("2006-01-02"), err)
			}
		}
		if err := d.setSetting(tx, netEventRollupClosedDayKey, day.Format("2006-01-02")); err != nil {
			return err
		}
		return tx.Where("\"key\" = ?", netEventRollupCloseFailuresKey).Delete(&models.SystemSetting{}).Error
	})
}

// noteNetEventRollupCloseFailure records one failed close of day at `now`.
// After netEventRollupCloseGiveUp counted failures of the SAME day — a
// failure within netEventRollupFailureSpacing of the previous counted one is
// not counted — it skips the day: the hour-fold rows stay (distinct_src_exact
// = false), the closed-day cursor advances past it, a WARNING is logged and
// the skip metric counts it. skipped reports whether that happened; err is a
// settings error only. The setting holds "YYYY-MM-DD:n:<RFC 3339 of the last
// counted failure>".
func (d *Database) noteNetEventRollupCloseFailure(day, now time.Time, cause error) (skipped bool, err error) {
	ds := day.Format("2006-01-02")
	n := 1
	if v, ok := d.GetSettingValue(netEventRollupCloseFailuresKey); ok {
		if parts := strings.SplitN(v, ":", 3); len(parts) == 3 && parts[0] == ds {
			c, cerr := strconv.Atoi(parts[1])
			last, terr := time.Parse(time.RFC3339, parts[2])
			if cerr == nil && terr == nil {
				if now.Sub(last) < netEventRollupFailureSpacing {
					log.Printf("Net event rollup: closing day %s failed again within %s of the last counted failure (%d/%d, not counted): %v",
						ds, netEventRollupFailureSpacing, c, netEventRollupCloseGiveUp, cause)
					return false, nil
				}
				n = c + 1
			}
		}
	}
	if n < netEventRollupCloseGiveUp {
		log.Printf("Net event rollup: closing day %s failed (%d/%d): %v", ds, n, netEventRollupCloseGiveUp, cause)
		return false, d.setSetting(d.db, netEventRollupCloseFailuresKey, fmt.Sprintf("%s:%d:%s", ds, n, now.UTC().Format(time.RFC3339)))
	}
	log.Printf("WARNING: Net event rollup: giving up on the exact recompute of day %s after %d failures (%v); its rollup rows keep the hour folds' values with distinct_src as a lower bound (distinct_src_exact = false)",
		ds, n, cause)
	metrics.IncNetEventRollupDaySkipped()
	err = d.db.Transaction(func(tx *gorm.DB) error {
		if err := d.setSetting(tx, netEventRollupClosedDayKey, ds); err != nil {
			return err
		}
		return tx.Where("\"key\" = ?", netEventRollupCloseFailuresKey).Delete(&models.SystemSetting{}).Error
	})
	return true, err
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
