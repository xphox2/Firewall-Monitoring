package database

import (
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Flow summary read path.
//
// This is what makes the 30-day and 90-day ranges answerable. Measured on
// production, a 90-day aggregate returns in **113 ms** from the summary against
// **31,595 ms** from flow_rollups — and that second number is the point, because
// it exceeds the 30 s statement_timeout. Those windows were not slow, they were
// impossible: every rolled-up panel was cancelled and the page fell back to the
// raw window, roughly an hour, under a 90-day label.
//
// Both paths return identical figures (342,031,562 flows / 3,949,471,419,102
// bytes / 7,079,816,102 packets over 90 days), which is also the proof that the
// two summary tiers are disjoint — an overlap would make the summary larger.

// flowSummaryMinHours is the window above which the summary is preferred.
//
// Below it the live path is exact and quick enough (the rolled-up panels run
// concurrently; 24 h completes in 9.5 s), and exactness is worth more than speed
// at the default range: the summary's top-N lists are approximate by
// construction while the live path's are not.
// It is a var, not a const, so tests can force either path and compare them —
// which is the only way to assert the two agree.
var flowSummaryMinHours = 24

// flowSummaryReadIntervals is every summary tier, always.
//
// Deliberately not mirrored on rollupIntervalsForWindow. The summary tiers are
// disjoint — a day's rows supersede the hourly rows covering it, and the hourly
// tier is floored at the daily tier's reach — so reading both and summing can
// neither gap nor double-count, whatever the window. A tier holding nothing in
// range simply contributes nothing. That is one less thing to keep in step as
// the promotion boundary moves.
var flowSummaryReadIntervals = []string{"1h", "1d"}

// flowSummaryCompatible reports whether a filter can be answered from the
// summary at all.
//
// The high-cardinality dimensions live in flow_summary_tops as per-bucket top-N
// lists, not as filterable columns, so a filter ON one of them cannot be
// honoured: a top-50 list cannot give the total for an address that fell below
// the cut in every bucket. Those requests keep the live path, where they still
// work for windows the live path can serve.
func flowSummaryCompatible(filter FlowStatsFilter) bool {
	return filter.SrcAddr == "" && filter.DstAddr == "" &&
		filter.DstPort == nil && filter.DstASN == nil
}

// flowSummaryDimensionFiltered reports whether the filter narrows one of the
// cube's own dimensions.
//
// The cube carries the full cross product of those columns, so the AGGREGATE
// panels honour any combination of them — including the protocol pill row. The
// top-N table does not carry them: its lists are computed per bucket across all
// protocols and categories. So when a dimension filter is present the top-talker
// panels must report degraded rather than show unfiltered talkers beside
// filtered totals, which would be a new way to mislead.
func flowSummaryDimensionFiltered(filter FlowStatsFilter) bool {
	return filter.Protocol != nil || filter.AppCategory != nil || filter.Direction != nil ||
		filter.DstCountry != "" || filter.FlowSource != nil || filter.FirewallEvent != nil
}

// summaryCoversWindow reports whether the summary reaches back far enough to
// answer a window starting at cutoff.
//
// This guard is the difference between "fast" and "quietly wrong". While the
// backfill is still running the summary's oldest bucket is later than the
// window start, and reading it would silently report a fraction of the range —
// the exact failure this whole programme exists to remove. The summary is only
// used when it demonstrably covers everything flow_rollups holds in the window.
func (d *Database) summaryCoversWindow(cutoff time.Time) bool {
	sumOldest, ok := d.summaryOldest()
	if !ok {
		return false // nothing summarised yet
	}
	if !sumOldest.After(cutoff) {
		return true // covers the whole window
	}
	// The summary starts after the cutoff. That is still complete if the rollups
	// have nothing older either (a young deployment), and wrong otherwise.
	rollOldest, _, ok, err := d.tierTimeBounds([]string{"5m", "1h", "1d"})
	if err != nil || !ok {
		return false
	}
	return !sumOldest.After(rollOldest)
}

// summaryOldest returns the oldest summary bucket across both tiers, probing
// each interval with an equality so the index's first-tuple stop applies (see
// tierTimeBounds for why an IN list is 1,650x worse on the rollup table).
func (d *Database) summaryOldest() (time.Time, bool) {
	var oldest time.Time
	found := false
	for _, iv := range flowSummaryReadIntervals {
		ts, ok, err := aggregateTimestamp(
			d.db.Session(&gorm.Session{}).Model(&models.FlowSummary{}).Where("interval_type = ?", iv),
			"MIN(timestamp)")
		if err != nil || !ok {
			continue
		}
		if !found || ts.Before(oldest) {
			oldest = ts
			found = true
		}
	}
	return oldest, found
}

// flowSummaryTopValues reads one high-cardinality panel: a window's top-N as a
// merge of per-bucket top-N lists.
//
// The merge is approximate — a value ranked just below the cut in EVERY bucket
// can never surface, however large its total. N is 50 precisely so that bound
// stays small; see flowSummaryTopN for the measured figures.
func flowSummaryTopValues(q *gorm.DB, dimension string, limit int) ([]KeyCount, error) {
	var rows []struct {
		Value string
		Total int64
	}
	err := q.Where("dimension = ? AND scope_local = ?", dimension, false).
		Select("value, COALESCE(SUM(bytes_sum),0) as total").
		Group("value").Order("total DESC").Order("value ASC").
		Limit(limit).Scan(&rows).Error
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Value, Count: r.Total})
	}
	return out, err
}

// applySummaryDeviceFilters writes the only filters the top-N and per-bucket
// tables can honour. They carry no dimension columns, so protocol, category,
// direction, country, source and event are deliberately absent here — a caller
// that needs those must not use these tables (see flowSummaryDimensionFiltered).
func applySummaryDeviceFilters(q *gorm.DB, filter FlowStatsFilter) *gorm.DB {
	if filter.DeviceID > 0 {
		q = q.Where("device_id = ?", filter.DeviceID)
	}
	if filter.SiteID > 0 {
		q = q.Where("device_id IN (SELECT id FROM devices WHERE site_id = ?)", filter.SiteID)
	}
	if filter.ProbeID > 0 {
		q = q.Where("device_id IN (SELECT id FROM devices WHERE probe_id = ?)", filter.ProbeID)
	}
	return q
}
