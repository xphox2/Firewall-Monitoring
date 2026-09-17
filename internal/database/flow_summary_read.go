package database

import (
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
// 48, not 24, and the extra day is a correctness boundary rather than caution.
// Summary rows are stamped at bucket START, so a `timestamp > cutoff` predicate
// drops the bucket the cutoff falls inside. Below 48 hours the live path reads
// the 5-minute rollup tier and truncates at a 5-minute boundary, while the
// summary can only truncate at an hour — measured on production, a 48-hour
// window came out 1.1 GB short for exactly that reason. Above 48 hours the
// cutoff lands in the hourly or daily rollup band and both paths truncate at the
// same boundary, so they agree exactly (verified at 7d and 90d on production).
//
// Below the threshold the live path is also quick enough: 24 h completes in
// 9.5 s, and its top-N lists are exact where the summary's are a per-bucket
// merge.
//
// A var, not a const, so tests can force either path and compare them — which is
// the only way to assert the two agree.
var flowSummaryMinHours = 48

// flowSummaryReadIntervals is every summary tier, always.
//
// Same shape as flowRollupReadIntervals, and for the same reason. The tiers are
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

// summaryBackfillComplete reports whether every summary tier has finished its
// initial walk, which is the only honest basis for reading the summary at all.
//
// An earlier version compared the summary's OLDEST bucket against the window's
// cutoff and called that coverage. It does not work, and it fails in the
// direction that matters: the backfill walks oldest-first, so after its very
// first cycle the summary's oldest bucket already equals the rollups' oldest and
// the check passes while nearly all of history is still missing. Measured in a
// harness: ten days of source, one cycle, and a 45-day window reported 2,001
// bytes against 10,001 — a fifth of the truth, not degraded, silently. That is
// precisely the failure this guard exists to prevent.
//
// The right signal was already there. summariseTier maintains a CONTIGUOUS fill
// marker per tier (see flowSummaryFillKeyPrefix) that advances only through
// unbroken successes; a tier is caught up when its marker has reached its newest
// owned bucket. Requiring both tiers is deliberately conservative — no summary
// reads until the whole thing is built — because a wrong number served quickly
// is worse than a right one served slowly, which is the defect this entire
// programme exists to remove.
func (d *Database) summaryBackfillComplete() bool {
	for _, tier := range flowSummaryTiers {
		_, newest, ok, err := d.tierTimeBounds(tier.rangeSources)
		if err != nil {
			return false
		}
		if !ok {
			continue // this tier has no source data, so nothing to backfill
		}
		lastOwned := tier.bucketOf(newest)
		filled := d.summaryFillMarker(tier.interval)
		if filled.IsZero() || filled.Before(lastOwned) {
			return false
		}
	}
	return true
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
