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
// The tiers are disjoint — a day's rows supersede the hourly rows covering it,
// and the hourly tier is floored at the daily tier's reach — so reading both and
// summing can neither gap nor double-count, whatever the window. A tier holding
// nothing in range simply contributes nothing. That is one less thing to keep in
// step as the promotion boundary moves.
//
// The rollup reader deliberately does NOT do this (see rollupIntervalsForWindow
// in flows.go): there, a wider interval_type IN list inflates PostgreSQL's row
// estimate enough to flip a 118M-row table onto a seq scan. Here the whole
// summary is ~635k rows across both tiers, so the same widening costs nothing.
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
		filter.DstPort == nil && filter.ServicePort == nil && filter.DstASN == nil
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
		// A tier whose source rows all fall below the summary's retention
		// window owns nothing (see summaryRetentionFloor) and so never builds a
		// marker; it has nothing to backfill either.
		if retained, ok := d.summaryRetentionFloor(tier, time.Now()); ok && retained.After(lastOwned) {
			continue
		}
		filled := d.summaryFillMarker(tier.interval)
		if filled.IsZero() || filled.Before(lastOwned) {
			return false
		}
	}
	return true
}

// summaryCoversCutoff reports whether the summary holds every bucket a window
// starting at cutoff reads, which summaryBackfillComplete alone does not say.
//
// The fill markers prove the summary is contiguous from each tier's low marker
// (flowSummaryFillFromKeyPrefix) UP to its fill marker; summaryBackfillComplete
// checks the top, this checks the bottom. That bottom moves: the summariser
// owns nothing below FlowSummaryRetentionKey and cleanup prunes to it, so with
// a 30-day window on the summary a 90-day request would have read 30 days of
// history under a 90-day label — silently, since nothing else would hint at
// it. A window the summary does not reach falls back to the live rollup path,
// which is slow but right.
//
// A tier is compared at its own width: summary rows are stamped at bucket
// START and readers use `timestamp > cutoff`, so the first bucket a window
// reads is the one AFTER the bucket the cutoff falls in. Coverage is exact at
// that boundary: a 30-day window on a 30-day retention is served (the
// straddling bucket is outside the window on both paths), a 31-day one is not.
//
// A tier still walking a span it has newly acquired (flowSummaryAcquiringKeyPrefix)
// is half-built below its low marker — the dirty walk may already have written
// there and superseded the other tier's rows — so a window reaching below that
// marker is not served, whatever the other tier holds. Otherwise the summary
// covers the window when some tier's reliable range reaches it, or when the
// summary starts where the DATA starts — a young installation, or a window
// wider than the rollups' own history; only that last case probes the rollup
// tiers, so a window the markers answer costs nothing more than the settings
// reads.
func (d *Database) summaryCoversCutoff(cutoff time.Time) bool {
	var lowest time.Time
	var lowestBucketOf func(time.Time) time.Time
	anyReaches := false
	for _, tier := range flowSummaryTiers {
		from := d.summaryFillFromMarker(tier.interval)
		if from.IsZero() {
			continue
		}
		reaches := !from.After(tier.bucketOf(cutoff).Add(tier.width))
		if !reaches && d.summaryAcquiring(tier.interval) {
			return false
		}
		if reaches {
			anyReaches = true
		}
		if lowestBucketOf == nil || from.Before(lowest) {
			lowest, lowestBucketOf = from, tier.bucketOf
		}
	}
	if lowestBucketOf == nil {
		return false
	}
	if anyReaches {
		return true
	}
	seen := map[string]bool{}
	for _, tier := range flowSummaryTiers {
		for _, iv := range tier.rangeSources {
			if seen[iv] {
				continue
			}
			seen[iv] = true
			t, ok, err := aggregateTimestamp(
				d.db.Session(&gorm.Session{}).Model(&models.FlowRollup{}).Where("interval_type = ?", iv),
				"MIN(timestamp)")
			if err != nil {
				return false
			}
			if ok && lowestBucketOf(t).Before(lowest) {
				return false
			}
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
