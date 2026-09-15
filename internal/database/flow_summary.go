package database

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Flow summary writer.
//
// WHY A SEPARATE, IDEMPOTENT JOB rather than a write inside the rollup
// transaction:
//
//   - Late data becomes exact. A collector replaying its store-and-forward
//     spool delivers rows with old timestamps — a path aggregateFlowsToRollup
//     explicitly designs for — so "each bucket is finished exactly once" is not
//     a property the ladder can promise. Because this job RECOMPUTES a bucket
//     from scratch rather than merging into it, re-running it is correct by
//     construction. A merge-based top-N is lossy; a recompute is not.
//   - The rollup cycle visits each hour through roughly twelve partial windows,
//     so a per-bucket top-N could never be computed in one pass inside it.
//   - It keeps a bug out of the rollup ladder's critical path. That job has had
//     two production incidents; a defect here slows a page, not ingestion.
//
// The same function is also the backfill: one code path, exercised every cycle,
// rather than a migration that runs once and is never tested again.

// Summary dimensions for FlowSummaryTop.
const (
	flowSummaryDimSrcAddr      = "src_addr"
	flowSummaryDimDstAddr      = "dst_addr"
	flowSummaryDimDstPort      = "dst_port"
	flowSummaryDimDstASN       = "dst_asn"
	flowSummaryDimConversation = "conversation"
)

// flowSummaryTopN is how many values are kept per bucket per dimension.
//
// Load-bearing, and not to be lowered. A window's top-10 is a merge of
// per-bucket top-Ns, and the error bound is the sum of each bucket's Nth value.
// Measured over 24h of hourly buckets on production:
//
//	dimension      bound@N=10   bound@N=50   true #10
//	src_addr        1,286 MB       10 MB      2,607 MB
//	conversation    1,565 MB       43 MB      2,023 MB
//	dst_port        1,094 MB       55 MB        562 MB
//
// At N=10 the port bound EXCEEDS the true #10 — a merged top-10 can be flatly
// wrong. At 50 it is roughly a tenth of it. Re-measure if traffic shape changes.
var flowSummaryTopN = 50

// flowSummaryMaxCycleDuration bounds one pass by TIME, not bucket count.
//
// Bucket cost varies by more than an order of magnitude and the expensive ones
// are not the common ones: measured on production, an hourly bucket over ~160k
// source rows takes 1.26s, while a daily bucket over 2.1M rows takes 14.1s and
// the densest day (4.6M rows) approaches 30s on a cold cache. A cap counted in
// buckets therefore cannot bound the work; an earlier version allowed 48 per
// cycle, which on the daily tier is minutes.
var flowSummaryMaxCycleDuration = 60 * time.Second

// flowSummaryMaxDailyBucketsPerCycle additionally caps the daily tier, whose
// buckets are the expensive ones. Backfilling six months of daily buckets is a
// one-time cost and there is no hurry; starving the rest of the cycle is worse.
var flowSummaryMaxDailyBucketsPerCycle = 2

// flowSummaryBucketHook is a test-only injection point (see summariseBucket).
var flowSummaryBucketHook func(interval string, bucket time.Time) error

// flowSummaryWatermarkKeyPrefix names the per-tier progress marker. It stores
// the highest flow_rollups.id this tier has already accounted for.
//
// An id watermark, NOT "recompute the last few buckets". The redo-window
// approach only absorbed changes at the leading edge: a collector offline for
// five hours replays into buckets the walk has already passed and would never be
// revisited, so the summary silently kept the pre-replay figures. Because
// promotion INSERTS rows (5m→1h→1d), an id watermark also catches a band moving
// between tiers, wherever in history it lands. This is the same primitive the
// rollup ladder itself uses.
const flowSummaryWatermarkKeyPrefix = "flow_summary_watermark_"

// flowSummaryTier describes one rung of the summary ladder.
type flowSummaryTier struct {
	// interval is the summary's own interval_type.
	interval string
	// rangeSources decide which buckets this tier OWNS.
	rangeSources []string
	// sumSources decide what is aggregated INSIDE a bucket.
	//
	// These differ for the daily tier, and that difference is a data-loss fix.
	// The rollup ladder promotes 1h→1d with a cutoff that is not day-aligned, so
	// the boundary day is always PARTIALLY promoted. On production today,
	// 2026-08-16 holds 767 MB in the 1d tier (one midnight row) and 41 GB across
	// the 1h tier. A daily bucket that summed only the 1d tier would record 767 MB
	// for a 45 GB day and then delete the hourly rows covering it — losing 98% of
	// that day, permanently, and repeating for every new boundary day. Summing
	// every tier inside the bucket makes the daily row complete, which is what
	// makes superseding the hourly rows safe.
	sumSources []string
	width      time.Duration
	bucketOf   func(time.Time) time.Time
	maxPerPass int
}

// flowSummaryTiers mirrors the rollup ladder, which is what keeps the summary
// tiers disjoint. The hourly tier owns whatever is still at 5m/1h resolution;
// the daily tier owns whatever promotion has begun collapsing to days, and
// supersedes the hourly rows for those days.
var flowSummaryTiers = []flowSummaryTier{
	{
		interval:     "1h",
		rangeSources: []string{"5m", "1h"},
		sumSources:   []string{"5m", "1h"},
		width:        time.Hour,
		bucketOf:     func(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) },
		maxPerPass:   0, // time-bounded only
	},
	{
		interval:     "1d",
		rangeSources: []string{"1d"},
		sumSources:   []string{"5m", "1h", "1d"},
		width:        24 * time.Hour,
		bucketOf: func(t time.Time) time.Time {
			u := t.UTC()
			return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
		},
		maxPerPass: flowSummaryMaxDailyBucketsPerCycle,
	},
}

// RunFlowSummaryCycle brings the flow summary up to date. Safe to call
// repeatedly; each bucket is recomputed from its source rows, so a partial or
// repeated run converges rather than accumulating.
//
// Returns true if it wrote anything.
func (d *Database) RunFlowSummaryCycle() bool {
	deadline := time.Now().Add(flowSummaryMaxCycleDuration)

	// Where the daily tier's reach ends. Everything at or below this instant
	// belongs to the daily tier; the hourly tier must not claim it.
	//
	// Without this floor the two tiers fight over the boundary day forever: the
	// daily pass supersedes the hourly rows, and the next hourly pass writes them
	// straight back (the 1h rollup rows are still there), leaving BOTH tiers
	// holding the day so a reader summing them double-counts it.
	//
	// The daily tier runs FIRST for the same reason — it establishes the floor
	// and clears any hourly rows left over from before a day was promoted.
	var dailyFloor time.Time
	for _, tier := range flowSummaryTiers {
		if tier.interval != "1d" {
			continue
		}
		if _, newest, ok, err := d.tierTimeBounds(tier.rangeSources); err == nil && ok {
			dailyFloor = tier.bucketOf(newest).Add(tier.width)
		}
		// On error the floor stays zero and the hourly tier temporarily owns
		// everything. That is self-healing rather than harmful: the same rows
		// leave the daily tier's watermark unadvanced, so the next pass redirties
		// those days and the daily tier supersedes any hourly rows written in the
		// meantime. The exposure is one cycle of double-counting at worst.
	}

	ordered := []flowSummaryTier{}
	for _, t := range flowSummaryTiers {
		if t.interval == "1d" {
			ordered = append(ordered, t)
		}
	}
	for _, t := range flowSummaryTiers {
		if t.interval != "1d" {
			ordered = append(ordered, t)
		}
	}

	wrote := false
	for _, tier := range ordered {
		floor := time.Time{}
		if tier.interval != "1d" {
			floor = dailyFloor
		}
		n, err := d.summariseTier(tier, deadline, floor)
		if n > 0 {
			log.Printf("Flow summary: wrote %d %s bucket(s)", n, tier.interval)
			wrote = true
		}
		if err != nil {
			log.Printf("Flow summary: %s tier: %v (will resume next cycle)", tier.interval, err)
		}
	}
	return wrote
}

// aggregateTimestamp runs a MIN/MAX timestamp aggregate and coerces the result.
//
// A plain Scan into time.Time does NOT work across both engines: SQLite returns
// timestamps as text, so the scan quietly yields the zero value and every caller
// concludes there is no data. coerceDBTime is the codebase's existing answer
// (see oldestEligibleTimestamp). ok is false when the aggregate is NULL.
func aggregateTimestamp(q *gorm.DB, expr string) (time.Time, bool, error) {
	rows, err := q.Select(expr).Rows()
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return time.Time{}, false, rows.Err()
	}
	var raw any
	if err := rows.Scan(&raw); err != nil {
		return time.Time{}, false, err
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, false, err
	}
	ts, ok := coerceDBTime(raw)
	return ts, ok, nil
}

// tierTimeBounds returns the oldest and newest source timestamps for a tier.
//
// It probes each interval SEPARATELY with `=` rather than one `interval_type IN
// (...)` query, because the IN defeats the index's first-tuple stop:
// idx_rollup_interval_ts leads on interval_type, so an equality pins it and the
// scan stops at the first tuple, while an IN list forces a full index scan.
// Measured on production: the IN form takes 8,774ms, the four per-interval
// equality probes total 5.3ms — a difference of about 1,650x, and it would have
// run every five minutes forever. This is the exact planner trap the rollup
// ladder's own comments document.
func (d *Database) tierTimeBounds(intervals []string) (oldest, newest time.Time, ok bool, err error) {
	for _, iv := range intervals {
		base := func() *gorm.DB {
			return d.db.Session(&gorm.Session{}).Model(&models.FlowRollup{}).Where("interval_type = ?", iv)
		}
		lo, haveLo, e := aggregateTimestamp(base(), "MIN(timestamp)")
		if e != nil {
			return time.Time{}, time.Time{}, false, e
		}
		if !haveLo {
			continue
		}
		hi, _, e := aggregateTimestamp(base(), "MAX(timestamp)")
		if e != nil {
			return time.Time{}, time.Time{}, false, e
		}
		if !ok || lo.Before(oldest) {
			oldest = lo
		}
		if !ok || hi.After(newest) {
			newest = hi
		}
		ok = true
	}
	return oldest, newest, ok, nil
}

// flowSummaryFillKeyPrefix names the per-tier contiguous backfill marker: the
// newest bucket such that every bucket from the tier's start up to it has been
// summarised successfully. Distinct from the id watermark, which tracks CHANGES.
//
// Both markers live in system_settings under category "system", matching
// encryption_key_canary — this table is the codebase's key-value store, and the
// settings UI renders an explicit field list rather than iterating rows, so
// internal keys do not surface there.
const flowSummaryFillKeyPrefix = "flow_summary_filled_"

func (d *Database) summaryFillMarker(interval string) time.Time {
	v, ok := d.GetSettingValue(flowSummaryFillKeyPrefix + interval)
	if !ok || strings.TrimSpace(v) == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (d *Database) setSummaryFillMarker(interval string, at time.Time) {
	if err := d.UpsertSetting(&models.SystemSetting{
		Key:      flowSummaryFillKeyPrefix + interval,
		Value:    at.UTC().Format(time.RFC3339),
		Category: "system",
		Type:     "string",
		Label:    "Flow summary backfill marker (" + interval + ")",
	}); err != nil {
		log.Printf("Flow summary: persist %s fill marker: %v", interval, err)
	}
}

// flowSummaryDirtyKeyPrefix names the per-tier dirty cursor: how far through the
// CURRENT watermark epoch's dirty list this tier has got. Cleared whenever the
// epoch completes and the watermark moves on.
const flowSummaryDirtyKeyPrefix = "flow_summary_dirty_cursor_"

// summaryDirtyCursor returns how far the current epoch got, and the id ceiling
// that epoch was opened with. Both live in one setting as "<RFC3339>|<ceiling>".
//
// The ceiling is the half of this that is easy to miss and impossible to do
// without. An epoch's dirty list is "rows newer than the watermark"; if that were
// recomputed against a LIVE ceiling every pass, rows arriving mid-epoch would
// join the list behind the cursor and be skipped by it, and then be buried when
// the epoch finally completed and the watermark jumped to the new ceiling. Rows
// that arrive after an epoch opens must belong to the NEXT epoch, so the epoch's
// upper bound has to be pinned when it opens.
func (d *Database) summaryDirtyCursor(interval string) (at time.Time, ceiling int64, open bool) {
	v, ok := d.GetSettingValue(flowSummaryDirtyKeyPrefix + interval)
	if !ok || strings.TrimSpace(v) == "" {
		return time.Time{}, 0, false
	}
	parts := strings.SplitN(strings.TrimSpace(v), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, 0, false
	}
	c, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || c <= 0 {
		return time.Time{}, 0, false
	}
	// An epoch can be open with NO bucket completed yet; "" means exactly that.
	if parts[0] == "" {
		return time.Time{}, c, true
	}
	t, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return time.Time{}, c, true
	}
	return t.UTC(), c, true
}

func (d *Database) setSummaryDirtyCursor(interval string, at time.Time, ceiling int64) {
	val := "|" + strconv.FormatInt(ceiling, 10)
	if !at.IsZero() {
		val = at.UTC().Format(time.RFC3339) + "|" + strconv.FormatInt(ceiling, 10)
	}
	if err := d.UpsertSetting(&models.SystemSetting{
		Key:      flowSummaryDirtyKeyPrefix + interval,
		Value:    val,
		Category: "system",
		Type:     "string",
		Label:    "Flow summary dirty cursor (" + interval + ")",
	}); err != nil {
		log.Printf("Flow summary: persist %s dirty cursor: %v", interval, err)
	}
}

func (d *Database) clearSummaryDirtyCursor(interval string) {
	if _, _, open := d.summaryDirtyCursor(interval); !open {
		return
	}
	if err := d.UpsertSetting(&models.SystemSetting{
		Key:      flowSummaryDirtyKeyPrefix + interval,
		Value:    "",
		Category: "system",
		Type:     "string",
		Label:    "Flow summary dirty cursor (" + interval + ")",
	}); err != nil {
		log.Printf("Flow summary: clear %s dirty cursor: %v", interval, err)
	}
}

func (d *Database) summaryWatermark(interval string) int64 {
	return int64(d.GetIntSetting(flowSummaryWatermarkKeyPrefix+interval, 0))
}

func (d *Database) setSummaryWatermark(interval string, id int64) {
	if err := d.UpsertSetting(&models.SystemSetting{
		Key:      flowSummaryWatermarkKeyPrefix + interval,
		Value:    strconv.FormatInt(id, 10),
		Category: "system",
		Type:     "number",
		Label:    "Flow summary progress marker (" + interval + ")",
	}); err != nil {
		log.Printf("Flow summary: persist %s watermark: %v", interval, err)
	}
}

// summariseTier computes whatever this tier owes: first the buckets changed
// since the last pass (correctness), then unvisited history (backfill).
func (d *Database) summariseTier(tier flowSummaryTier, deadline time.Time, floor time.Time) (int, error) {
	// Capture the id ceiling BEFORE reading, so rows arriving mid-pass are picked
	// up next time rather than being skipped.
	//
	// This is safe because the pass holds an advisory lock and the rollup ladder
	// allocates its ids inside a transaction: an id becomes visible at commit, so
	// a ceiling taken here cannot straddle a half-written window. The ladder's own
	// watermark rests on the same property. It DOES depend on that lock — on
	// SQLite (tests) the lock is a no-op, which is acceptable because nothing runs
	// concurrently there.
	var ceiling int64
	if err := d.db.Session(&gorm.Session{}).Model(&models.FlowRollup{}).
		Select("COALESCE(MAX(id),0)").Scan(&ceiling).Error; err != nil {
		return 0, fmt.Errorf("id ceiling: %w", err)
	}
	watermark := d.summaryWatermark(tier.interval)

	written := 0
	var firstErr error
	// A bucket that fails must NOT stall the tier. An earlier version returned on
	// the first error, so a single poison bucket (a timeout, a constraint
	// violation) meant nothing after it was ever summarised — silently, behind
	// one log line. Record and move on.
	//
	// Be honest about the remaining cost: a PERMANENTLY failing bucket is retried
	// every cycle, everything after it is recomputed every cycle up to the time
	// bound, and firstErr pins the watermark so the dirty scan keeps widening.
	// That is a deliberate trade — loud and degrading beats silent and wrong —
	// but it is not free, and an operator seeing this log line repeatedly should
	// act on it.
	run := func(b time.Time) (keepGoing, succeeded bool) {
		if time.Now().After(deadline) {
			return false, false
		}
		if err := d.summariseBucket(tier, b); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bucket %s: %w", b.Format(time.RFC3339), err)
			}
			log.Printf("Flow summary: %s bucket %s failed, skipping: %v",
				tier.interval, b.Format(time.RFC3339), err)
			return true, false // keep going, but this bucket is NOT filled
		}
		written++
		return true, true
	}

	// Which buckets this tier OWNS, from its range sources alone. A tier must not
	// claim a bucket outside its range: the daily tier sums every rollup tier (so
	// its rows are complete) but it only owns days promotion has begun collapsing,
	// and it supersedes the hourly rows for the days it owns. Letting it claim a
	// day with no 1d rows at all would delete correct hourly rows and replace them
	// with a day-resolution copy for no reason.
	oldest, newest, ok, err := d.tierTimeBounds(tier.rangeSources)
	if err != nil {
		return written, fmt.Errorf("tier bounds: %w", err)
	}
	if !ok {
		// No source data for this tier yet. Still record that everything up to
		// the ceiling has been seen: otherwise the first pass after data DOES
		// appear starts its dirty scan from id 0.
		d.setSummaryWatermark(tier.interval, ceiling)
		return written, nil
	}
	ownedFrom := tier.bucketOf(oldest)
	// A lower tier's reach takes precedence: the hourly tier does not own days
	// the daily tier has already collapsed.
	if !floor.IsZero() && floor.After(ownedFrom) {
		ownedFrom = tier.bucketOf(floor)
	}
	ownedTo := tier.bucketOf(newest).Add(tier.width)
	if ownedTo.Before(ownedFrom) {
		return written, nil
	}
	owns := func(b time.Time) bool { return !b.Before(ownedFrom) && b.Before(ownedTo) }

	// ---- 1. buckets changed since the watermark ----
	//
	// Detection reads EVERY tier this bucket sums, not just the range sources:
	// late data replayed into the 1h tier must redirty a day the daily tier owns,
	// or that day silently keeps its pre-replay figures.
	dirtyComplete := true
	if watermark > 0 {
		// Open an epoch, or resume the one in progress. The epoch's ceiling is
		// pinned when it opens so rows arriving while it runs belong to the NEXT
		// epoch rather than joining this list behind the cursor.
		cursor, epochCeiling, open := d.summaryDirtyCursor(tier.interval)
		if !open {
			epochCeiling = ceiling
		}
		dirty, err := d.dirtyBuckets(tier, watermark, epochCeiling)
		if err != nil {
			return written, fmt.Errorf("dirty buckets: %w", err)
		}
		// The cursor is what makes a CAPPED dirty walk make progress. Holding the
		// watermark back on a truncated walk is necessary but not sufficient: the
		// next pass recomputes the same dirty list from the same watermark, so
		// without a cursor it reprocesses the first bucket every cycle and never
		// reaches the rest. The list is ordered oldest-first, so remembering how
		// far the epoch got is enough.
		lastDone := cursor
		cursorContiguous := true
		for _, b := range dirty {
			// A bucket outside this tier's range is not this tier's problem, but
			// it HAS been seen — it must not hold the watermark back.
			if !owns(b) {
				continue
			}
			if !cursor.IsZero() && !b.After(cursor) {
				continue // already handled earlier in this epoch
			}
			if tier.maxPerPass > 0 && written >= tier.maxPerPass {
				dirtyComplete = false
				break
			}
			keepGoing, ok := run(b)
			// CONTIGUOUS, like the backfill loop. Advancing lastDone past a
			// failure would drop the failed bucket below the cursor, where the
			// next pass skips it — and because it was skipped rather than run,
			// firstErr is clear, the epoch completes, and the watermark buries
			// it. Stopping the cursor at the first failure keeps it above the
			// line so it is retried.
			if ok && cursorContiguous {
				lastDone = b
			} else if !ok {
				cursorContiguous = false
			}
			if !keepGoing {
				dirtyComplete = false
				break
			}
		}
		if dirtyComplete {
			// The epoch is done. Advance the watermark to the epoch's PINNED
			// ceiling, not the live one — anything newer arrived mid-epoch and
			// must stay dirty for the next one.
			if firstErr == nil {
				ceiling = epochCeiling
			}
			d.clearSummaryDirtyCursor(tier.interval)
		} else {
			d.setSummaryDirtyCursor(tier.interval, lastDone, epochCeiling)
		}
	}

	// ---- 2. backfill any history never visited ----
	//
	// Resume from a CONTIGUOUS fill marker, not from MAX(summary timestamp).
	// Using the max meant a bucket that failed while a later one succeeded was
	// never revisited: the max jumped past it and the walk resumed beyond the
	// gap, leaving a permanent hole in the middle of history that nothing would
	// ever notice. The marker advances only through unbroken successes, so a
	// failed bucket is retried every cycle while later buckets still progress.
	{
		filled := d.summaryFillMarker(tier.interval)
		// Self-heal if the summary was emptied underneath us. MAX(summary
		// timestamp) used to re-backfill automatically after a TRUNCATE or a
		// failed migration; a persisted marker does not, so a cleared table would
		// be a permanent hole up to the marker. One cheap existence check buys
		// that back.
		if !filled.IsZero() {
			var any int64
			if err := d.db.Session(&gorm.Session{}).Model(&models.FlowSummary{}).
				Where("interval_type = ?", tier.interval).Limit(1).Count(&any).Error; err == nil && any == 0 {
				log.Printf("Flow summary: %s tier has a fill marker but no rows; restarting its backfill", tier.interval)
				filled = time.Time{}
			}
		}
		start := ownedFrom
		if !filled.IsZero() {
			if next := tier.bucketOf(filled).Add(tier.width); next.After(start) {
				start = next
			}
		}
		// ownedTo includes the bucket the newest source row falls in, partial
		// though it is: that makes the summary's reach equal the rollup tiers'
		// reach, so a reader needs only summary + raw with no band belonging to
		// neither.
		contiguous := true
		newFilled := filled
		for b := start; b.Before(ownedTo); b = b.Add(tier.width) {
			if tier.maxPerPass > 0 && written >= tier.maxPerPass {
				break
			}
			keepGoing, ok := run(b)
			if ok && contiguous {
				newFilled = b
			}
			if !ok {
				contiguous = false
			}
			if !keepGoing {
				break
			}
		}
		if newFilled.After(filled) {
			d.setSummaryFillMarker(tier.interval, newFilled)
		}
	}

	// Advance the watermark whenever this pass SAW everything up to the ceiling
	// and nothing failed — not merely when it wrote something.
	//
	// Keying it on `written > 0` leaked: the daily tier sees a stream of new 5m
	// rows for today, owns none of them, writes nothing, and so never advanced.
	// Its dirty scan then grew without bound, re-reading the same ever-larger id
	// range every five minutes forever. Conversely, advancing after a TRUNCATED
	// dirty pass (hit the per-tier cap or the time bound) would drop the buckets
	// it did not reach, so both conditions have to hold.
	if firstErr == nil && dirtyComplete {
		d.setSummaryWatermark(tier.interval, ceiling)
	}
	return written, firstErr
}

// dirtyBuckets lists the buckets touched by rows newer than the watermark.
func (d *Database) dirtyBuckets(tier flowSummaryTier, watermark, ceiling int64) ([]time.Time, error) {
	var stamps []time.Time
	rows, err := d.db.Session(&gorm.Session{}).Model(&models.FlowRollup{}).
		Where("interval_type IN ? AND id > ? AND id <= ?", tier.sumSources, watermark, ceiling).
		Select("DISTINCT timestamp").Order("timestamp ASC").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[time.Time]bool{}
	for rows.Next() {
		var raw any
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		ts, ok := coerceDBTime(raw)
		if !ok {
			continue
		}
		b := tier.bucketOf(ts)
		if !seen[b] {
			seen[b] = true
			stamps = append(stamps, b)
		}
	}
	return stamps, rows.Err()
}

// summariseBucket recomputes one bucket end to end, in one transaction.
//
// Delete-then-insert, deliberately: it is what makes the job idempotent. An
// upsert would have to merge, and a merged top-N is lossy — values that fell
// below the cut in the first pass are gone, so a second pass could not restore
// them. Recomputing from the source rows yields the same answer for the same
// input, whatever ran before.
func (d *Database) summariseBucket(tier flowSummaryTier, bucket time.Time) error {
	// Test seam. A permanently-failing bucket is the case that used to leave a
	// silent hole in history, and there is no other way to provoke one
	// deterministically. Nil in production.
	if flowSummaryBucketHook != nil {
		if err := flowSummaryBucketHook(tier.interval, bucket); err != nil {
			return err
		}
	}
	end := bucket.Add(tier.width)

	return d.db.Transaction(func(tx *gorm.DB) error {
		src := func() *gorm.DB {
			return tx.Model(&models.FlowRollup{}).
				Where("interval_type IN ? AND timestamp >= ? AND timestamp < ?", tier.sumSources, bucket, end)
		}

		for _, m := range []interface{}{&models.FlowSummary{}, &models.FlowSummaryTop{}, &models.FlowSummaryBucket{}} {
			if err := tx.Where("interval_type = ? AND timestamp = ?", tier.interval, bucket).Delete(m).Error; err != nil {
				return fmt.Errorf("clear bucket: %w", err)
			}
		}

		if err := d.writeSummaryCube(tx, src, tier, bucket); err != nil {
			return err
		}
		if err := d.writeSummaryBucketScalars(tx, src, tier, bucket); err != nil {
			return err
		}
		if err := d.writeSummaryTops(tx, src, tier, bucket); err != nil {
			return err
		}

		// A day's summary supersedes the hourly rows covering it, mirroring the
		// ladder's own promotion-deletes-the-source rule — which is what keeps
		// the two summary tiers disjoint so a reader can sum them.
		//
		// Safe ONLY because the daily bucket sums every rollup tier (see
		// flowSummaryTier.sumSources): the day it replaces them with is complete,
		// including the hours still sitting in the 1h tier.
		if tier.interval == "1d" {
			for _, m := range []interface{}{&models.FlowSummary{}, &models.FlowSummaryTop{}, &models.FlowSummaryBucket{}} {
				if err := tx.Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", bucket, end).
					Delete(m).Error; err != nil {
					return fmt.Errorf("supersede hourly rows: %w", err)
				}
			}
		}
		return nil
	})
}

// writeSummaryCube materialises the low-cardinality cross product.
func (d *Database) writeSummaryCube(tx *gorm.DB, src func() *gorm.DB, tier flowSummaryTier, bucket time.Time) error {
	type cubeRow struct {
		DeviceID      uint
		Protocol      uint8
		AppCategory   uint8
		Direction     uint8
		ScopeLocal    bool
		DstCountry    string
		FlowSource    uint8
		FirewallEvent uint8
		BytesSum      uint64
		PacketsSum    uint64
		FlowCount     int64
	}
	// COALESCE on dst_country is not cosmetic: the column is nullable, so NULL
	// and '' group separately while GORM scans both into a Go string as "". The
	// two rows then collide on idx_flow_summary_key and the whole bucket fails
	// to write.
	const country = "COALESCE(dst_country, '')"
	groupKey := "device_id, protocol, app_category, direction, scope_local, " + country + ", flow_source, firewall_event"
	var rows []cubeRow
	if err := src().
		Select("device_id, protocol, app_category, direction, scope_local, " + country + " as dst_country, flow_source, firewall_event, " +
			"SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count").
		Group(groupKey).Scan(&rows).Error; err != nil {
		return fmt.Errorf("scan cube: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	out := make([]models.FlowSummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.FlowSummary{
			Timestamp: bucket, IntervalType: tier.interval, DeviceID: r.DeviceID,
			Protocol: r.Protocol, AppCategory: r.AppCategory, Direction: r.Direction,
			ScopeLocal: r.ScopeLocal, DstCountry: r.DstCountry,
			FlowSource: r.FlowSource, FirewallEvent: r.FirewallEvent,
			BytesSum: r.BytesSum, PacketsSum: r.PacketsSum, FlowCount: r.FlowCount,
		})
	}
	return tx.CreateInBatches(out, 500).Error
}

// writeSummaryBucketScalars stores the per-bucket figures neither other shape
// can express: exact distinct address counts, and the sampling range.
func (d *Database) writeSummaryBucketScalars(tx *gorm.DB, src func() *gorm.DB, tier flowSummaryTier, bucket time.Time) error {
	type scalarRow struct {
		DeviceID    uint
		ScopeLocal  bool
		DistinctSrc int64
		DistinctDst int64
		SamplingMin float64
		SamplingMax float64
	}
	var rows []scalarRow
	if err := src().
		Select("device_id, scope_local, " +
			"COUNT(DISTINCT src_addr) as distinct_src, COUNT(DISTINCT dst_addr) as distinct_dst, " +
			"COALESCE(MIN(NULLIF(sampling_rate_avg,0)),0) as sampling_min, " +
			"COALESCE(MAX(sampling_rate_avg),0) as sampling_max").
		Group("device_id, scope_local").Scan(&rows).Error; err != nil {
		return fmt.Errorf("scan bucket scalars: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	out := make([]models.FlowSummaryBucket, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.FlowSummaryBucket{
			Timestamp: bucket, IntervalType: tier.interval, DeviceID: r.DeviceID,
			ScopeLocal: r.ScopeLocal, DistinctSrc: r.DistinctSrc, DistinctDst: r.DistinctDst,
			SamplingRateMin: r.SamplingMin, SamplingRateMax: r.SamplingMax,
		})
	}
	return tx.CreateInBatches(out, 500).Error
}

// writeSummaryTops stores per-bucket top-N for each high-cardinality dimension,
// ranked by bytes because every panel these feed ranks by bytes.
//
// KNOWN LIMITATION, which the reader must respect: these lists carry no
// dimension columns, so they answer "top talkers for this device" and nothing
// narrower. "Top sources for TCP" or "top ports to Germany" cannot be served
// from here — a reader applying a cube filter must report these panels as
// degraded rather than show unfiltered talkers beside filtered totals.
func (d *Database) writeSummaryTops(tx *gorm.DB, src func() *gorm.DB, tier flowSummaryTier, bucket time.Time) error {
	dims := []struct {
		name string
		expr string
		skip string
	}{
		{flowSummaryDimSrcAddr, "src_addr", "src_addr <> ''"},
		{flowSummaryDimDstAddr, "dst_addr", "dst_addr <> ''"},
		{flowSummaryDimDstPort, d.dialect.CastText("dst_port"), "dst_port > 0"},
		{flowSummaryDimDstASN, d.dialect.CastText("dst_asn"), "dst_asn <> 0"},
		{flowSummaryDimConversation,
			d.dialect.Concat("src_addr", "'|'", "dst_addr", "'|'", d.dialect.CastText("dst_port"), "'|'", d.dialect.CastText("protocol")),
			"src_addr <> '' AND dst_addr <> ''"},
	}

	// The key set is identical for every dimension, so read it once.
	var keys []struct {
		DeviceID   uint
		ScopeLocal bool
	}
	if err := src().Select("device_id, scope_local").Group("device_id, scope_local").Scan(&keys).Error; err != nil {
		return fmt.Errorf("scan top keys: %w", err)
	}

	type topRow struct {
		Value      string
		BytesSum   uint64
		PacketsSum uint64
		FlowCount  int64
	}
	var out []models.FlowSummaryTop
	for _, dim := range dims {
		for _, k := range keys {
			var rows []topRow
			q := src().Where("device_id = ? AND scope_local = ?", k.DeviceID, k.ScopeLocal)
			if dim.skip != "" {
				q = q.Where(dim.skip)
			}
			// The secondary sort on value makes a tie at position N resolve the
			// same way every run, so two recomputes of identical input produce
			// identical rows — which "idempotent" has to mean.
			if err := q.
				Select(dim.expr + " as value, SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count").
				Group(dim.expr).Order("bytes_sum DESC").Order("value ASC").
				Limit(flowSummaryTopN).Scan(&rows).Error; err != nil {
				return fmt.Errorf("scan top %s: %w", dim.name, err)
			}
			for _, r := range rows {
				out = append(out, models.FlowSummaryTop{
					Timestamp: bucket, IntervalType: tier.interval, DeviceID: k.DeviceID,
					ScopeLocal: k.ScopeLocal, Dimension: dim.name, Value: r.Value,
					BytesSum: r.BytesSum, PacketsSum: r.PacketsSum, FlowCount: r.FlowCount,
				})
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return tx.CreateInBatches(out, 500).Error
}
