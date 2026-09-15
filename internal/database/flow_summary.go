package database

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Flow summary writer.
//
// WHY A SEPARATE, IDEMPOTENT JOB rather than a write inside the rollup
// transaction (which is where an earlier design put it):
//
//   - Late data becomes exact. A collector replaying its store-and-forward
//     spool delivers rows with old timestamps — a path aggregateFlowsToRollup
//     explicitly designs for — so "each bucket is finished exactly once" is not
//     a property the ladder can promise. Because this job RECOMPUTES a bucket
//     from scratch rather than merging into it, re-running it on late data is
//     correct by construction. A merge-based top-N is lossy; a recompute is not.
//   - The rollup cycle visits each hour through roughly twelve partial windows
//     (its aggregation window is an hour but its cutoff is not bucket-aligned),
//     so a per-bucket top-N could never be computed in one pass inside that
//     callback.
//   - It keeps a bug out of the rollup ladder's critical path. That job has had
//     two production incidents; a defect here slows a page, not ingestion.
//
// The same function is also the backfill. That is the design's best property:
// one code path, exercised every cycle, rather than a migration that runs once
// and is never tested again.

// Summary dimensions for FlowSummaryTop. Values are stored as text so one table
// serves every high-cardinality dimension.
const (
	flowSummaryDimSrcAddr      = "src_addr"
	flowSummaryDimDstAddr      = "dst_addr"
	flowSummaryDimDstPort      = "dst_port"
	flowSummaryDimDstASN       = "dst_asn"
	flowSummaryDimConversation = "conversation"
)

// flowSummaryTopN is how many values are kept per bucket per dimension.
//
// This number is load-bearing and must not be lowered. A window's top-10 is a
// merge of per-bucket top-Ns, and the merge's error bound is the sum of each
// bucket's Nth value. Measured over 24h of hourly buckets on production:
//
//	dimension      bound@N=10   bound@N=50   true #10
//	src_addr        1,286 MB       10 MB      2,607 MB
//	conversation    1,565 MB       43 MB      2,023 MB
//	dst_port        1,094 MB       55 MB        562 MB
//
// At N=10 the port bound EXCEEDS the true #10 — a merged top-10 can be flatly
// wrong. At 50 it is roughly a tenth of it. Re-measure if traffic shape changes.
var flowSummaryTopN = 50

// flowSummaryRedoBuckets is how many already-summarised buckets at the leading
// edge are recomputed each cycle. Buckets do not stop changing the moment they
// are first summarised: late spool replay adds rows, and promotion moves a
// band between rollup tiers. Recomputing the most recent few absorbs both,
// which is only safe because recomputation is exact.
var flowSummaryRedoBuckets = 3

// flowSummaryMaxBucketsPerCycle bounds one pass so a cold start (six months of
// history to backfill) makes steady progress instead of monopolising the shared
// work lock.
//
// Sized against measured cost. One hourly bucket on production runs the cube in
// 81ms and each top-N query in ~37ms, so a bucket is roughly half a second all
// in; 48 of them is ~25s inside a 5-minute rollup tick. That is only the
// backfill's cost — production's retained history is about 885 buckets, so it
// catches up in under twenty cycles. Steady state does far less: just the
// leading edge redone (see flowSummaryRedoBuckets), about 1.5s per cycle.
//
// Each bucket commits in its own transaction, so a long pass never holds one
// long-running transaction open.
var flowSummaryMaxBucketsPerCycle = 48

// flowSummaryTier describes one rung: which rollup tiers feed it, and how wide
// its buckets are.
type flowSummaryTier struct {
	interval string   // the summary's own interval_type
	sources  []string // the flow_rollups interval_types that feed it
	width    time.Duration
	bucketOf func(time.Time) time.Time
}

// flowSummaryTiers mirrors the rollup ladder, which is what keeps the summary
// tiers disjoint without any promotion step of their own: the 5m and 1h rollup
// tiers hold the recent ~30 days and feed hourly summary rows; the 1d tier holds
// everything older and can only feed daily rows, because day-resolution source
// data cannot reconstruct hours.
//
// That last point is not a preference. On production the 1h rollup tier reaches
// back 28 days and the 1d tier covers the 165 days before it, so an hourly
// summary simply cannot be backfilled for most of the retained window.
var flowSummaryTiers = []flowSummaryTier{
	{
		interval: "1h",
		sources:  []string{"5m", "1h"},
		width:    time.Hour,
		bucketOf: func(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) },
	},
	{
		interval: "1d",
		sources:  []string{"1d"},
		width:    24 * time.Hour,
		bucketOf: func(t time.Time) time.Time {
			u := t.UTC()
			return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
		},
	},
}

// RunFlowSummaryCycle brings the flow summary up to date. Safe to call
// repeatedly; each bucket is recomputed from its source rows, so a partial or
// repeated run converges rather than accumulating.
//
// Returns true if it wrote anything, so the caller can tighten its schedule
// while a backfill is still catching up.
func (d *Database) RunFlowSummaryCycle() bool {
	wrote := false
	for _, tier := range flowSummaryTiers {
		n, err := d.summariseTier(tier)
		if err != nil {
			log.Printf("Flow summary: %s tier: %v (will resume next cycle)", tier.interval, err)
			continue
		}
		if n > 0 {
			log.Printf("Flow summary: wrote %d %s bucket(s)", n, tier.interval)
			wrote = true
		}
	}
	return wrote
}

// aggregateTimestamp runs a MIN/MAX timestamp aggregate and coerces the result.
//
// It exists because a plain Scan into time.Time does NOT work across both
// engines: SQLite returns timestamps as text, so the scan quietly yields the
// zero value and every caller concludes there is no data. coerceDBTime is the
// codebase's existing answer (see oldestEligibleTimestamp, which the rollup
// ladder uses for the same reason). ok is false when the aggregate is NULL,
// i.e. no rows matched.
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

// summariseTier finds the buckets this tier still owes and computes them.
func (d *Database) summariseTier(tier flowSummaryTier) (int, error) {
	// Where the source data starts and ends. Both go through aggregateTimestamp
	// rather than scanning straight into a time.Time: SQLite hands timestamps
	// back as text, so a direct scan yields the zero value and the whole cycle
	// silently does nothing. coerceDBTime is the existing fix for that, already
	// used by the rollup ladder's own window walk.
	srcBase := func() *gorm.DB {
		return d.db.Model(&models.FlowRollup{}).Where("interval_type IN ?", tier.sources)
	}
	minTS, ok, err := aggregateTimestamp(srcBase(), "MIN(timestamp)")
	if err != nil {
		return 0, fmt.Errorf("source start: %w", err)
	}
	if !ok {
		return 0, nil // no source rows for this tier
	}
	maxTS, ok, err := aggregateTimestamp(srcBase(), "MAX(timestamp)")
	if err != nil {
		return 0, fmt.Errorf("source end: %w", err)
	}
	if !ok {
		return 0, nil
	}

	// Resume from the newest bucket already summarised, stepping back a few so
	// late arrivals and tier promotions are picked up (see
	// flowSummaryRedoBuckets). With nothing summarised yet this starts at the
	// oldest source row, which is the backfill.
	start := tier.bucketOf(minTS)
	watermark, haveWatermark, err := aggregateTimestamp(
		d.db.Model(&models.FlowSummary{}).Where("interval_type = ?", tier.interval), "MAX(timestamp)")
	if err != nil {
		return 0, fmt.Errorf("watermark: %w", err)
	}
	if haveWatermark {
		redoFrom := tier.bucketOf(watermark).Add(-time.Duration(flowSummaryRedoBuckets) * tier.width)
		if redoFrom.After(start) {
			start = redoFrom
		}
	}

	// Include the bucket the newest source row falls in, even though it is still
	// filling.
	//
	// This is deliberate and it is what keeps the read path simple. If the
	// summary stopped at the last COMPLETE bucket, it would trail the rollup
	// tiers by up to a bucket, leaving a band covered by neither the summary nor
	// raw flow_samples — so a 90-day total would quietly disagree with the live
	// path by an hour of traffic. Covering the partial bucket makes the summary's
	// reach exactly equal to the rollup tiers' reach, so summary + raw is a
	// complete picture, the same two sources the live path unions.
	//
	// The partial bucket costs nothing to carry: flowSummaryRedoBuckets
	// recomputes the leading edge every cycle anyway, and recomputation is exact.
	end := tier.bucketOf(maxTS).Add(tier.width)

	written := 0
	for b := start; b.Before(end); b = b.Add(tier.width) {
		if written >= flowSummaryMaxBucketsPerCycle {
			break
		}
		if err := d.summariseBucket(tier, b); err != nil {
			return written, fmt.Errorf("bucket %s: %w", b.Format(time.RFC3339), err)
		}
		written++
	}
	return written, nil
}

// summariseBucket recomputes one bucket end to end, in one transaction.
//
// Delete-then-insert, deliberately: it is what makes the job idempotent. An
// upsert would have to merge, and a merged top-N is lossy — the values that fell
// below the cut in the first pass are gone, so a second pass could not restore
// them. Recomputing from the source rows always yields the same answer for the
// same input, whatever ran before.
func (d *Database) summariseBucket(tier flowSummaryTier, bucket time.Time) error {
	end := bucket.Add(tier.width)

	return d.db.Transaction(func(tx *gorm.DB) error {
		src := func() *gorm.DB {
			return tx.Model(&models.FlowRollup{}).
				Where("interval_type IN ? AND timestamp >= ? AND timestamp < ?", tier.sources, bucket, end)
		}

		for _, del := range []struct {
			model interface{}
			table string
		}{
			{&models.FlowSummary{}, "flow_summaries"},
			{&models.FlowSummaryTop{}, "flow_summary_tops"},
			{&models.FlowSummaryBucket{}, "flow_summary_buckets"},
		} {
			if err := tx.Where("interval_type = ? AND timestamp = ?", tier.interval, bucket).
				Delete(del.model).Error; err != nil {
				return fmt.Errorf("clear %s: %w", del.table, err)
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

		// A day's summary supersedes the hourly rows covering it. The rollup
		// ladder moves a band from the 1h tier to the 1d tier as it ages, so
		// without this the same period would be represented in BOTH summary
		// tiers and a 90-day read would double-count it. This mirrors the
		// ladder's own promotion-deletes-the-source rule, which is what keeps
		// the rollup tiers disjoint.
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
		SamplingBytes float64
	}
	const groupKey = "device_id, protocol, app_category, direction, scope_local, dst_country, flow_source, firewall_event"
	var rows []cubeRow
	if err := src().
		Select(groupKey + ", SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, " +
			"SUM(flow_count) as flow_count, SUM(sampling_rate_avg * bytes_sum) as sampling_bytes").
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
			SamplingBytes: r.SamplingBytes,
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

// writeSummaryTops stores per-bucket top-N for each high-cardinality dimension.
//
// Ranked by BYTES, because every panel these feed ranks by bytes. A dimension
// ranked by flow count would need its own rows.
func (d *Database) writeSummaryTops(tx *gorm.DB, src func() *gorm.DB, tier flowSummaryTier, bucket time.Time) error {
	// expr is the SQL that produces the dimension's value as text; skip is an
	// optional predicate excluding rows the panels never show.
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

	type topRow struct {
		DeviceID   uint
		ScopeLocal bool
		Value      string
		BytesSum   uint64
		PacketsSum uint64
		FlowCount  int64
	}
	// Top-N is PER (device, scope), not per bucket overall: the page shows
	// scope-local traffic and routed traffic in separate panels, so one combined
	// list would let multicast noise crowd out real talkers. The key set is the
	// same for every dimension, so it is read ONCE rather than per dimension.
	var keys []struct {
		DeviceID   uint
		ScopeLocal bool
	}
	if err := src().Select("device_id, scope_local").Group("device_id, scope_local").Scan(&keys).Error; err != nil {
		return fmt.Errorf("scan top keys: %w", err)
	}

	var out []models.FlowSummaryTop
	for _, dim := range dims {
		for _, k := range keys {
			var rows []topRow
			q := src().Where("device_id = ? AND scope_local = ?", k.DeviceID, k.ScopeLocal)
			if dim.skip != "" {
				q = q.Where(dim.skip)
			}
			if err := q.
				Select(dim.expr + " as value, SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count").
				Group(dim.expr).Order("bytes_sum DESC").Limit(flowSummaryTopN).Scan(&rows).Error; err != nil {
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
