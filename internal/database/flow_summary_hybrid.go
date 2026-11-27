package database

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The hybrid read: a window of 7 to 48 hours answered from the hourly summary
// for its whole hours, and from 5-minute rollup rows only at its two edges.
//
// WHY. The default Flows window is 24 hours. Below flowSummaryMinHours the
// page read every 5-minute rollup row in the window — about two million on a
// busy install — and measured 14-21 s against a 20 s budget. The summary could
// not simply be used instead, for two reasons this file exists to remove:
//
//  1. The OLD edge. Summary rows are stamped at the start of their hour, so a
//     `timestamp > cutoff` over the summary drops the whole hour the cutoff
//     falls in, where the 5-minute tier truncates at a 5-minute boundary
//     (measured: 1.1 GB short at 48 h). The HEAD arm reads that one hour from
//     the 5-minute rows, exactly as the live read does.
//
//  2. The NEW edge. A rollup cycle commits its rows before the summariser has
//     folded them in, and a summariser that is behind has not folded in more.
//     The TAIL arm reads from the 5-minute rows every hour the summary has not
//     accounted for — found from the summariser's own watermark, see
//     flowHybridPlan.
//
// Between the two, the MIDDLE is the hourly summary.
//
//	cutoff        headEnd                         tailStart            now
//	  |--- head ---|----------- middle ------------|------ tail ------|- raw -|
//	  5m rollups     hourly summary                  5m rollups         samples
//
// The arms partition the window by timestamp, so no row is read twice.
//
// One thing it does not close: a row that is INGESTED and rolled up into a
// middle hour after this request's raw read, before its panels run. The live
// read would count it (its rollup query has no upper bound); this read does
// not, as if the row had arrived a moment after the request — which it did.
// A row that was already in raw samples when the request read them is counted
// there, once, however the rollup cycle moves it afterwards.
//
// It is all-or-nothing per request and it FAILS CLOSED: when the plan cannot
// show that the middle is current, the request runs the live read's own
// queries instead (the panel bases dispatch on the plan; see flowStats), and
// says so in ServedFrom / SummaryBypassReason. There is no partial use.

// FlowServedHybrid is FlowStatsResult.ServedFrom for this read.
const FlowServedHybrid = "hybrid"

// Reasons a hybrid-eligible window was read live (SummaryBypassReason). Fixed
// strings: they are served to browsers and must never carry an error's text.
const (
	flowHybridRefusedSettings  = "summary state unreadable"
	flowHybridRefusedNotBuilt  = "summary not built"
	flowHybridRefusedBacklog   = "summary more than one pass behind the rollups"
	flowHybridRefusedProbe     = "summary state could not be checked"
	flowHybridRefusedNoRollups = "rollups do not reach the window"
	flowHybridRefusedTail      = "rows not yet summarised several hours back"
	flowHybridRefusedRebuild   = "summary being rebuilt"
	flowHybridRefusedRetention = "summary retention shorter than the window"
)

// flowHybridMinHours: at or below this the chart uses 5-minute buckets (see
// bucketUnit in flowStats), which an hourly summary cannot draw.
const flowHybridMinHours = 6

// flowHybridMaxTail bounds how much of the window the tail may cover, measured
// on rollup stamps (newest hour's end minus tailStart), not to the wall clock.
// In normal running the tail is the still-filling hour and sometimes the one
// before it. A tail of many hours means the summariser is behind, and a tail
// that long is just the live read with extra steps.
var flowHybridMaxTail = 3 * time.Hour

// flowHybridMinRetentionDays: summary retention below this could delete hourly
// rows inside a 48-hour window (cleanup works in whole days).
const flowHybridMinRetentionDays = 3

// flowHybridEnabled switches the hybrid read off; a test knob, also the one
// place to disable the read if it ever has to be.
var flowHybridEnabled = true

// Test-only injection points.
var (
	// flowStatsBeforeRawHook runs before flowStats issues its first query.
	flowStatsBeforeRawHook func()
	// flowHybridPlanHook runs at the start of the plan; an error is treated
	// as one of the plan's own queries failing.
	flowHybridPlanHook func() error
	// flowStatsJobHook runs before a rolled-up panel's query; an error fails
	// that panel only.
	flowStatsJobHook func(block string) error
)

// flowHybridEligible is the static part of the decision: could this request
// use the hybrid read at all? Whether it DOES is flowHybridPlan's answer.
//
// "Single-tier window" is asked of rollupIntervalsForWindow, not written as a
// literal 48: that function owns the knowledge of where the 5-minute tier
// ends, and a second copy of the number is how the two drift apart.
func flowHybridEligible(hours int, filter FlowStatsFilter) bool {
	if !flowHybridEnabled || hours <= flowHybridMinHours {
		return false
	}
	if tiers := rollupIntervalsForWindow(hours); len(tiers) != 1 || tiers[0] != "5m" {
		return false
	}
	// A cube-dimension filter stays on the live read: the summary's top-N
	// lists carry no dimension columns, so those panels could not be served.
	return flowSummaryCompatible(filter) && !flowSummaryDimensionFiltered(filter)
}

// flowHybridPlanResult is one request's plan. ok=false carries the reason and
// means "run the live read".
type flowHybridPlanResult struct {
	ok                 bool
	reason             string
	headEnd, tailStart time.Time
}

func hourlySummaryTier() flowSummaryTier {
	for _, t := range flowSummaryTiers {
		if t.interval == "1h" {
			return t
		}
	}
	panic("flow summary: no hourly tier")
}

// flowHybridPlan decides where the tail starts, or refuses.
//
// It MUST run after the request's raw-sample reads (flushRollups calls it). A
// rollup cycle moves rows from raw samples into 5-minute rollups; if it
// commits between a plan and the raw read, a late row it moved into a middle
// hour is in neither — the raw read no longer sees it, and the plan, made
// earlier, did not put that hour in the tail. Planned afterwards, any row the
// raw read missed is already a rollup row above the watermark.
//
// The rule for the tail: every rollup row the hourly tier has NOT accounted
// for has an id above its watermark, so the oldest hour touched by such a row
// is the first hour that cannot come from the summary. The scan that finds
// those hours is dirtyChunkStamps — the summariser's own statement, whose plan
// was measured on production (see flowSummaryDirtyScanChunkDefault) — and it
// is limited to ONE piece here: a backlog wider than that is the summariser's
// to walk, not a page load's.
//
// The watermark alone is not proof that hours below it were built — the
// first-pass arm of summariseTier advances it before the backfill has — so the
// fill marker must also reach the last middle hour.
//
// h carries the request's budget context; every query here is bounded by it.
func (d *Database) flowHybridPlan(ctx context.Context, h *gorm.DB, cutoff time.Time) flowHybridPlanResult {
	tier := hourlySummaryTier()
	refuse := func(reason string) flowHybridPlanResult { return flowHybridPlanResult{reason: reason} }
	if flowHybridPlanHook != nil {
		if err := flowHybridPlanHook(); err != nil {
			return refuse(flowHybridRefusedProbe)
		}
	}
	headEnd := tier.bucketOf(cutoff).Add(tier.width)

	// One strict read. The four rebuild keys exist only while a
	// reclassification or the summary recompute it requests is in progress
	// (they are deleted at rest); the keys that outlive a run — its status,
	// its done-markers — are deliberately not consulted.
	wmKey, fillKey := flowSummaryWatermarkKeyPrefix+tier.interval, flowSummaryFillKeyPrefix+tier.interval
	rebuildKeys := []string{flowReclassStateKey, flowSummaryRecomputeRequestKey,
		recomputeCursorKey(tier.interval), recomputeRetryKey(tier.interval)}
	keys := append([]string{wmKey, fillKey, FlowSummaryRetentionKey}, rebuildKeys...)
	vals, err := d.summarySettings(ctx, keys...)
	if err != nil {
		return refuse(flowHybridRefusedSettings)
	}
	watermark, err := strconv.ParseInt(strings.TrimSpace(vals[wmKey]), 10, 64)
	if strings.TrimSpace(vals[wmKey]) == "" || (err == nil && watermark == 0) {
		return refuse(flowHybridRefusedNotBuilt)
	}
	if err != nil || watermark < 0 {
		return refuse(flowHybridRefusedSettings)
	}
	var filled time.Time
	if v := strings.TrimSpace(vals[fillKey]); v != "" {
		t, perr := time.Parse(time.RFC3339, v)
		if perr != nil {
			return refuse(flowHybridRefusedSettings)
		}
		filled = t.UTC()
	}
	// In-place reclassification rewrites rollup rows without new ids, so the
	// watermark cannot see it; the summary is stale until the recompute it
	// requests has walked those buckets.
	for _, k := range rebuildKeys {
		if strings.TrimSpace(vals[k]) != "" {
			return refuse(flowHybridRefusedRebuild)
		}
	}
	if v := strings.TrimSpace(vals[FlowSummaryRetentionKey]); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil {
			return refuse(flowHybridRefusedSettings)
		}
		if n > 0 && n < flowHybridMinRetentionDays {
			return refuse(flowHybridRefusedRetention)
		}
	}

	var ceiling int64
	if err := h.Session(&gorm.Session{}).Model(&models.FlowRollup{}).
		Select("COALESCE(MAX(id),0)").Scan(&ceiling).Error; err != nil {
		return refuse(flowHybridRefusedProbe)
	}
	chunk := flowSummaryDirtyScanChunk
	if chunk <= 0 {
		chunk = flowSummaryDirtyScanChunkDefault
	}
	if ceiling-watermark > chunk {
		// More new ids than one scan piece: the summariser is more than a
		// pass behind. Expected once a day for one pass (the 1h→1d promotion
		// inserts a day of rows in one go), and whenever a pass overran its
		// time bound and is still catching up.
		return refuse(flowHybridRefusedBacklog)
	}
	var unsummarised []time.Time
	if ceiling > watermark {
		unsummarised, err = dirtyChunkStamps(h.Session(&gorm.Session{}), tier.sumSources, watermark, ceiling)
		if err != nil {
			return refuse(flowHybridRefusedProbe)
		}
	}
	newest, ok, err := aggregateTimestamp(
		h.Session(&gorm.Session{}).Model(&models.FlowRollup{}).Where("interval_type = ?", "5m"), "MAX(timestamp)")
	if err != nil {
		return refuse(flowHybridRefusedProbe)
	}
	newestHour := tier.bucketOf(newest)
	if !ok || newestHour.Before(headEnd) {
		// The 5-minute tier does not reach past the head hour (rollups held
		// back for hours: a cleanup holding the maintenance lock, the archive
		// gate). A tail starting there would begin before the cutoff or lie
		// on top of the head.
		return refuse(flowHybridRefusedNoRollups)
	}

	tailStart := newestHour
	for _, ts := range unsummarised {
		// Hours before headEnd are the head's (read live already) or outside
		// the window altogether.
		if b := tier.bucketOf(ts); !b.Before(headEnd) && b.Before(tailStart) {
			tailStart = b
		}
	}
	if newestHour.Add(tier.width).Sub(tailStart) > flowHybridMaxTail {
		// Either the summariser is hours behind, or it is fine and ONE late
		// row (a collector replaying its spool) landed hours back and has not
		// been folded in yet. The reason names what was found, not a cause.
		return refuse(flowHybridRefusedTail)
	}
	// The last middle hour is tailStart-1h; with an empty middle there is
	// nothing the marker has to vouch for.
	if tailStart.After(headEnd) && filled.Before(tailStart.Add(-tier.width)) {
		return refuse(flowHybridRefusedNotBuilt)
	}
	return flowHybridPlanResult{ok: true, headEnd: headEnd, tailStart: tailStart}
}

// flowHybridCubeColumns is the column list both arms of the cube union
// project, in this order. It is flow_summaries' shape plus sampling_rate_avg,
// which only rollup rows carry (the middle's range comes from
// flow_summary_buckets through its own panel).
const flowHybridCubeColumns = "timestamp, device_id, protocol, app_category, direction, scope_local, " +
	"dst_country, flow_source, firewall_event, bytes_sum, packets_sum, flow_count"

// flowHybridCube is the table the dimension panels read on a hybrid request:
// edge rollup rows and middle summary rows under the cube's column names, so
// every panel runs the SQL it runs against flow_rollups.
//
// head, tail and middle are complete queries (filters applied, including the
// probe filter — a filter missing from one arm would serve other devices'
// traffic for that part of the window). The derived-table form of the union
// is the one flowStatsMaterialized already uses: a parenthesised compound does
// not parse on SQLite.
//
// Head and tail are separate arms rather than one arm with
// `timestamp < headEnd OR timestamp >= tailStart`. Each is then a plain range
// on (interval_type, timestamp); the OR form is as fast only while the planner
// chooses to OR two bitmap scans, and as slow as the whole live read when it
// does not.
func flowHybridCube(session func() *gorm.DB, d Dialect, head, tail, middle *gorm.DB) *gorm.DB {
	edgeCols := flowHybridCubeColumns + ", sampling_rate_avg"
	union := session().Raw("SELECT * FROM (?) AS hybrid_head UNION ALL SELECT * FROM (?) AS hybrid_tail "+
		"UNION ALL SELECT * FROM (?) AS hybrid_middle",
		head.Select(edgeCols), tail.Select(edgeCols),
		middle.Select(flowHybridCubeColumns+", "+nullNumeric(d)+" AS sampling_rate_avg"))
	return session().Table("(?) AS flow_hybrid", union)
}

// flowSummaryTopDimension is one high-cardinality dimension of
// flow_summary_tops: how its value is derived from a rollup row, and which
// rows have one. The WRITER (writeSummaryTops) and the hybrid READER both use
// this table; two copies of the encoding would let the edge rows and the
// middle rows of one list disagree about what a value looks like.
type flowSummaryTopDimension struct {
	name string
	expr string
	skip string
}

func flowSummaryTopDimensions(d Dialect) []flowSummaryTopDimension {
	return []flowSummaryTopDimension{
		{flowSummaryDimSrcAddr, "src_addr", "src_addr <> ''"},
		{flowSummaryDimDstAddr, "dst_addr", "dst_addr <> ''"},
		// service_port replaced dst_port in v0.11.263 (Top services). Buckets
		// written earlier carry the old dimension and none of this one; the
		// reader gates on flow_summary_service_since for that.
		{flowSummaryDimServicePort, d.CastText("service_port"), "service_port > 0"},
		{flowSummaryDimDstASN, d.CastText("dst_asn"), "dst_asn <> 0"},
		{flowSummaryDimConversation,
			d.Concat("src_addr", "'|'", "dst_addr", "'|'", d.CastText("dst_port"), "'|'", d.CastText("protocol")),
			"src_addr <> '' AND dst_addr <> ''"},
	}
}

func flowSummaryTopDimensionNamed(d Dialect, name string) (flowSummaryTopDimension, error) {
	for _, dim := range flowSummaryTopDimensions(d) {
		if dim.name == name {
			return dim, nil
		}
	}
	return flowSummaryTopDimension{}, fmt.Errorf("unknown summary dimension %q", name)
}

// flowHybridTops is flow_summary_tops' shape for one dimension over the whole
// window: the middle's stored per-hour lists, and the edge rows projected into
// the same shape with the writer's own value encoding and row predicate. The
// summary's top-N readers then run unchanged, and the edges contribute EXACT
// totals to the merge instead of a second truncated list.
func flowHybridTops(session func() *gorm.DB, dim flowSummaryTopDimension, head, tail, middle *gorm.DB) *gorm.DB {
	const cols = "dimension, scope_local, value, bytes_sum, packets_sum, flow_count"
	edge := func(q *gorm.DB) *gorm.DB {
		return q.Where(dim.skip).Select("? AS dimension, scope_local, "+dim.expr+" AS value, bytes_sum, packets_sum, flow_count", dim.name)
	}
	union := session().Raw("SELECT * FROM (?) AS hybrid_head UNION ALL SELECT * FROM (?) AS hybrid_tail "+
		"UNION ALL SELECT * FROM (?) AS hybrid_middle",
		edge(head), edge(tail), middle.Where("dimension = ?", dim.name).Select(cols))
	return session().Table("(?) AS flow_hybrid_tops", union)
}

// nullNumeric is a typed NULL for a numeric column of a UNION arm. PostgreSQL
// resolves a union's column types arm by arm and will not unify a bare NULL
// (type "unknown" becomes text) with numeric.
func nullNumeric(d Dialect) string {
	if d.IsPostgres() {
		return "CAST(NULL AS numeric)"
	}
	return "NULL"
}
