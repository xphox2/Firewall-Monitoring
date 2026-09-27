package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Long Flows reports: a filter on src/dst address, destination port or ASN
// cannot be served by the summary tables (they keep those dimensions only as
// per-bucket top-N), and flow_rollups has no index on any of them — so every
// rolled-up panel used to scan the whole table. Measured on production for a
// 30-day window filtered to one source address: 15.4 s for ONE panel, a
// parallel sequential scan of 20 GB discarding 140M rows; the page runs about
// fourteen, so all of them hit the 20 s budget and the page reported roughly
// one hour of raw samples under a 30-day label.
//
// The materialized run reads the window ONCE, one day at a time, into a
// session-local scope table holding exactly the rows the filter selects, and
// every rolled-up panel then reads that table. One day of flow_rollups is an
// index scan on (interval_type, timestamp) — rows are inserted in time order, so
// each day's pages sit together — costing 0.3-1.7 s when cached and 2.4-7.8 s
// cold on production: a 30-day report takes about 30 s warm and 2-2.5 min cold,
// with a real "day N of 30" to report and each statement far under the 30 s
// statement_timeout. Temp tables are per session, so the whole run —
// raw queries included — goes through one pinned connection with the rolled-up
// panels run one at a time.

// flowStatsMaterialize gates the materialized run. Tests flip it to compare the
// materialized result with the direct one on the same filter.
var flowStatsMaterialize = true

// flowScopeChunkHook, when set, runs before each scope-table INSERT and may
// return an error in its place. Tests use it to simulate a statement timeout;
// nil in production.
var flowScopeChunkHook func(a, b time.Time) error

// FlowStatsMaterializes reports whether a request would take the materialized
// run — the long one. The stream handler uses it to decide whether the request
// needs one of the long-report slots. It needs no database: the summary path
// requires flowSummaryCompatible, so an incompatible filter never reaches the
// backfill check.
func FlowStatsMaterializes(hours int, filter FlowStatsFilter) bool {
	return flowStatsMaterialize && hours > 1 && !flowSummaryCompatible(filter)
}

// FlowStatsIsLong reports whether a request is a LONG report: materialized and
// spanning more than one day chunk. Only these take one of the stream's slots —
// a filtered 6 h or 24 h view is one sub-second chunk and must never be told
// to wait behind a 90-day report.
func FlowStatsIsLong(hours int, filter FlowStatsFilter) bool {
	return FlowStatsMaterializes(hours, filter) && hours > 24
}

// FlowStatsProgress is one step of a Flows report, for a progress display.
type FlowStatsProgress struct {
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Label string `json:"label"`
}

// FlowStatsOptions carries what differs between the synchronous endpoint and
// the streamed one.
type FlowStatsOptions struct {
	// Progress is called before each step, always from the goroutine that called
	// GetFlowStatsOpts, so it may write to a response.
	Progress func(FlowStatsProgress)
	// LongRunning removes the overall time limit from a materialized run: it
	// runs until it finishes or the client goes away. The synchronous endpoint
	// keeps its 20 s, because its 30 s write timeout would cut the response off;
	// a stream has no such wall and shows its progress, so a fixed budget would
	// only throw away a report someone is watching — and would fail first on
	// exactly the slower systems that need longer. What still stops it: the
	// client closing the page or pressing Cancel (the request context), and a
	// client that stops reading (the next write fails — the stream writes a
	// keepalive every 15 s). Each single statement is still bounded by the 30 s
	// statement_timeout: a day that exceeds it is split and retried (fillRange),
	// and a piece that still fails degrades the panels rather than stopping the
	// report. Other runs keep the budget and concurrency they were tuned for.
	LongRunning bool
}

// flowStatsRun is what flowStats varies on between the direct and the
// materialized run.
type flowStatsRun struct {
	h           *gorm.DB // every query goes through this handle
	cutoff      time.Time
	useSummary  bool
	scope       string // table the rolled-up panels read; "" = flow_rollups
	concurrency int
	budget      *flowStatsBudget
	// fill, when set, fills the scope table from the flow_rollups base it is
	// given, before any rolled-up panel runs.
	fill func(source func() *gorm.DB) error

	progress  func(FlowStatsProgress)
	done      int
	total     int
	fillSteps int
}

// step reports the step about to run.
func (r *flowStatsRun) step(label string) {
	if r.progress == nil {
		return
	}
	if r.done >= r.total {
		r.total = r.done + 1
	}
	r.progress(FlowStatsProgress{Done: r.done, Total: r.total, Label: label})
	r.done++
}

// expect fixes the total once the number of rolled-up panels is known:
// the steps so far, the fill's days, "Aggregating panels", one per panel, and a
// final step for the finishing work.
func (r *flowStatsRun) expect(panels int) {
	if panels == 0 {
		// No rolled-up work (a raw-only window): only the final step remains.
		r.total = r.done + 1
		return
	}
	r.total = r.done + r.fillSteps + 1 + panels + 1
}

// finish reports the last step.
func (r *flowStatsRun) finish() { r.step("Finishing") }

// GetFlowStats returns aggregated flow statistics, optionally narrowed by
// filter, within the synchronous endpoint's budget.
func (d *Database) GetFlowStats(hours int, filter FlowStatsFilter) (*FlowStatsResult, error) {
	return d.GetFlowStatsOpts(hours, filter, FlowStatsOptions{})
}

// GetFlowStatsOpts is GetFlowStats with progress reporting and, for the
// streamed endpoint, a budget scaled to the window.
func (d *Database) GetFlowStatsOpts(hours int, filter FlowStatsFilter, opts FlowStatsOptions) (*FlowStatsResult, error) {
	now := time.Now()
	cutoff := now.Add(-time.Duration(hours) * time.Hour)
	parent := d.db.Statement.Context

	if !FlowStatsMaterializes(hours, filter) {
		// Decided here, before anything is pinned: summaryBackfillComplete
		// queries through d.
		useSummary := hours > flowSummaryMinHours && flowSummaryCompatible(filter) && d.summaryBackfillComplete()
		run := &flowStatsRun{
			h: d.db, cutoff: cutoff, useSummary: useSummary,
			concurrency: flowStatsRollupConcurrency,
			budget:      newFlowStatsBudget(parent, flowStatsRollupBudget),
			progress:    opts.Progress, total: 20,
		}
		res, err := d.flowStats(hours, filter, run)
		if err == nil {
			run.finish()
		}
		return res, err
	}

	allowance := materializedAllowance(opts)
	var res *FlowStatsResult
	var runErr error
	connErr := d.db.Connection(func(tx *gorm.DB) error {
		res, runErr = d.flowStatsMaterialized(tx, hours, filter, now, cutoff, allowance, opts.Progress)
		return nil
	})
	if connErr != nil {
		return nil, connErr
	}
	return res, runErr
}

// materializedAllowance is the materialized run's overall time limit: none for
// the stream (zero = no deadline; see FlowStatsOptions.LongRunning), the
// synchronous endpoint's 20 s otherwise.
func materializedAllowance(opts FlowStatsOptions) time.Duration {
	if opts.LongRunning {
		return 0
	}
	return flowStatsRollupBudget
}

// flowScopeColumns are the flow_rollups columns the rolled-up panels read or
// filter on. device_id, flow_source and firewall_event are carried so the
// shared filters re-apply cleanly on the scope table.
const flowScopeColumns = "timestamp, device_id, interval_type, src_addr, dst_addr, dst_port, protocol, " +
	"bytes_sum, packets_sum, flow_count, sampling_rate_avg, app_category, direction, scope_local, " +
	"dst_country, dst_asn, flow_source, firewall_event"

var flowScopeNameRE = regexp.MustCompile(`^flow_scope_[a-f0-9]{16}$`)

// newFlowScopeName returns a random scope table name. It is interpolated into
// DDL (a table name cannot be a bind parameter), so it is validated as well as
// generated.
func newFlowScopeName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := "flow_scope_" + hex.EncodeToString(b[:])
	if !flowScopeNameRE.MatchString(name) {
		return "", fmt.Errorf("invalid scope table name %q", name)
	}
	return name, nil
}

// flowStatsMaterialized runs flowStats on one pinned connection, with the
// rolled-up panels reading a scope table filled one day at a time.
func (d *Database) flowStatsMaterialized(tx *gorm.DB, hours int, filter FlowStatsFilter, now, cutoff time.Time,
	allowance time.Duration, progress func(FlowStatsProgress)) (*FlowStatsResult, error) {
	ctx := tx.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}
	name, err := newFlowScopeName()
	if err != nil {
		return nil, err
	}
	// CREATE … AS SELECT … WHERE 1=0 copies the column types exactly on both
	// dialects without hand-written DDL.
	if err := tx.Exec("CREATE TEMP TABLE " + name + " AS SELECT " + flowScopeColumns + " FROM flow_rollups WHERE 1=0").Error; err != nil {
		return nil, fmt.Errorf("flow stats scope table: %w", err)
	}
	defer dropFlowScope(tx, ctx, name)

	budget := newFlowStatsBudget(ctx, allowance)
	days := (hours + 23) / 24
	run := &flowStatsRun{
		h: tx, cutoff: cutoff, useSummary: false, scope: name,
		concurrency: 1, // one connection: the panels run one at a time
		budget:      budget, progress: progress,
		fillSteps: days, total: 1 + days + 1 + 16 + 1,
	}
	// fillRange copies (a, b] into the scope table. A range whose statement is
	// cancelled server-side (SQLSTATE 57014 — the 30 s statement_timeout, or an
	// operator's pg_cancel_backend) is split in half and each half retried, down
	// to an hour: a slower disk still finishes, one smaller statement at a time.
	// A failed INSERT inserts nothing, so a retry cannot duplicate rows. A
	// client cancel never arrives as 57014 (pgx reports it as a lost
	// connection), and the budget check below stops the recursion anyway.
	var dayLabel string
	var fillRange func(source func() *gorm.DB, a, b time.Time) error
	fillRange = func(source func() *gorm.DB, a, b time.Time) error {
		cctx, cancel, ok := budget.context()
		if !ok {
			return errors.New("flow stats budget spent before the scan finished")
		}
		// Half-open (a, b] chunks from the one captured cutoff to the one
		// captured now: together exactly `timestamp > cutoff`, each row in
		// exactly one chunk. The derived-table form parses on SQLite too.
		chunk := source().Select(flowScopeColumns).Where("timestamp > ? AND timestamp <= ?", a, b)
		var err error
		if flowScopeChunkHook != nil {
			err = flowScopeChunkHook(a, b)
		}
		if err == nil {
			err = tx.WithContext(cctx).Exec("INSERT INTO "+name+" ("+flowScopeColumns+") SELECT "+flowScopeColumns+" FROM (?) AS src", chunk).Error
		}
		cancel()
		if err != nil && sqlState(err) == "57014" && b.Sub(a) > time.Hour {
			mid := a.Add(b.Sub(a) / 2)
			log.Printf("Flow stats: reading %s..%s was cancelled by the server (%v); splitting it", a.Format(time.RFC3339), b.Format(time.RFC3339), err)
			// Show the split on the progress panel without advancing the bar.
			if run.progress != nil {
				run.progress(FlowStatsProgress{Done: run.done - 1, Total: run.total,
					Label: fmt.Sprintf("%s (in smaller pieces)", dayLabel)})
			}
			if err := fillRange(source, a, mid); err != nil {
				return err
			}
			return fillRange(source, mid, b)
		}
		return err
	}
	run.fill = func(source func() *gorm.DB) error {
		for i, a := 0, cutoff; a.Before(now); i++ {
			b := a.Add(24 * time.Hour)
			if b.After(now) {
				b = now
			}
			dayLabel = fmt.Sprintf("Reading day %d of %d", i+1, days)
			run.step(dayLabel)
			if err := fillRange(source, a, b); err != nil {
				return err
			}
			a = b
		}
		return nil
	}
	res, err := d.flowStats(hours, filter, run)
	if err == nil {
		run.finish()
	}
	return res, err
}

// dropFlowScope removes the scope table on a context that ignores the
// request's cancellation, so a live connection never returns to the pool
// holding it. If the drop fails the connection is discarded instead.
//
// What a cancel does to the connection depends on the driver. pgx reports a
// statement on an already-cancelled context as driver.ErrBadConn, and
// database/sql then closes the connection — the backend ends and the
// session-local table with it, so on PostgreSQL a cancelled run (a Cancel
// click, a closed tab) usually arrives here with the connection already gone.
// SQLite keeps the connection, and the drop below is what removes the table.
func dropFlowScope(tx *gorm.DB, ctx context.Context, name string) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := tx.WithContext(dctx).Exec("DROP TABLE IF EXISTS " + name).Error; err != nil {
		if ctx.Err() != nil {
			log.Printf("Flow stats: report cancelled by the client; its connection and scope table were discarded")
		} else {
			log.Printf("Flow stats: dropping %s failed (%v); discarding the connection", name, err)
		}
		if c, ok := tx.Statement.ConnPool.(*sql.Conn); ok {
			_ = c.Raw(func(any) error { return driver.ErrBadConn })
		}
	}
}

// flowStatsPanelLabels names each rolled-up panel for a person.
var flowStatsPanelLabels = map[string]string{
	"totals":            "Totals",
	"unique_src_addr":   "Unique sources",
	"unique_dst_addr":   "Unique destinations",
	"sampling":          "Sampling rate",
	"local_traffic":     "Local traffic",
	"protocols":         "Protocols",
	"by_app_category":   "Applications",
	"by_direction":      "Direction",
	"top_countries":     "Top countries",
	"top_asns":          "Top networks (ASN)",
	"top_sources":       "Top sources",
	"top_destinations":  "Top destinations",
	"top_conversations": "Top conversations",
	"top_ports":         "Top ports",
	"bytes_over_time":   "Traffic over time",
}

func flowStatsPanelLabel(block string) string {
	if l, ok := flowStatsPanelLabels[block]; ok {
		return l
	}
	return strings.ReplaceAll(block, "_", " ")
}
