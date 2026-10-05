package metrics

import "github.com/prometheus/client_golang/prometheus"

// netEventRollupDaySkips counts the UTC days the net_events rollup gave up
// recomputing exactly (RunNetEventRollupCycle: three failed closes in a row),
// leaving that day's rows at the hour folds' lower-bound distinct_src. One is
// an operator signal — the day's partition could not be read within the
// statement budget — so it is a counter, not a log line alone. Served by
// whichever process runs the rollup (the poller's /metrics).
var netEventRollupDaySkips = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "fwmon",
	Subsystem: "net_event_rollup",
	Name:      "day_skips_total",
	Help:      "UTC days whose exact net_event_rollups recompute was skipped after repeated failures (distinct_src left approximate).",
})

func init() {
	prometheus.MustRegister(netEventRollupDaySkips)
}

// IncNetEventRollupDaySkipped records one skipped day close.
func IncNetEventRollupDaySkipped() { netEventRollupDaySkips.Inc() }
