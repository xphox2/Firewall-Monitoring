package metrics

import "github.com/prometheus/client_golang/prometheus"

// Syslog normalization counters (Phase 1, S-4). The ingest parses every
// syslog row once; these say what became of the rows — how many mapped to an
// Event (ok), were recognised but not mapped (unparsed) or matched no family
// (no_family) — and how many rows each normalized table received, so an
// operator can see "normalization stopped producing rows" or "every line of
// this vendor is unparsed" on /metrics instead of in a table count. Served by
// the API server (ingest runs there).
var (
	normalizeOutcomes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon",
		Subsystem: "normalize",
		Name:      "outcomes_total",
		Help:      "Syslog rows by normalization outcome (ok, unparsed, no_family).",
	}, []string{"kind"})
	normalizeRows = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon",
		Subsystem: "normalize",
		Name:      "rows_total",
		Help:      "Rows written to the normalized tables by the syslog ingest, by table.",
	}, []string{"table"})
	normalizeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon",
		Subsystem: "normalize",
		Name:      "write_errors_total",
		Help:      "Failed batch writes to the normalized tables (the raw syslog rows were already saved), by table.",
	}, []string{"table"})
)

func init() {
	prometheus.MustRegister(normalizeOutcomes, normalizeRows, normalizeErrors)
}

// AddNormalizeOutcome counts n rows with the given outcome kind.
func AddNormalizeOutcome(kind string, n int) {
	if n > 0 {
		normalizeOutcomes.WithLabelValues(kind).Add(float64(n))
	}
}

// AddNormalizeRows counts n rows written to table.
func AddNormalizeRows(table string, n int) {
	if n > 0 {
		normalizeRows.WithLabelValues(table).Add(float64(n))
	}
}

// IncNormalizeWriteError counts one failed batch write to table.
func IncNormalizeWriteError(table string) { normalizeErrors.WithLabelValues(table).Inc() }
