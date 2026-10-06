package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Raw archive (archive plan PR 4): what the poller's archive worker has
// exported, uploaded and verified, how far each stream lags, and why it is
// failing or waiting. Served by the poller's /metrics (the worker runs there).
// Labels: stream = syslog / sflow / netflow / sflow-counters; table = the
// source table; stage = where an attempt failed.
var (
	archiveLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "lag_seconds",
		Help: "Seconds from the end of the newest period whose chunk is verified (gapless from the first chunk) to now, per stream; from the first chunk's start while none is verified.",
	}, []string{"stream"})
	archiveVerifiedThrough = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "verified_through_id",
		Help: "Highest source-table id covered by a gapless run of verified chunks from the first chunk (V), per table.",
	}, []string{"table"})
	archiveChunks = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "chunks",
		Help: "Archive chunks by source table and status.",
	}, []string{"table", "status"})
	archiveRows = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "rows_total",
		Help: "Rows in objects verified by this process, per stream.",
	}, []string{"stream"})
	archiveObjects = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "objects_total",
		Help: "Data objects verified by this process, per stream (chunk manifests not included).",
	}, []string{"stream"})
	archiveObjectBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "object_bytes_total",
		Help: "Stored (compressed) bytes of objects verified by this process, per stream.",
	}, []string{"stream"})
	archiveRawBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "raw_bytes_total",
		Help: "Uncompressed NDJSON bytes of objects verified by this process, per stream.",
	}, []string{"stream"})
	archiveErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "errors_total",
		Help: "Archive failures by stage (lock, preflight, mark, plan, settle, stage, read, upload, verify, count, manifest, db).",
	}, []string{"stage"})
	archiveLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "last_success_timestamp_seconds",
		Help: "Unix time this process last verified a chunk of the stream.",
	}, []string{"stream"})
	archiveUnsettled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "fwmon", Subsystem: "archive", Name: "unsettled",
		Help: "1 while the table's next chunk waits to be exported, by reason: settling (the settle window after the cut), open_writer (a writing transaction older than the cut), no_statement_timeout (statement_timeout 0: nothing can be settled).",
	}, []string{"table", "reason"})
)

// ArchiveUnsettledReasons are the reason label values of
// fwmon_archive_unsettled.
var ArchiveUnsettledReasons = []string{"settling", "open_writer", "no_statement_timeout"}

func init() {
	prometheus.MustRegister(archiveLag, archiveVerifiedThrough, archiveChunks, archiveRows, archiveObjects,
		archiveObjectBytes, archiveRawBytes, archiveErrors, archiveLastSuccess, archiveUnsettled)
}

// SetArchiveLag sets a stream's lag.
func SetArchiveLag(stream string, lag time.Duration) {
	archiveLag.WithLabelValues(stream).Set(lag.Seconds())
}

// SetArchiveVerifiedThrough sets a table's V.
func SetArchiveVerifiedThrough(table string, id int64) {
	archiveVerifiedThrough.WithLabelValues(table).Set(float64(id))
}

// SetArchiveChunks sets the chunk count of a table and status.
func SetArchiveChunks(table, status string, n int64) {
	archiveChunks.WithLabelValues(table, status).Set(float64(n))
}

// AddArchiveVerifiedObject counts one verified object of a stream.
func AddArchiveVerifiedObject(stream string, rows, rawBytes, objectBytes int64) {
	archiveObjects.WithLabelValues(stream).Inc()
	archiveRows.WithLabelValues(stream).Add(float64(rows))
	archiveRawBytes.WithLabelValues(stream).Add(float64(rawBytes))
	archiveObjectBytes.WithLabelValues(stream).Add(float64(objectBytes))
}

// IncArchiveError counts one failure at stage.
func IncArchiveError(stage string) { archiveErrors.WithLabelValues(stage).Inc() }

// SetArchiveLastSuccess records a verified chunk of stream at t.
func SetArchiveLastSuccess(stream string, t time.Time) {
	archiveLastSuccess.WithLabelValues(stream).Set(float64(t.Unix()))
}

// SetArchiveUnsettled sets the table's unsettled reason (1 for reason, 0 for
// the others); "" clears every reason.
func SetArchiveUnsettled(table, reason string) {
	for _, r := range ArchiveUnsettledReasons {
		v := 0.0
		if r == reason {
			v = 1
		}
		archiveUnsettled.WithLabelValues(table, r).Set(v)
	}
}
