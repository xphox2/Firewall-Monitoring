// Package metrics provides a small in-process metrics registry. Counters are
// per-process (lock-free atomic uint64s); cross-instance aggregation is the
// scraper's job (standard Prometheus model). The /api/metrics handler emits
// the Prometheus text exposition format so the same numbers can be scraped
// with or without a Prometheus server in front.
//
// We deliberately do NOT depend on github.com/prometheus/client_golang:
// this package is a few hundred lines, has no transitive dep churn, and the
// handful of metrics the server actually needs (batch dedup, etc.) fit on
// one screen. Adding client_golang would drag in protobuf + a half-dozen
// x/* upgrades for one counter — see the AUDIT-070 PR description for the
// trade-off discussion.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// counter is a 64-bit monotonic counter, updated with atomic.AddUint64.
// Reads go through atomic.LoadUint64 so a scrape is racy-but-bounded (worst
// case: scraper sees a snapshot where one counter was bumped and another
// not yet — Prometheus's contract is that counters are per-process
// monotonic, not transactional across labels).
type counter struct {
	v atomic.Uint64
}

func (c *counter) inc()        { c.v.Add(1) }
func (c *counter) get() uint64 { return c.v.Load() }

// Registry holds the named counters. The map is protected by a single RWMutex
// because label discovery (an "Inc" for a new label) is rare and reads (a
// /metrics scrape) are common — the lock is held only long enough to
// snapshot the map keys; the atomic Loads inside counters run lock-free.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]map[string]*counter // metric -> labelSet -> counter
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{counters: make(map[string]map[string]*counter)}
}

// DefaultRegistry is the process-wide Registry used by the server's
// `/api/metrics` handler and the AUDIT-070 dedup code path. Tests that
// need a clean baseline should call Reset() in their setup. A single
// global is fine because (a) the process has one server and (b) the
// counters are designed to be per-process (cross-instance aggregation
// is the scraper's job).
var DefaultRegistry = NewRegistry()

// IncBatchDedup is the AUDIT-070 entry point: bumps
// `probe_batch_dedup_total{endpoint="..."}` for the named probe ingest
// endpoint (syslog, traps, flows, pings). The endpoint label MUST be one
// of the four short names so the counter stays in a small, predictable
// cardinality.
func (r *Registry) IncBatchDedup(endpoint string) {
	r.incLabeled("probe_batch_dedup_total", "endpoint", endpoint)
}

// IncBatchDedupFor is an alias kept for callers that already use the longer
// name; the `*For` suffix matches Go's strconv.Itoa / fmt.Sprintf family.
func (r *Registry) IncBatchDedupFor(endpoint string) { r.IncBatchDedup(endpoint) }

// BatchDedupSnapshot returns the current counter value for the given
// endpoint. Used by tests to assert the counter moved on a dedup hit; 0 is
// the right answer for an endpoint that has never been hit, including an
// endpoint that doesn't exist yet (which is the natural state before the
// first probe arrives).
func (r *Registry) BatchDedupSnapshot(endpoint string) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if labels, ok := r.counters["probe_batch_dedup_total"]; ok {
		if c, ok := labels["endpoint="+endpoint]; ok {
			return c.get()
		}
	}
	return 0
}

// Reset clears every counter. Intended for tests only — production code
// must never call this (a /metrics scrape sees counters monotonically grow
// over the process lifetime, which is the Prometheus contract).
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters = make(map[string]map[string]*counter)
}

// incLabeled is the generic counter-with-label helper. The label-name +
// label-value are concatenated into a single map key (`name=value`) so the
// inner map stays a `map[string]*counter`; the exposition step splits on
// `=` to render the Prometheus `{name="value"}` syntax.
func (r *Registry) incLabeled(metric, labelName, labelValue string) {
	key := labelName + "=" + labelValue
	r.mu.RLock()
	labels, ok := r.counters[metric]
	if ok {
		c, ok := labels[key]
		r.mu.RUnlock()
		if ok {
			c.inc()
			return
		}
	} else {
		r.mu.RUnlock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check under the write lock: a concurrent Inc may have created it
	// while we were upgrading locks.
	if r.counters[metric] == nil {
		r.counters[metric] = make(map[string]*counter)
	}
	if r.counters[metric][key] == nil {
		r.counters[metric][key] = &counter{}
	}
	r.counters[metric][key].inc()
}

// descriptions is the static metadata block emitted before each counter
// (HELP + TYPE lines, per the Prometheus text format). Statically wired so
// adding a new counter is a one-line change in this map.
var descriptions = map[string]struct{ help, type_ string }{
	"probe_batch_dedup_total": {
		help:  "Total number of probe batches dropped as duplicates by the server-side X-Probe-Batch-ID dedup (AUDIT-070).",
		type_: "counter",
	},
}

// WritePrometheusText serialises the registry into Prometheus text
// exposition format on w. Format reference:
// https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
//
// Output for two label values looks like:
//
//	# HELP probe_batch_dedup_total Total number of probe batches dropped as duplicates by the server-side X-Probe-Batch-ID dedup (AUDIT-070).
//	# TYPE probe_batch_dedup_total counter
//	probe_batch_dedup_total{endpoint="syslog"} 3
//	probe_batch_dedup_total{endpoint="traps"} 1
//
// The "Unknown counter" branch is a defensive default — a metric that's
// been Inc'd but lacks a description block would still surface (with no
// HELP/TYPE), which is the Prometheus convention for "metric is being
// emitted by something the scraper doesn't know about".
func (r *Registry) WritePrometheusText(w io.Writer) error {
	r.mu.RLock()
	// Snapshot the metric names so we can sort them and release the
	// lock before doing I/O.
	metricNames := make([]string, 0, len(r.counters))
	for name := range r.counters {
		metricNames = append(metricNames, name)
	}
	r.mu.RUnlock()
	sort.Strings(metricNames)

	for _, name := range metricNames {
		if d, ok := descriptions[name]; ok {
			if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n",
				name, d.help, name, d.type_); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "# TYPE %s counter\n", name); err != nil {
				return err
			}
		}
		// Snapshot + sort the label keys for stable output (Prometheus
		// doesn't require this, but it makes test assertions and
		// diffs deterministic).
		r.mu.RLock()
		labelKeys := make([]string, 0, len(r.counters[name]))
		for k := range r.counters[name] {
			labelKeys = append(labelKeys, k)
		}
		values := make(map[string]uint64, len(labelKeys))
		for _, k := range labelKeys {
			values[k] = r.counters[name][k].get()
		}
		r.mu.RUnlock()
		sort.Strings(labelKeys)

		for _, k := range labelKeys {
			labelName, labelValue := splitLabelKey(k)
			if _, err := fmt.Fprintf(w, "%s{%s=%q} %d\n",
				name, labelName, labelValue, values[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

// splitLabelKey is the inverse of `labelName + "=" + labelValue`. Returns
// ("endpoint", "syslog") for the key "endpoint=syslog". The label value is
// guaranteed not to contain `=` by convention (only the four short endpoint
// names reach this code), so a single Split is correct.
func splitLabelKey(k string) (name, value string) {
	for i := 0; i < len(k); i++ {
		if k[i] == '=' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}
