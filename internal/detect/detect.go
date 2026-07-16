// Package detect is the sFlow good-vs-bad traffic detection engine. Each
// Detector runs a bounded SQL aggregation over a recent window of flow_samples
// (enriched at ingest by internal/classify with app category, direction, and —
// when enabled — geo/ASN) and returns Detection findings. The poller runs the
// Registry on a timer under its leader lock, persists every finding, and feeds
// each to the alert engine (observe-mode severities first, so a noisy detector
// can't page anyone).
//
// detect is a leaf package: it imports only gorm and models, so database, alerts,
// and the poller can all depend on it without an import cycle.
package detect

import (
	"encoding/json"
	"log"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Category groups detectors by the kind of problem they surface.
type Category string

const (
	CategorySecurity    Category = "security"
	CategoryOperational Category = "operational"
	CategoryPolicy      Category = "policy"
)

// ValidityClass declares what flow data a detector's math is valid over
// (Tranche 4, T4-1 — the FastNetMon rule: byte/packet sums are unbiased on
// sampled rows because ingest pre-multiplies them by sampling_rate, but
// flow-count rates and per-flow timing are only valid on complete session
// exports).
type ValidityClass string

const (
	// ValiditySampledOK: volume (byte/packet) math only — safe on sampled sFlow.
	ValiditySampledOK ValidityClass = "sampled_ok"
	// ValidityCompleteOnly: needs every flow record (per-flow timing, flow
	// counts, firewall events). Queries carry completeRows().
	ValidityCompleteOnly ValidityClass = "complete_only"
	// ValidityRateGated: mixed — volume thresholds on all rows; count-rate and
	// packet-rate thresholds gated per-metric inside the detector.
	ValidityRateGated ValidityClass = "rate_gated"
)

// detectorValidity classifies every Registry() detector. A guardrail test
// asserts completeness, so adding a detector without declaring its evidence
// class fails CI. RunAll stamps the class into Details["validity"] so every
// persisted detection self-documents what data it was judged on.
var detectorValidity = map[string]ValidityClass{
	"cleartext":            ValiditySampledOK,
	"unexpected_egress":    ValiditySampledOK,
	"sampling_backoff":     ValiditySampledOK,
	"capacity":             ValiditySampledOK,
	"port_scan":            ValiditySampledOK,
	"super_spreader":       ValiditySampledOK,
	"data_exfil":           ValiditySampledOK,
	"threat_intel":         ValiditySampledOK,
	"c2_beacon":            ValiditySampledOK, // CV heuristic, written for sampled noise
	"ddos_volumetric":      ValidityRateGated,
	"ddos_prefix":          ValidityRateGated,
	"sampling_rate_change": ValiditySampledOK, // inspects metadata, not traffic
}

// victimKeyed marks security detectors whose findings are keyed by the VICTIM
// (DstAddr) rather than an offending source. These must NOT enter the
// per-source SFLOW_SECURITY consolidation (their SrcAddr is empty — grouping
// by it would collapse every victim into one degenerate "" group); the poller
// routes them down the per-detection path, which auto-derives SFLOW_<NAME>
// alert types. Event-rule suppression still applies: the rule-subject
// source_ip field carries the victim address for these.
var victimKeyed = map[string]bool{
	"ddos_volumetric": true,
	"ddos_prefix":     true,
}

// VictimKeyed reports whether a security detector's findings are victim-keyed.
func VictimKeyed(detector string) bool { return victimKeyed[detector] }

// Detection is one finding produced by a detector over a window. It is both
// persisted (models.FlowDetection) and mapped to an alert (AlertManager
// .ProcessFlowDetection). Severity is a plain string ("info"|"warning"|
// "critical") to keep this package free of the models/alerts types.
type Detection struct {
	Detector string
	Category Category
	Severity string
	DeviceID uint
	SrcAddr  string
	DstAddr  string
	DstPort  uint16
	Protocol uint8
	Score    float64 // magnitude (bytes / flows / pct) for ranking
	Message  string
	DedupKey string // stable per (detector, target) — drives alert cooldown + UI dedup
	Details  map[string]any
}

// Window is the time range and DB handle a detector runs against, plus the
// tunable detector thresholds (Config).
type Window struct {
	Start  time.Time
	End    time.Time
	DB     *gorm.DB
	Config Config
}

// Config holds operator-tunable detector thresholds. A zero value for any field
// means "use the built-in default" (see withDefaults), so a caller can override
// just the knobs it cares about — and an unset Window.Config behaves exactly
// like the historical hard-coded constants (except the raised port-scan floor).
type Config struct {
	PortScanPorts      int     // distinct dst ports from one src to flag a scan
	SuperSpreaderHosts int     // distinct dst hosts from one src
	DataExfilBytes     int64   // outbound (src,dst) bytes in the window
	BeaconMinSamples   int     // min flows to judge periodicity
	BeaconMaxAvgBytes  int     // "small" callout ceiling for beacons
	BeaconMaxCV        float64 // inter-arrival coefficient-of-variation ceiling
	CapacityThreshold  float64 // egress-utilisation fraction that fires a finding

	// Tranche 4 Phase 1 — DDoS volumetric (per-victim) OR-thresholds.
	// Defaults follow FastNetMon community edition (threshold_mbps 1000 /
	// threshold_pps 20000 / threshold_flows 3500). bps+pps are valid on
	// sampled rows (pre-multiplied counters); fps counts complete rows only.
	DDoSBps int64 // bits/second per victim, peak minute
	DDoSPps int64 // packets/second per victim, peak minute
	DDoSFps int   // flows/second per victim, peak minute (complete rows only)
	// Per-prefix (carpet-bombing) thresholds; <=0 inherits the per-host value.
	DDoSPrefixBps int64
	DDoSPrefixPps int64
	DDoSPrefixFps int
	// SampRateMinRows: a sampling rate must appear on at least this many rows
	// in a window to count toward the per-exporter rate set (single mangled
	// datagrams must not register as a rate change).
	SampRateMinRows int

	// Per-detector kill switches for the Tranche-4 detectors (zero value =
	// enabled, so withDefaults needs no handling; set via the dedicated
	// three-state detect_<name>_enabled parser in the poller).
	DDoSVolumetricDisabled     bool
	DDoSPrefixDisabled         bool
	SamplingRateChangeDisabled bool
}

// withDefaults returns a copy with every unset (<=0) field filled from the
// package defaults, so detectors can read c.Field directly.
func (c Config) withDefaults() Config {
	if c.PortScanPorts <= 0 {
		c.PortScanPorts = defaultPortScanPorts
	}
	if c.SuperSpreaderHosts <= 0 {
		c.SuperSpreaderHosts = defaultSuperSpreaderHosts
	}
	if c.DataExfilBytes <= 0 {
		c.DataExfilBytes = defaultDataExfilBytes
	}
	if c.BeaconMinSamples <= 0 {
		c.BeaconMinSamples = defaultBeaconMinSamples
	}
	if c.BeaconMaxAvgBytes <= 0 {
		c.BeaconMaxAvgBytes = defaultBeaconMaxAvgBytes
	}
	if c.BeaconMaxCV <= 0 {
		c.BeaconMaxCV = defaultBeaconMaxCV
	}
	if c.CapacityThreshold <= 0 {
		c.CapacityThreshold = defaultCapacityThreshold
	}
	if c.DDoSBps <= 0 {
		c.DDoSBps = defaultDDoSBps
	}
	if c.DDoSPps <= 0 {
		c.DDoSPps = defaultDDoSPps
	}
	if c.DDoSFps <= 0 {
		c.DDoSFps = defaultDDoSFps
	}
	// Prefix thresholds inherit the per-host values: carpet bombing spreads a
	// link-scale attack across a subnet, and the defended resource (the link)
	// is the same size (FastNetMon hostgroup practice).
	if c.DDoSPrefixBps <= 0 {
		c.DDoSPrefixBps = c.DDoSBps
	}
	if c.DDoSPrefixPps <= 0 {
		c.DDoSPrefixPps = c.DDoSPps
	}
	if c.DDoSPrefixFps <= 0 {
		c.DDoSPrefixFps = c.DDoSFps
	}
	if c.SampRateMinRows <= 0 {
		c.SampRateMinRows = defaultSampRateMinRows
	}
	return c
}

// Seconds is the window length in seconds (>=1), used for rate math.
func (w Window) Seconds() float64 {
	s := w.End.Sub(w.Start).Seconds()
	if s < 1 {
		return 1
	}
	return s
}

// maxLookback is the ceiling on how far back a detector may read raw
// flow_samples. HARD INVARIANT: RunFlowRollupCycle (internal/database/flows.go)
// deletes raw rows older than 1h after folding them into rollups, and rollup +
// detect run as sequential cases of the poller's single leader-locked loop —
// so a trailing 60-minute range can never read a hole mid-window. Evidence
// sitting exactly at the 59-61 min boundary can age out between cycles;
// detectors using Lookback must tolerate that (thresholds, not exact counts).
const maxLookback = 60 * time.Minute

// Lookback returns w.End minus d, clamped to the raw-retention ceiling. Use
// this (never a hand-rolled subtraction) for any range longer than the cycle
// window, so a future config bump can't silently read into rolled-up rows.
func (w Window) Lookback(d time.Duration) time.Time {
	if d > maxLookback {
		d = maxLookback
	}
	return w.End.Add(-d)
}

// Detector produces detections over a window. Implementations must be read-only
// and bounded (LIMIT their result sets) — the engine runs them every cycle.
type Detector interface {
	Name() string
	Category() Category
	Detect(w Window) ([]Detection, error)
}

// Registry is the ordered set of detectors the engine runs each cycle. R3 ships
// the operational + policy detectors; R4 adds the security detectors (port scan,
// super spreader, data exfil, threat-intel, C2 beacon). See security.go.
func Registry() []Detector {
	return []Detector{
		cleartextDetector{},
		unexpectedEgressDetector{},
		samplingBackoffDetector{},
		capacityDetector{},
		portScanDetector{},
		superSpreaderDetector{},
		dataExfilDetector{},
		threatIntelDetector{},
		c2BeaconDetector{},
		// Tranche 4 Phase 1 (ddos.go, samplerate.go):
		ddosVolumetricDetector{},
		ddosPrefixDetector{},
		samplingRateChangeDetector{},
	}
}

// ToModel converts a Detection into the persistable models.FlowDetection,
// stamping the window and detection time and JSON-encoding the details map.
func (d Detection) ToModel(w Window, now time.Time) models.FlowDetection {
	details := ""
	if len(d.Details) > 0 {
		if b, err := json.Marshal(d.Details); err == nil {
			details = string(b)
		}
	}
	return models.FlowDetection{
		// Store UTC so the SQLite (test) string-time comparison in
		// GetRecentDetections (which queries `>= since.UTC()`) is consistent;
		// Postgres timestamptz is tz-correct either way.
		DetectedAt:  now.UTC(),
		WindowStart: w.Start.UTC(),
		WindowEnd:   w.End.UTC(),
		Detector:    d.Detector,
		Category:    string(d.Category),
		Severity:    d.Severity,
		DeviceID:    d.DeviceID,
		SrcAddr:     d.SrcAddr,
		DstAddr:     d.DstAddr,
		DstPort:     d.DstPort,
		Protocol:    d.Protocol,
		Score:       d.Score,
		Message:     d.Message,
		DedupKey:    d.DedupKey,
		Details:     details,
	}
}

// RunAll runs every detector in the Registry over the window and returns the
// findings as persistable models, stamped at `now`. A detector that errors is
// logged and skipped so one bad query can't sink the whole cycle.
func RunAll(w Window, now time.Time) []models.FlowDetection {
	var out []models.FlowDetection
	for _, det := range Registry() {
		found, err := det.Detect(w)
		if err != nil {
			log.Printf("flow-detect %s: %v", det.Name(), err)
			continue
		}
		validity := detectorValidity[det.Name()]
		for _, f := range found {
			// Stamp the declared evidence class so every persisted detection
			// self-documents what data it was judged on (T4-1).
			if validity != "" {
				if f.Details == nil {
					f.Details = map[string]any{}
				}
				f.Details["validity"] = string(validity)
			}
			out = append(out, f.ToModel(w, now))
		}
	}
	return out
}
