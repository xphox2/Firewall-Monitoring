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

// Window is the time range and DB handle a detector runs against.
type Window struct {
	Start time.Time
	End   time.Time
	DB    *gorm.DB
}

// Seconds is the window length in seconds (>=1), used for rate math.
func (w Window) Seconds() float64 {
	s := w.End.Sub(w.Start).Seconds()
	if s < 1 {
		return 1
	}
	return s
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
		for _, f := range found {
			out = append(out, f.ToModel(w, now))
		}
	}
	return out
}
