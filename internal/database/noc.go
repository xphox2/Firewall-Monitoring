package database

import (
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// NOCSnapshot is a point-in-time view of recent flow activity for the real-time
// NOC dashboard. It is computed over a short trailing window (so throughput is
// "now", not an hourly average) and is cheap enough to recompute every few
// seconds by the broadcaster. Bytes are already sampling-scaled at ingest, so
// SUM(bytes)*8/window is an estimated bits/sec.
type NOCSnapshot struct {
	GeneratedAt   time.Time `json:"generated_at"`
	WindowSeconds int       `json:"window_seconds"`

	TotalFlows    int64   `json:"total_flows"`
	TotalBytes    uint64  `json:"total_bytes"`
	BitsPerSecond float64 `json:"bits_per_second"`
	UniqueSources int64   `json:"unique_sources"`
	UniqueDests   int64   `json:"unique_dests"`
	ThreatFlows   int64   `json:"threat_flows"` // flows in window touching a known-bad endpoint

	TopSources      []KeyCount `json:"top_sources"`
	TopDestinations []KeyCount `json:"top_destinations"`
	ByCategory      []KeyCount `json:"by_category"`  // Key = classify.Category id (string)
	ByDirection     []KeyCount `json:"by_direction"` // Key = classify.Dir* id (string)
	TopCountries    []KeyCount `json:"top_countries"`

	Detections []models.FlowDetection `json:"detections"` // recent, most-severe first

	ProbesOnline      int   `json:"probes_online"`
	ProbesOffline     int   `json:"probes_offline"`
	DevicesOnline     int   `json:"devices_online"`
	DevicesOffline    int   `json:"devices_offline"`
	ActiveThreatIntel int64 `json:"active_threat_intel"`
}

// GetNOCSnapshot computes a NOCSnapshot over the trailing window. All flow
// aggregates are bounded (top-N) and run against the raw flow_samples indexes.
// Errors on the optional sub-queries are tolerated (the field stays zero) so a
// single failing aggregate doesn't blank the whole dashboard.
func (d *Database) GetNOCSnapshot(window time.Duration) (*NOCSnapshot, error) {
	if window <= 0 {
		window = 5 * time.Minute
	}
	secs := window.Seconds()
	cutoff := time.Now().Add(-window)
	snap := &NOCSnapshot{
		GeneratedAt:   time.Now().UTC(),
		WindowSeconds: int(secs),
	}

	base := func() *gorm.DB {
		return d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff)
	}

	var agg struct {
		Flows  int64
		Bytes  uint64
		Srcs   int64
		Dsts   int64
		Threat int64
	}
	base().Select("COUNT(*) as flows, COALESCE(SUM(bytes),0) as bytes, COUNT(DISTINCT src_addr) as srcs, COUNT(DISTINCT dst_addr) as dsts, COALESCE(SUM(CASE WHEN threat_flag <> 0 THEN 1 ELSE 0 END),0) as threat").
		Scan(&agg)
	snap.TotalFlows = agg.Flows
	snap.TotalBytes = agg.Bytes
	snap.UniqueSources = agg.Srcs
	snap.UniqueDests = agg.Dsts
	snap.ThreatFlows = agg.Threat
	if secs > 0 {
		snap.BitsPerSecond = float64(agg.Bytes) * 8 / secs
	}

	snap.TopSources = topAddrsByBytes(base, "src_addr", 8)
	snap.TopDestinations = topAddrsByBytes(base, "dst_addr", 8)
	snap.ByCategory = groupCountKey(base, "app_category", 8)
	snap.ByDirection = groupCountKey(base, "direction", 6)

	// Top destination countries (geo enrichment) — skip blanks.
	{
		type row struct {
			C     string
			Total int64
		}
		var rows []row
		base().Where("dst_country <> ''").
			Select("dst_country as c, SUM(bytes) as total").
			Group("dst_country").Order("total DESC").Limit(8).Scan(&rows)
		snap.TopCountries = make([]KeyCount, 0, len(rows))
		for _, r := range rows {
			snap.TopCountries = append(snap.TopCountries, KeyCount{Key: r.C, Count: r.Total})
		}
	}

	// Recent detections (last 15 min), most severe + newest first.
	if dets, err := d.GetRecentDetections(time.Now().Add(-15*time.Minute), 15, false); err == nil {
		snap.Detections = dets
	}

	// Probe + device fleet status.
	if probes, err := d.GetAllProbes(); err == nil {
		for _, p := range probes {
			if p.Status == "online" {
				snap.ProbesOnline++
			} else {
				snap.ProbesOffline++
			}
		}
	}
	if devs, err := d.GetDeviceStatuses(); err == nil {
		for _, dev := range devs {
			if s, _ := dev["status"].(string); s == "online" || s == "up" {
				snap.DevicesOnline++
			} else {
				snap.DevicesOffline++
			}
		}
	}
	snap.ActiveThreatIntel, _ = d.CountActiveThreatIntel()

	return snap, nil
}

// groupCountKey returns the top-N values of a numeric column by flow count, with
// the numeric value rendered as the KeyCount.Key (the client maps id→label).
func groupCountKey(base func() *gorm.DB, col string, limit int) []KeyCount {
	type row struct {
		K     int64
		Total int64
	}
	var rows []row
	base().Select(col + " as k, COUNT(*) as total").Group(col).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: itoaInt64(r.K), Count: r.Total})
	}
	return out
}

func itoaInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	pos := len(b)
	for v > 0 {
		pos--
		b[pos] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
