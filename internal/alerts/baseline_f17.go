package alerts

import (
	"math"
	"time"
)

// F17 adaptive baselining: per-device mean/stddev of the four system metrics
// over the trailing 24h, cached for 6h (mirroring the traffic-spike detector's
// refresh cadence). The cache has its own mutex and is REFRESHED OUTSIDE
// am.mu (ensureBaseline runs before the alert lock is taken), so the poller's
// alert path never holds the alert mutex across a DB query.

const (
	baselineWindow  = 24 // hours of history per baseline
	baselineRefresh = 6 * time.Hour
	baselineMinPts  = 12 // fewer samples than this = no baseline (fail static)
)

type metricBaseline struct {
	mean float64
	std  float64
	ok   bool
}

type deviceBaselines struct {
	at      time.Time
	metrics map[string]metricBaseline
}

// zscoreConfigured reports whether any loaded rule opted into zscore mode —
// the gate that keeps baseline DB reads off installs that never use F17. Covers
// BOTH policy AlertRules (policyCache.anyZScore) and metric Event Rules whose
// dampen_json opts into zscore (anyMetricZScoreRule, set in RefreshEventRules) —
// otherwise an event-rule-only zscore would never get baselines (Phase 4a).
func (am *AlertManager) zscoreConfigured() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return (am.policyCache.loaded && am.policyCache.anyZScore) || am.anyMetricZScoreRule
}

// ensureBaseline refreshes the device's baseline if stale. Called WITHOUT
// am.mu held (does a DB read). Cheap when fresh: one mutex check.
func (am *AlertManager) ensureBaseline(deviceID uint) {
	am.baselineMu.Lock()
	b, ok := am.baselines[deviceID]
	fresh := ok && time.Since(b.at) < baselineRefresh
	am.baselineMu.Unlock()
	if fresh || am.db == nil {
		return
	}

	hist, err := am.db.GetSystemStatusHistory(deviceID, baselineWindow)
	entry := deviceBaselines{at: time.Now(), metrics: map[string]metricBaseline{}}
	if err == nil && len(hist) >= baselineMinPts {
		series := map[string][]float64{
			"cpu_usage":     make([]float64, 0, len(hist)),
			"memory_usage":  make([]float64, 0, len(hist)),
			"disk_usage":    make([]float64, 0, len(hist)),
			"session_count": make([]float64, 0, len(hist)),
		}
		for i := range hist {
			series["cpu_usage"] = append(series["cpu_usage"], hist[i].CPUUsage)
			series["memory_usage"] = append(series["memory_usage"], hist[i].MemoryUsage)
			series["disk_usage"] = append(series["disk_usage"], hist[i].DiskUsage)
			series["session_count"] = append(series["session_count"], float64(hist[i].SessionCount))
		}
		for metric, vals := range series {
			mean, std := meanStd(vals)
			entry.metrics[metric] = metricBaseline{mean: mean, std: std, ok: true}
		}
	}
	// A failed/short read still caches (all-not-ok) so a device with no
	// history doesn't re-query the DB every poll cycle for 6 hours.
	am.baselineMu.Lock()
	am.baselines[deviceID] = entry
	am.baselineMu.Unlock()
}

// baselineFor returns the cached baseline for (device, metric). ok=false when
// no usable baseline exists — callers fall back to static thresholds.
func (am *AlertManager) baselineFor(deviceID uint, metric string) (mean, std float64, ok bool) {
	am.baselineMu.Lock()
	defer am.baselineMu.Unlock()
	if b, exists := am.baselines[deviceID]; exists {
		if m, has := b.metrics[metric]; has && m.ok {
			return m.mean, m.std, true
		}
	}
	return 0, 0, false
}

// zscoreFireAt computes the effective fire threshold for a resolved config:
// static mode returns Threshold unchanged; zscore mode returns
// max(Threshold, mean + K·σ) — the static value acts as a floor — falling
// back to plain Threshold when no baseline exists or the line is flat
// (σ≈0 would make ordinary noise alert).
func (am *AlertManager) zscoreFireAt(resolved ResolvedAlertConfig, deviceID uint, metric string) (fireAt float64, std float64, dynamic bool) {
	fireAt = resolved.Threshold
	if resolved.Mode != "zscore" {
		return fireAt, 0, false
	}
	mean, sd, ok := am.baselineFor(deviceID, metric)
	if !ok || sd < 1e-9 || math.IsNaN(sd) {
		return fireAt, 0, false
	}
	k := resolved.ZScoreK
	if k <= 0 {
		k = 3.0
	}
	dyn := mean + k*sd
	if dyn > fireAt {
		return dyn, sd, true
	}
	return fireAt, sd, false
}

func meanStd(vals []float64) (mean, std float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean = sum / float64(len(vals))
	var sq float64
	for _, v := range vals {
		d := v - mean
		sq += d * d
	}
	std = math.Sqrt(sq / float64(len(vals)))
	return mean, std
}
