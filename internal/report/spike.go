package report

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// TrafficSpike represents a detected spike in traffic data. For report spike
// cards (v0.10.236) Value/Mean/StdDev are throughput in bits-per-second derived
// from counter deltas — NOT raw octet-counter values.
type TrafficSpike struct {
	Timestamp time.Time `json:"timestamp"`
	Interface string    `json:"interface"`
	Value     float64   `json:"value"`
	Mean      float64   `json:"mean"`
	StdDev    float64   `json:"stddev"`
	Severity  string    `json:"severity"` // "warning" or "critical"
}

// detectSpikesInSeries flags anomalies in a throughput (bps) series using a
// rolling-window standard deviation. values[i] is aligned with times[i].
//
// v0.10.236: this replaces the old DetectTrafficSpikes, which ran std-dev
// analysis directly on InterfaceChartBucket.InBytes+OutBytes — i.e. on a
// monotonically increasing SNMP octet counter. A cumulative counter trends
// strictly upward, so the latest sample is always far above the rolling mean,
// making the old detector fire constantly and report meaningless byte counts.
// The honest signal is the per-bucket throughput derived from counter deltas
// (see computeTraffic in data.go), which is what we analyze here.
func detectSpikesInSeries(values []float64, times []time.Time, stddevThreshold float64, ifName string) []TrafficSpike {
	if len(values) < 3 || stddevThreshold <= 0 {
		return nil
	}

	// Rolling window size: up to 1/4 of data points, min 3, max 60.
	windowSize := len(values) / 4
	if windowSize < 3 {
		windowSize = 3
	}
	if windowSize > 60 {
		windowSize = 60
	}

	var spikes []TrafficSpike
	for i := windowSize; i < len(values); i++ {
		// Compute mean and stddev over the window preceding this point
		window := values[i-windowSize : i]
		mean, stddev := meanStdDev(window)
		if stddev == 0 {
			continue
		}

		if values[i] > mean+stddevThreshold*stddev {
			severity := "warning"
			if values[i] > mean+stddevThreshold*2*stddev {
				severity = "critical"
			}
			var ts time.Time
			if i < len(times) {
				ts = times[i]
			}
			spikes = append(spikes, TrafficSpike{
				Timestamp: ts,
				Interface: ifName,
				Value:     values[i],
				Mean:      mean,
				StdDev:    stddev,
				Severity:  severity,
			})
		}
	}
	return spikes
}

// distinctDays counts the unique calendar days present in the timestamps.
func distinctDays(times []time.Time) int {
	seen := make(map[int]struct{})
	for _, t := range times {
		if t.IsZero() {
			continue
		}
		seen[t.Year()*1000+t.YearDay()] = struct{}{}
	}
	return len(seen)
}

// SeasonalProfile holds throughput (bps) samples binned by (weekday, hour) so a
// point can be judged against what's normal for that weekday AND time of day —
// e.g. a Monday-morning ramp vs. prior Mondays, not vs. the quiet weekend. This
// is what makes detection weekly-periodic and tolerant of timing drift.
type SeasonalProfile struct {
	byWeekdayHour map[int]map[int][]float64 // [weekday][hour] -> samples
	byHour        map[int][]float64         // [hour] -> samples (fallback)
}

// BuildSeasonalProfile bins a multi-day bps series by (weekday, hour).
func BuildSeasonalProfile(series []float64, times []time.Time) *SeasonalProfile {
	p := &SeasonalProfile{
		byWeekdayHour: make(map[int]map[int][]float64),
		byHour:        make(map[int][]float64),
	}
	for i, v := range series {
		if i >= len(times) || times[i].IsZero() {
			continue
		}
		wd, h := int(times[i].Weekday()), times[i].Hour()
		if p.byWeekdayHour[wd] == nil {
			p.byWeekdayHour[wd] = make(map[int][]float64)
		}
		p.byWeekdayHour[wd][h] = append(p.byWeekdayHour[wd][h], v)
		p.byHour[h] = append(p.byHour[h], v)
	}
	return p
}

// minSeasonalSamples is the fewest samples a slot needs before we'll judge
// against it (below this, fall back or report not-enough-history).
const minSeasonalSamples = 3

// neighborHours returns h and its ±1h neighbors (wrapping midnight). The ±1h
// window is the timing tolerance: a scheduled job that runs a little early or
// late still matches its own baseline instead of tripping a false spike.
func neighborHours(h int) [3]int {
	return [3]int{(h + 23) % 24, h, (h + 1) % 24}
}

// Band returns the expected throughput mean/stddev for time t, aggregating the
// ±1h neighborhood of t's (weekday, hour). It falls back to the same hours
// across all weekdays, then reports ok=false when there are too few samples.
func (p *SeasonalProfile) Band(t time.Time) (mean, std float64, ok bool) {
	if p == nil || t.IsZero() {
		return 0, 0, false
	}
	hrs := neighborHours(t.Hour())

	var samples []float64
	if hm := p.byWeekdayHour[int(t.Weekday())]; hm != nil {
		for _, hh := range hrs {
			samples = append(samples, hm[hh]...)
		}
	}
	if len(samples) >= minSeasonalSamples {
		mean, std = meanStdDev(samples)
		return mean, std, true
	}

	samples = samples[:0]
	for _, hh := range hrs {
		samples = append(samples, p.byHour[hh]...)
	}
	if len(samples) >= minSeasonalSamples {
		mean, std = meanStdDev(samples)
		return mean, std, true
	}
	return 0, 0, false
}

// IsAnomalous reports whether bps is above the expected band for t, and the
// severity. k is the std-dev multiplier (threshold). Returns false when there
// isn't enough history (Band not ok) or the band has zero spread.
func (p *SeasonalProfile) IsAnomalous(t time.Time, bps, k float64) (bool, string) {
	mean, std, ok := p.Band(t)
	if !ok || std == 0 {
		return false, ""
	}
	switch {
	case bps > mean+k*2*std:
		return true, "critical"
	case bps > mean+k*std:
		return true, "warning"
	default:
		return false, ""
	}
}

// detectSpikesTimeOfDay flags throughput in the most recent `hours` of the
// series that is anomalous *for its weekday and time of day*, learned from the
// preceding days in the same series. Recurring scheduled traffic (e.g. a nightly
// backup, even one that pauses on weekends or runs a little late) becomes part
// of its own (weekday, hour±1) baseline and is no longer flagged, while an
// unusual surge at a normally-quiet time still is.
//
// series/times should span several days/weeks at a consistent (hourly) cadence —
// the report passes the interface's multi-day chart. Points within the last
// `hours` are the report window under test; everything before is the baseline
// (the window itself is excluded so a surge can't normalize against itself).
// Falls back to the rolling-window detector when there isn't at least 3 days of
// prior history to form a stable norm.
func detectSpikesTimeOfDay(series []float64, times []time.Time, hours int, stddevThreshold float64, ifName string) []TrafficSpike {
	if stddevThreshold <= 0 || len(series) < 3 || len(times) != len(series) {
		return nil
	}

	maxT := times[len(times)-1]
	testStart := maxT.Add(-time.Duration(hours) * time.Hour)

	var priorVals, testVals []float64
	var priorTimes, testTimes []time.Time
	for i, v := range series {
		t := times[i]
		if t.IsZero() {
			continue
		}
		if t.Before(testStart) {
			priorVals = append(priorVals, v)
			priorTimes = append(priorTimes, t)
		} else {
			testVals = append(testVals, v)
			testTimes = append(testTimes, t)
		}
	}
	if len(testVals) == 0 {
		return nil
	}

	// Without enough prior history, fall back to the single-window detector on
	// the report window so spikes are still surfaced on fresh installs.
	if distinctDays(priorTimes) < 3 {
		return detectSpikesInSeries(testVals, testTimes, stddevThreshold, ifName)
	}

	profile := BuildSeasonalProfile(priorVals, priorTimes)
	var spikes []TrafficSpike
	for i, v := range testVals {
		anom, sev := profile.IsAnomalous(testTimes[i], v, stddevThreshold)
		if !anom {
			continue
		}
		mean, std, _ := profile.Band(testTimes[i])
		spikes = append(spikes, TrafficSpike{
			Timestamp: testTimes[i],
			Interface: ifName,
			Value:     v,
			Mean:      mean,
			StdDev:    std,
			Severity:  sev,
		})
	}
	return spikes
}

func meanStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	sumSq := 0.0
	for _, v := range values {
		d := v - mean
		sumSq += d * d
	}
	stddev := math.Sqrt(sumSq / float64(len(values)))
	return mean, stddev
}

// RollingStats tracks a circular buffer of traffic values per interface for real-time spike detection.
type RollingStats struct {
	mu       sync.RWMutex
	buffers  map[string]*circularBuffer // keyed by "deviceID_ifName"
	capacity int
}

type circularBuffer struct {
	data  []float64
	pos   int
	count int
}

// NewRollingStats creates a new RollingStats with the given buffer capacity.
func NewRollingStats(capacity int) *RollingStats {
	if capacity < 10 {
		capacity = 10
	}
	return &RollingStats{
		buffers:  make(map[string]*circularBuffer),
		capacity: capacity,
	}
}

// AddAndCheck adds a value to the rolling buffer and returns a spike if detected.
func (rs *RollingStats) AddAndCheck(deviceID uint, ifName string, inBytes, outBytes uint64, threshold float64) *TrafficSpike {
	key := fmt.Sprintf("%d_%s", deviceID, ifName)
	value := float64(inBytes + outBytes)

	rs.mu.Lock()
	defer rs.mu.Unlock()

	buf, ok := rs.buffers[key]
	if !ok {
		buf = &circularBuffer{data: make([]float64, rs.capacity)}
		rs.buffers[key] = buf
	}

	// Add value
	buf.data[buf.pos] = value
	buf.pos = (buf.pos + 1) % rs.capacity
	if buf.count < rs.capacity {
		buf.count++
	}

	// Need at least 10 samples before detecting
	if buf.count < 10 {
		return nil
	}

	// Compute stats over buffer (excluding current value)
	var vals []float64
	for i := 0; i < buf.count; i++ {
		idx := (buf.pos - 1 - i + rs.capacity) % rs.capacity
		if i > 0 { // skip the value we just inserted
			vals = append(vals, buf.data[idx])
		}
	}

	mean, stddev := meanStdDev(vals)
	if stddev == 0 {
		return nil
	}

	if value > mean+threshold*stddev {
		return &TrafficSpike{
			Timestamp: time.Now(),
			Interface: ifName,
			Value:     value,
			Mean:      mean,
			StdDev:    stddev,
			Severity:  "warning",
		}
	}
	return nil
}
