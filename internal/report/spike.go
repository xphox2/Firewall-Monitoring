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
