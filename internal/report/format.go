package report

import (
	"fmt"
	"math"
)

// autoScale returns a unit suffix and divisor for the given magnitude.
// Moved out of charts.go (v0.10.236) so the HTML report model builder can
// format byte values without pulling in the go-chart dependency.
func autoScale(maxVal float64) (string, float64) {
	if maxVal == 0 {
		return "Bytes", 1
	}
	abs := math.Abs(maxVal)
	switch {
	case abs >= 1e12:
		return "TB", 1e12
	case abs >= 1e9:
		return "GB", 1e9
	case abs >= 1e6:
		return "MB", 1e6
	case abs >= 1e3:
		return "KB", 1e3
	default:
		return "Bytes", 1
	}
}

// formatBytes renders a byte count as a human-readable string (e.g. "412.3 GB").
func formatBytes(n float64) string {
	if n <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := int(math.Floor(math.Log(n) / math.Log(1024)))
	if i < 0 {
		i = 0
	}
	if i >= len(units) {
		i = len(units) - 1
	}
	val := n / math.Pow(1024, float64(i))
	if i == 0 {
		return fmt.Sprintf("%.0f %s", val, units[i])
	}
	return fmt.Sprintf("%.1f %s", val, units[i])
}

// formatThroughput renders a bits-per-second value as a human-readable rate
// (e.g. "842.0 Mbps"). Uses base-1000 (network convention).
func formatThroughput(bps float64) string {
	if bps <= 0 {
		return "0 bps"
	}
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := int(math.Floor(math.Log(bps) / math.Log(1000)))
	if i < 0 {
		i = 0
	}
	if i >= len(units) {
		i = len(units) - 1
	}
	val := bps / math.Pow(1000, float64(i))
	return fmt.Sprintf("%.1f %s", val, units[i])
}
