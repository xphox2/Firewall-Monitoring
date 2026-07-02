package report

import (
	"fmt"
	"math"
)

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
