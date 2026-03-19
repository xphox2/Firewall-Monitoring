package report

import (
	"bytes"
	"fmt"
	"math"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

const (
	chartWidth  = 600
	chartHeight = 200
)

// RenderTrafficChart renders a time series chart of InBytes (blue) and OutBytes (green).
func RenderTrafficChart(data []database.InterfaceChartBucket, title string) ([]byte, error) {
	if len(data) == 0 {
		return renderEmptyChart(title)
	}

	times := make([]time.Time, len(data))
	inVals := make([]float64, len(data))
	outVals := make([]float64, len(data))

	// Auto-scale Y axis
	maxVal := 0.0
	for i, d := range data {
		t, _ := time.Parse(time.RFC3339, d.Bucket)
		if t.IsZero() {
			t, _ = time.Parse("2006-01-02T15:04:05", d.Bucket)
		}
		if t.IsZero() {
			t, _ = time.Parse("2006-01-02 15:04:05", d.Bucket)
		}
		times[i] = t
		inVals[i] = d.InBytes
		outVals[i] = d.OutBytes
		if d.InBytes > maxVal {
			maxVal = d.InBytes
		}
		if d.OutBytes > maxVal {
			maxVal = d.OutBytes
		}
	}

	suffix, divisor := autoScale(maxVal)

	for i := range inVals {
		inVals[i] /= divisor
		outVals[i] /= divisor
	}

	graph := chart.Chart{
		Title:  title,
		Width:  chartWidth,
		Height: chartHeight,
		TitleStyle: chart.Style{
			FontSize: 10,
		},
		Background: chart.Style{
			Padding: chart.Box{Top: 20, Left: 10, Right: 10, Bottom: 20},
		},
		XAxis: chart.XAxis{
			Style:          chart.Style{FontSize: 8},
			ValueFormatter: chart.TimeMinuteValueFormatter,
		},
		YAxis: chart.YAxis{
			Name:  suffix,
			Style: chart.Style{FontSize: 8},
		},
		Series: []chart.Series{
			chart.TimeSeries{
				Name:    "In",
				XValues: times,
				YValues: inVals,
				Style: chart.Style{
					StrokeColor: drawing.Color{R: 66, G: 133, B: 244, A: 255},
					StrokeWidth: 1.5,
				},
			},
			chart.TimeSeries{
				Name:    "Out",
				XValues: times,
				YValues: outVals,
				Style: chart.Style{
					StrokeColor: drawing.Color{R: 52, G: 168, B: 83, A: 255},
					StrokeWidth: 1.5,
				},
			},
		},
	}
	graph.Elements = []chart.Renderable{chart.LegendLeft(&graph)}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, fmt.Errorf("render traffic chart: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderCPUMemChart renders a dual-series chart of CPU% and Memory%.
func RenderCPUMemChart(history []models.SystemStatus, title string) ([]byte, error) {
	if len(history) == 0 {
		return renderEmptyChart(title)
	}

	times := make([]time.Time, len(history))
	cpuVals := make([]float64, len(history))
	memVals := make([]float64, len(history))

	for i, h := range history {
		times[i] = h.Timestamp
		cpuVals[i] = h.CPUUsage
		memVals[i] = h.MemoryUsage
	}

	graph := chart.Chart{
		Title:  title,
		Width:  chartWidth,
		Height: chartHeight,
		TitleStyle: chart.Style{
			FontSize: 10,
		},
		Background: chart.Style{
			Padding: chart.Box{Top: 20, Left: 10, Right: 10, Bottom: 20},
		},
		XAxis: chart.XAxis{
			Style:          chart.Style{FontSize: 8},
			ValueFormatter: chart.TimeMinuteValueFormatter,
		},
		YAxis: chart.YAxis{
			Name:  "%",
			Style: chart.Style{FontSize: 8},
			Range: &chart.ContinuousRange{Min: 0, Max: 100},
		},
		Series: []chart.Series{
			chart.TimeSeries{
				Name:    "CPU",
				XValues: times,
				YValues: cpuVals,
				Style: chart.Style{
					StrokeColor: drawing.Color{R: 234, G: 67, B: 53, A: 255},
					StrokeWidth: 1.5,
				},
			},
			chart.TimeSeries{
				Name:    "Memory",
				XValues: times,
				YValues: memVals,
				Style: chart.Style{
					StrokeColor: drawing.Color{R: 251, G: 188, B: 4, A: 255},
					StrokeWidth: 1.5,
				},
			},
		},
	}
	graph.Elements = []chart.Renderable{chart.LegendLeft(&graph)}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, fmt.Errorf("render cpu/mem chart: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderUptimeMeter renders a horizontal bar: green=uptime, red=downtime, grey=untracked.
func RenderUptimeMeter(percent float64, daysTracked, maxDays int) ([]byte, error) {
	trackedFraction := float64(daysTracked) / float64(maxDays)
	if trackedFraction > 1 {
		trackedFraction = 1
	}
	uptimeFraction := (percent / 100) * trackedFraction
	downtimeFraction := trackedFraction - uptimeFraction
	untrackedFraction := 1.0 - trackedFraction

	values := []chart.Value{}
	if uptimeFraction > 0 {
		values = append(values, chart.Value{
			Label: fmt.Sprintf("%.4f%%", percent),
			Value: uptimeFraction,
			Style: chart.Style{
				FillColor:   drawing.Color{R: 52, G: 168, B: 83, A: 255},
				FontSize:    9,
				StrokeWidth: 0,
			},
		})
	}
	if downtimeFraction > 0.001 {
		values = append(values, chart.Value{
			Label: "down",
			Value: downtimeFraction,
			Style: chart.Style{
				FillColor:   drawing.Color{R: 234, G: 67, B: 53, A: 255},
				FontSize:    9,
				StrokeWidth: 0,
			},
		})
	}
	if untrackedFraction > 0.01 {
		values = append(values, chart.Value{
			Label: "n/a",
			Value: untrackedFraction,
			Style: chart.Style{
				FillColor:   drawing.Color{R: 189, G: 189, B: 189, A: 255},
				FontSize:    9,
				StrokeWidth: 0,
			},
		})
	}

	if len(values) == 0 {
		values = append(values, chart.Value{
			Label: "no data",
			Value: 1,
			Style: chart.Style{
				FillColor: drawing.Color{R: 189, G: 189, B: 189, A: 255},
				FontSize:  9,
			},
		})
	}

	graph := chart.BarChart{
		Title:  fmt.Sprintf("Uptime: %.4f%% (%d days)", percent, daysTracked),
		Width:  chartWidth,
		Height: 80,
		TitleStyle: chart.Style{
			FontSize: 9,
		},
		BarWidth: chartWidth - 80,
		Bars:     values,
	}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, fmt.Errorf("render uptime meter: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderAlertTrend renders a bar chart of alert counts over time buckets.
func RenderAlertTrend(alerts []models.Alert, hours int) ([]byte, error) {
	if len(alerts) == 0 {
		return renderEmptyChart("Alerts")
	}

	// Bucket alerts by time
	bucketDuration := time.Hour
	if hours > 48 {
		bucketDuration = 24 * time.Hour
	}

	now := time.Now()
	start := now.Add(-time.Duration(hours) * time.Hour)
	numBuckets := int(now.Sub(start)/bucketDuration) + 1
	if numBuckets > 100 {
		numBuckets = 100
	}

	counts := make(map[int]int)
	for _, a := range alerts {
		idx := int(a.Timestamp.Sub(start) / bucketDuration)
		if idx >= 0 && idx < numBuckets {
			counts[idx]++
		}
	}

	values := make([]chart.Value, 0, numBuckets)
	for i := 0; i < numBuckets; i++ {
		label := ""
		if i%6 == 0 {
			t := start.Add(time.Duration(i) * bucketDuration)
			if bucketDuration >= 24*time.Hour {
				label = t.Format("Jan 2")
			} else {
				label = t.Format("15:04")
			}
		}
		values = append(values, chart.Value{
			Label: label,
			Value: float64(counts[i]),
			Style: chart.Style{
				FillColor:   drawing.Color{R: 66, G: 133, B: 244, A: 255},
				StrokeWidth: 0,
			},
		})
	}

	graph := chart.BarChart{
		Title:  "Alert Trend",
		Width:  chartWidth,
		Height: chartHeight,
		TitleStyle: chart.Style{
			FontSize: 10,
		},
		Bars: values,
	}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, fmt.Errorf("render alert trend: %w", err)
	}
	return buf.Bytes(), nil
}

func renderEmptyChart(title string) ([]byte, error) {
	graph := chart.Chart{
		Title:  title + " (no data)",
		Width:  chartWidth,
		Height: chartHeight,
		TitleStyle: chart.Style{
			FontSize: 10,
		},
		Background: chart.Style{
			FillColor: drawing.Color{R: 255, G: 255, B: 255, A: 255},
		},
		Series: []chart.Series{
			chart.ContinuousSeries{
				XValues: []float64{0, 1},
				YValues: []float64{0, 0},
			},
		},
	}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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
