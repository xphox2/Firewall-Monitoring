package report

import (
	"bytes"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// png_charts.go — themed PNG renderers for EMAIL bodies (v0.11.118). The web
// preview keeps its inline SVGs (svg_charts.go); email clients get real PNGs
// inlined via CID because SVG support in mail clients is effectively zero.
//
// Sizing: rendered at 2x (1104×400) and displayed at width="552" for retina
// sharpness inside the 600px sheet. Backgrounds are ALWAYS opaque theme
// canvas — a transparent PNG on a client-recolored surface is the classic
// dark-mode disaster.

const (
	pngChartWidth  = 1104
	pngChartHeight = 400
	// PNGDisplayWidth is the HTML width attr matching the 2x render.
	PNGDisplayWidth = 552
)

// hexColor converts "#rrggbb" to a drawing.Color (opaque). Invalid input
// yields an opaque mid-grey rather than an error — theme tokens are
// compile-time constants covered by tests, so this never fires in practice.
func hexColor(hex string) drawing.Color {
	var r, g, b uint8
	if _, err := fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b); err != nil {
		return drawing.Color{R: 128, G: 128, B: 128, A: 255}
	}
	return drawing.Color{R: r, G: g, B: b, A: 255}
}

// pngAxisStyle returns the shared themed axis style.
func pngAxisStyle(th ReportTheme) chart.Style {
	return chart.Style{
		FontSize:    14, // 2x render → reads as 7pt at display size ×2 = crisp 14px
		FontColor:   hexColor(th.ChartAxis),
		StrokeColor: hexColor(th.ChartGrid),
	}
}

func pngGridStyle(th ReportTheme) chart.Style {
	return chart.Style{
		StrokeColor: hexColor(th.ChartGrid),
		StrokeWidth: 1.0,
	}
}

// RenderCPUMemPNG renders a device's CPU/Memory history as a themed dual-line
// PNG. Returns (nil, nil) when there is not enough data to draw a line —
// callers skip the chart (the Resource Trends table always carries the
// numbers regardless).
func RenderCPUMemPNG(card DeviceCard, th ReportTheme) ([]byte, error) {
	if len(card.CPUHistory) < 2 || len(card.SysTimes) < 2 || len(card.CPUHistory) != len(card.SysTimes) {
		return nil, nil
	}
	series := []chart.Series{
		chart.TimeSeries{
			Name:    "CPU %",
			XValues: card.SysTimes,
			YValues: card.CPUHistory,
			Style:   chart.Style{StrokeColor: hexColor(th.SeriesCPU), StrokeWidth: 2.5},
		},
	}
	if len(card.MemHistory) == len(card.SysTimes) {
		series = append(series, chart.TimeSeries{
			Name:    "Memory %",
			XValues: card.SysTimes,
			YValues: card.MemHistory,
			Style:   chart.Style{StrokeColor: hexColor(th.SeriesMem), StrokeWidth: 2.5},
		})
	}
	graph := chart.Chart{
		Width:      pngChartWidth,
		Height:     pngChartHeight,
		Background: chart.Style{FillColor: hexColor(th.ChartBG), Padding: chart.Box{Top: 24, Left: 16, Right: 24, Bottom: 16}},
		Canvas:     chart.Style{FillColor: hexColor(th.ChartBG)},
		XAxis: chart.XAxis{
			Style:          pngAxisStyle(th),
			TickStyle:      chart.Style{FontColor: hexColor(th.ChartAxis)},
			ValueFormatter: pngTimeFormatter(card.Timezone),
			GridMajorStyle: pngGridStyle(th),
		},
		YAxis: chart.YAxis{
			Style:          pngAxisStyle(th),
			TickStyle:      chart.Style{FontColor: hexColor(th.ChartAxis)},
			Range:          &chart.ContinuousRange{Min: 0, Max: 100},
			GridMajorStyle: pngGridStyle(th),
		},
		Series: series,
	}
	graph.Elements = []chart.Renderable{chart.Legend(&graph, chart.Style{
		FillColor:   hexColor(th.ChartBG),
		FontColor:   hexColor(th.ChartAxis),
		StrokeColor: hexColor(th.ChartGrid),
		FontSize:    14,
	})}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, fmt.Errorf("render cpu/mem png: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderAlertTimelinePNG renders the fleet alert timeline as a themed bar
// chart PNG. Returns (nil, nil) when there is nothing to draw.
func RenderAlertTimelinePNG(buckets []AlertBucket, th ReportTheme) ([]byte, error) {
	if len(buckets) == 0 {
		return nil, nil
	}
	total, maxCount := 0, 0
	bars := make([]chart.Value, 0, len(buckets))
	// Label every bucket only when they fit; otherwise every 4th (24 hourly
	// buckets at 1104px would collide).
	labelEvery := 1
	if len(buckets) > 12 {
		labelEvery = 4
	}
	for i, b := range buckets {
		total += b.Count
		if b.Count > maxCount {
			maxCount = b.Count
		}
		color := th.Warn
		if b.Crit {
			color = th.Crit
		}
		label := ""
		if i%labelEvery == 0 {
			label = b.Label
		}
		bars = append(bars, chart.Value{
			Value: float64(b.Count),
			Label: label,
			Style: chart.Style{FillColor: hexColor(color), StrokeColor: hexColor(color)},
		})
	}
	if total == 0 {
		return nil, nil
	}
	graph := chart.BarChart{
		Width:      pngChartWidth,
		Height:     pngChartHeight,
		Background: chart.Style{FillColor: hexColor(th.ChartBG), Padding: chart.Box{Top: 24, Left: 16, Right: 24, Bottom: 16}},
		Canvas:     chart.Style{FillColor: hexColor(th.ChartBG)},
		XAxis:      pngAxisStyle(th),
		YAxis: chart.YAxis{
			Style:     pngAxisStyle(th),
			TickStyle: chart.Style{FontColor: hexColor(th.ChartAxis)},
			// Explicit range: go-chart errors on a zero-span value range,
			// which every-bucket-equal-and-nonzero data would otherwise hit.
			Range:          &chart.ContinuousRange{Min: 0, Max: float64(maxCount)},
			GridMajorStyle: pngGridStyle(th),
		},
		BarWidth:   pngChartWidth / (len(buckets) + 6),
		BarSpacing: 6,
		Bars:       bars,
	}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, fmt.Errorf("render alert timeline png: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderCPUMemHistoryPNG renders raw SystemStatus history (the critical-alert
// path) through the same themed pipeline.
func RenderCPUMemHistoryPNG(history []models.SystemStatus, th ReportTheme) ([]byte, error) {
	if len(history) < 2 {
		return nil, nil
	}
	card := DeviceCard{
		SysTimes:   make([]time.Time, len(history)),
		CPUHistory: make([]float64, len(history)),
		MemHistory: make([]float64, len(history)),
		Timezone:   "UTC",
	}
	for i, h := range history {
		card.SysTimes[i] = h.Timestamp
		card.CPUHistory[i] = h.CPUUsage
		card.MemHistory[i] = h.MemoryUsage
	}
	return RenderCPUMemPNG(card, th)
}

// pngTimeFormatter formats X-axis ticks in the report timezone.
func pngTimeFormatter(tz string) chart.ValueFormatter {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	return func(v interface{}) string {
		switch t := v.(type) {
		case time.Time:
			return t.In(loc).Format("15:04")
		case float64:
			return time.Unix(0, int64(t)).In(loc).Format("15:04")
		}
		return ""
	}
}
