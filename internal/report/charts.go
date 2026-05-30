package report

import (
	"bytes"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// charts.go was trimmed in v0.10.236: the fleet report is now drawn entirely
// from email-safe HTML/CSS (see template_report.go), so the traffic / uptime /
// alert-trend PNG renderers were removed. go-chart survives only here, for the
// single CPU/Memory image embedded in critical-alert emails.

const (
	chartWidth  = 600
	chartHeight = 200
)

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
