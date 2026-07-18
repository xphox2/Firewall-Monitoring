package report

import (
	"strings"
	"testing"
)

// TestSVGCharts_NoNaNOnSinglePoint_L8 pins the 2026-07-01 audit L8 fix: a
// 1-point series must render the "no statistics" placeholder, not an SVG path
// with NaN coordinates (which browsers drop, breaking the report/PDF).
func TestSVGCharts_NoNaNOnSinglePoint_L8(t *testing.T) {
	one := DeviceCard{Name: "dev1", SparklineRaw: []float64{42}, CPUHistory: []float64{50}, MemHistory: []float64{60}}

	tp := string(RenderThroughputChart(one, "UTC", ThemeByName("")))
	if strings.Contains(tp, "NaN") {
		t.Errorf("throughput chart emitted NaN on a 1-point series: %.120s", tp)
	}
	if !strings.Contains(tp, "No throughput statistics") {
		t.Error("throughput chart should show the placeholder for a 1-point series")
	}

	cm := string(RenderCPUMemSVGChart(one, "UTC", ThemeByName("")))
	if strings.Contains(cm, "NaN") {
		t.Errorf("cpu/mem chart emitted NaN on a 1-point series: %.120s", cm)
	}

	// Control: a 2-point series renders a real chart (no placeholder, no NaN).
	two := DeviceCard{Name: "dev2", SparklineRaw: []float64{10, 20}}
	tp2 := string(RenderThroughputChart(two, "UTC", ThemeByName("")))
	if strings.Contains(tp2, "NaN") || strings.Contains(tp2, "No throughput statistics") {
		t.Errorf("2-point throughput chart should render normally: %.120s", tp2)
	}
}
