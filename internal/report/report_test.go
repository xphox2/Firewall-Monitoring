package report

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 0.5
}

// TestComputeTraffic verifies that traffic is derived from counter DELTAS, that
// totals telescope correctly, and that counter resets/wraps are clamped.
func TestComputeTraffic(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	// Use the real Postgres minute-bucket format (to_char 'YYYY-MM-DD HH24:MI',
	// NO seconds) so a parse-layout regression is caught here.
	mk := func(min int, in, out float64) database.InterfaceChartBucket {
		return database.InterfaceChartBucket{
			Bucket:   base.Add(time.Duration(min) * time.Minute).Format("2006-01-02 15:04"),
			InBytes:  in,
			OutBytes: out,
		}
	}
	// Cumulative counters. Totals: 0, 1e6, 3e6, then a RESET back to 1e6.
	buckets := []database.InterfaceChartBucket{
		mk(0, 0, 0),
		mk(1, 600000, 400000),   // total 1e6  → delta 1e6
		mk(2, 1800000, 1200000), // total 3e6  → delta 2e6
		mk(3, 600000, 400000),   // total 1e6  → delta negative → clamped 0
	}

	total, peak, avg, series, times := computeTraffic(buckets, 60)

	if !approx(total, 3e6) {
		t.Errorf("total = %.0f, want 3000000 (reset clamped)", total)
	}
	// Peak bucket transferred 2e6 bytes in 60s → 2e6*8/60 bps.
	if !approx(peak, 2e6*8/60) {
		t.Errorf("peak = %.0f, want %.0f", peak, 2e6*8/60)
	}
	// avg = total*8 / (60 * 3 windows)
	if !approx(avg, 3e6*8/180) {
		t.Errorf("avg = %.0f, want %.0f", avg, 3e6*8/180)
	}
	if len(series) != 3 || len(times) != 3 {
		t.Fatalf("series/times len = %d/%d, want 3/3", len(series), len(times))
	}
	if series[2] != 0 {
		t.Errorf("reset bucket throughput = %.0f, want 0", series[2])
	}
	// Bucket timestamps must parse — a zero time renders spikes as "Jan 1 00:00".
	if times[0].IsZero() {
		t.Error("bucket timestamp failed to parse (zero time) — check parseBucketTime layouts")
	}
}

func TestFormatters(t *testing.T) {
	t.Parallel()
	if got := formatBytes(3 * 1024 * 1024); got != "3.0 MB" {
		t.Errorf("formatBytes(3MiB) = %q, want 3.0 MB", got)
	}
	if got := formatThroughput(200000); got != "200.0 Kbps" {
		t.Errorf("formatThroughput(200000) = %q, want 200.0 Kbps", got)
	}
	if got := formatThroughput(0); got != "0 bps" {
		t.Errorf("formatThroughput(0) = %q", got)
	}
}

func TestDetectSpikesInSeries(t *testing.T) {
	t.Parallel()
	var vals []float64
	var times []time.Time
	base := time.Now()
	for i := 0; i < 20; i++ {
		vals = append(vals, 1000+float64(i%4)*80) // noisy baseline (real data has variance)
		times = append(times, base.Add(time.Duration(i)*time.Minute))
	}
	vals = append(vals, 50000) // obvious spike
	times = append(times, base.Add(20*time.Minute))

	spikes := detectSpikesInSeries(vals, times, 3.0, "wan1", 0)
	if len(spikes) == 0 {
		t.Fatal("expected a spike to be detected")
	}
	if spikes[len(spikes)-1].Interface != "wan1" {
		t.Errorf("spike interface = %q", spikes[len(spikes)-1].Interface)
	}
}

func TestGroupSpikes(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 5, 30, 2, 0, 0, 0, time.UTC)
	mk := func(dev, iface, sev string, minOff int) spikeItem {
		return spikeItem{device: dev, s: TrafficSpike{
			Interface: iface, Severity: sev, Value: 10e6,
			Timestamp: base.Add(time.Duration(minOff) * time.Minute),
		}}
	}
	items := []spikeItem{
		mk("fw-a", "wan1", "warning", 0),
		mk("fw-a", "wan1", "critical", 30),
		mk("fw-a", "wan1", "warning", 60),
		mk("fw-a", "lan", "warning", 5),
		mk("fw-b", "wan1", "warning", 10),
	}
	groups, more, total, crit, warn := groupSpikes(items, time.UTC, true, 8)

	if total != 5 || crit != 1 || warn != 4 {
		t.Errorf("totals = %d/%d/%d, want 5/1/4", total, crit, warn)
	}
	if len(groups) != 3 || more != 0 {
		t.Fatalf("groups = %d (more %d), want 3/0", len(groups), more)
	}
	// Critical group must sort first.
	if !groups[0].IsCritical || groups[0].Interface != "wan1" || groups[0].DeviceName != "fw-a" || groups[0].Count != 3 {
		t.Errorf("first group = %+v, want fw-a/wan1 count 3 critical", groups[0])
	}
	if groups[0].Window == "" {
		t.Error("expected a non-empty window label for the multi-event group")
	}

	// limit caps groups and reports the overflow.
	g2, more2, _, _, _ := groupSpikes(items, time.UTC, true, 2)
	if len(g2) != 2 || more2 != 1 {
		t.Errorf("capped = %d (more %d), want 2/1", len(g2), more2)
	}
}

// TestRenderReportHTML builds a model from synthetic device data (no DB) and
// confirms the report renders as a single self-contained HTML document with the
// expected executive sections and no image/CID references.
func TestRenderReportHTML(t *testing.T) {
	t.Parallel()
	devices := []models.Device{
		{Name: "fw-edge-01", IPAddress: "10.0.0.1", Status: "online"},
		{Name: "fw-edge-02", IPAddress: "10.0.0.2", Status: "offline"},
	}
	dd := []*DeviceReportData{
		{
			CPUAvg: 12, CPUMax: 40, MemAvg: 55, MemMax: 70, DiskUsage: 33,
			SessionCount: 1200, AlertCount: 1,
			Alerts:    []models.Alert{{Severity: "critical", Timestamp: time.Now()}},
			Talkers:   []IfaceTraffic{{Name: "wan1", TotalBytes: 412e9, PeakBps: 842e6, AvgBps: 100e6}},
			Sparkline: []float64{10, 50, 30, 90, 20},
			Spikes: []TrafficSpike{
				{Interface: "wan1", Value: 58e6, Mean: 5e5, Severity: "critical", Timestamp: time.Now().Add(-2 * time.Hour)},
				{Interface: "wan1", Value: 49e6, Mean: 2e6, Severity: "warning", Timestamp: time.Now().Add(-90 * time.Minute)},
			},
			UptimePct:         99.98,
			UptimeDaysTracked: 30,
		},
		nil,
	}

	m := BuildReportModel(devices, dd, "UTC", 24, "Daily")
	m.Version = "0.10.236"
	if m.OnlineDevices != 1 || m.OfflineDevices != 1 {
		t.Errorf("online/offline = %d/%d, want 1/1", m.OnlineDevices, m.OfflineDevices)
	}
	if m.CriticalAlerts != 1 {
		t.Errorf("critical alerts = %d, want 1", m.CriticalAlerts)
	}
	if len(m.TopTalkers) != 1 || m.TopTalkers[0].BarPct != 100 {
		t.Errorf("top talkers = %+v", m.TopTalkers)
	}
	// Two wan1 spikes on one device collapse to a single group, peak 58 Mbps.
	if len(m.SpikeGroups) != 1 || m.SpikeGroups[0].Count != 2 || !m.SpikeGroups[0].IsCritical {
		t.Errorf("spike groups = %+v", m.SpikeGroups)
	}
	if m.SpikeTotal != 2 || m.SpikeCritical != 1 || m.SpikeWarning != 1 {
		t.Errorf("spike totals = %d/%d/%d, want 2/1/1", m.SpikeTotal, m.SpikeCritical, m.SpikeWarning)
	}

	html, err := RenderReportHTML(m)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"Firewall Monitor", "Bandwidth", "Top Talkers", "Traffic Spikes", "fw-edge-01", "OFFLINE", "v0.10.236"} {
		if !strings.Contains(html, want) {
			t.Errorf("report HTML missing %q", want)
		}
	}
	if strings.Contains(html, "cid:") || strings.Contains(html, "<img") {
		t.Error("report HTML must not reference images / CID attachments")
	}
	if !strings.Contains(html, "<svg") {
		t.Error("expected web preview to contain SVG charts")
	}

	// Test IsEmail = true mode (Email version: no SVGs to avoid Gmail clipping)
	m.IsEmail = true
	for i := range m.Devices {
		m.Devices[i].IsEmail = true
	}
	htmlEmail, err := RenderReportHTML(m)
	if err != nil {
		t.Fatalf("render email: %v", err)
	}
	if strings.Contains(htmlEmail, "<svg") {
		t.Error("expected email report to contain no SVG charts (to prevent Gmail clipping)")
	}
	if !strings.Contains(htmlEmail, "Resource Trends") {
		t.Error("expected email report to contain Resource Trends text summary")
	}
}

func TestSVGCharts(t *testing.T) {
	t.Parallel()

	// 1. Test Alert Timeline SVG
	buckets := []AlertBucket{
		{Label: "12:00", Count: 5, Crit: true, Tooltip: "Time: 12:00\nAlerts: 5 (Critical)"},
		{Label: "13:00", Count: 2, Crit: false, Tooltip: "Time: 13:00\nAlerts: 2 (Warning)"},
	}
	alertSVG := RenderAlertTimelineSVG(buckets, ThemeByName(""))
	if !strings.Contains(string(alertSVG), "<svg") || !strings.Contains(string(alertSVG), "Critical") {
		t.Error("RenderAlertTimelineSVG did not produce valid SVG with data")
	}

	// 2. Test Throughput SVG
	card := DeviceCard{
		Name:           "fw-edge-01",
		SparklineRaw:   []float64{1000000, 5000000, 2000000},
		SparklineTimes: []time.Time{time.Now().Add(-10 * time.Minute), time.Now().Add(-5 * time.Minute), time.Now()},
	}
	tpSVG := RenderThroughputChart(card, "UTC", ThemeByName(""))
	if !strings.Contains(string(tpSVG), "<svg") || !strings.Contains(string(tpSVG), "5.0 Mbps") {
		t.Errorf("RenderThroughputChart failed, got: %s", tpSVG)
	}

	// 3. Test CPU/Mem SVG
	cardCPUMem := DeviceCard{
		Name:       "fw-edge-01",
		CPUHistory: []float64{10, 50, 90},
		MemHistory: []float64{40, 45, 50},
		SysTimes:   []time.Time{time.Now().Add(-10 * time.Minute), time.Now().Add(-5 * time.Minute), time.Now()},
	}
	cpuMemSVG := RenderCPUMemSVGChart(cardCPUMem, "UTC", ThemeByName(""))
	if !strings.Contains(string(cpuMemSVG), "<svg") || !strings.Contains(string(cpuMemSVG), "CPU Usage") {
		t.Errorf("RenderCPUMemSVGChart failed, got: %s", cpuMemSVG)
	}
}
