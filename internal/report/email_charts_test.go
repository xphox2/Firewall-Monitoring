package report

import (
	"bytes"
	"fmt"
	"image/png"
	"mime/quotedprintable"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// makeFleet builds n devices with rich per-device data (charts, talkers,
// alerts). Device 0 is offline; device 1 has the most alerts; the rest ramp
// CPUMax so the chart-slot prioritization is deterministic.
func makeFleet(n int) ([]models.Device, []*DeviceReportData) {
	now := time.Now()
	mkTimes := func(k int) []time.Time {
		ts := make([]time.Time, k)
		for i := range ts {
			ts[i] = now.Add(-time.Duration(k-i) * 5 * time.Minute)
		}
		return ts
	}
	devices := make([]models.Device, n)
	dd := make([]*DeviceReportData, n)
	for i := 0; i < n; i++ {
		status := "online"
		if i == 0 {
			status = "offline"
		}
		devices[i] = models.Device{Name: fmt.Sprintf("fw-%02d", i), IPAddress: fmt.Sprintf("10.0.0.%d", i+1), Status: status}
		alerts := []models.Alert{}
		if i == 1 {
			for j := 0; j < 5; j++ {
				alerts = append(alerts, models.Alert{Severity: "critical", Timestamp: now.Add(-time.Duration(j+1) * time.Hour)})
			}
		}
		dd[i] = &DeviceReportData{
			CPUAvg: 10, CPUMax: float64(20 + i*5), MemAvg: 30, MemMax: 50,
			DiskUsage: 40, SessionCount: 100 + i, AlertCount: len(alerts), Alerts: alerts,
			Talkers:        []IfaceTraffic{{Name: "wan1", TotalBytes: 4e9, PeakBps: 8e6, AvgBps: 1e6}},
			Sparkline:      []float64{1e6, 5e6, 3e6, 9e6},
			SparklineTimes: mkTimes(4),
			CPUHistory:     []float64{10, 50, 90, 30},
			MemHistory:     []float64{40, 45, 50, 55},
			SysTimes:       mkTimes(4),
			UptimePct:      99.9, UptimeDaysTracked: 30,
		}
	}
	return devices, dd
}

// TestPNGChartRenderers pins the themed PNG pipeline: decodable PNGs at the
// 2x render size, within the per-image budget, in both themes, with
// insufficient-data inputs skipping cleanly.
func TestPNGChartRenderers(t *testing.T) {
	t.Parallel()
	_, dd := makeFleet(2)
	card := DeviceCard{
		Name: "fw-00", Timezone: "UTC",
		CPUHistory: dd[0].CPUHistory, MemHistory: dd[0].MemHistory, SysTimes: dd[0].SysTimes,
	}
	buckets := []AlertBucket{
		{Label: "00:00", Count: 3, Crit: false},
		{Label: "01:00", Count: 7, Crit: true},
		{Label: "02:00", Count: 0},
	}
	for _, themeName := range []string{"light", "dark"} {
		th := ThemeByName(themeName)
		for name, render := range map[string]func() ([]byte, error){
			"cpumem":   func() ([]byte, error) { return RenderCPUMemPNG(card, th) },
			"timeline": func() ([]byte, error) { return RenderAlertTimelinePNG(buckets, th) },
			"history": func() ([]byte, error) {
				return RenderCPUMemHistoryPNG([]models.SystemStatus{
					{Timestamp: time.Now().Add(-time.Hour), CPUUsage: 50, MemoryUsage: 60},
					{Timestamp: time.Now(), CPUUsage: 70, MemoryUsage: 65},
				}, th)
			},
		} {
			data, err := render()
			if err != nil {
				t.Fatalf("%s/%s: %v", name, themeName, err)
			}
			if data == nil {
				t.Fatalf("%s/%s: nil PNG for drawable data", name, themeName)
			}
			img, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("%s/%s: not a decodable PNG: %v", name, themeName, err)
			}
			b := img.Bounds()
			if b.Dx() != pngChartWidth || b.Dy() != pngChartHeight {
				t.Errorf("%s/%s: size %dx%d, want %dx%d", name, themeName, b.Dx(), b.Dy(), pngChartWidth, pngChartHeight)
			}
			if len(data) > 80*1024 {
				t.Errorf("%s/%s: %d bytes exceeds 80KB per-image budget", name, themeName, len(data))
			}
			// Opaque theme background: the corner pixel must match ChartBG,
			// never transparent (the classic dark-mode disaster).
			_, _, _, a := img.At(b.Min.X, b.Min.Y).RGBA()
			if a != 0xffff {
				t.Errorf("%s/%s: background not opaque", name, themeName)
			}
		}
	}

	// Insufficient data skips cleanly (nil, nil) — caller falls back to tables.
	if d, err := RenderCPUMemPNG(DeviceCard{CPUHistory: []float64{1}, SysTimes: []time.Time{time.Now()}}, ThemeByName("")); d != nil || err != nil {
		t.Errorf("single-point cpumem should skip, got %d bytes err=%v", len(d), err)
	}
	if d, err := RenderAlertTimelinePNG(nil, ThemeByName("")); d != nil || err != nil {
		t.Errorf("empty timeline should skip, got %d bytes err=%v", len(d), err)
	}
	if d, err := RenderAlertTimelinePNG([]AlertBucket{{Label: "x", Count: 0}}, ThemeByName("")); d != nil || err != nil {
		t.Errorf("all-zero timeline should skip, got %d bytes err=%v", len(d), err)
	}
}

// TestBuildReportEmailCharts pins the email attachment contract: bounded
// themed PNGs with matching cid: anchors in the HTML, the 12-device cap with
// compact overflow rows, none of it leaking into the web render, and the
// QP-encoded HTML under the Gmail clip budget.
func TestBuildReportEmailCharts(t *testing.T) {
	t.Parallel()
	devices, dd := makeFleet(15)

	// Email render (collapsible=false).
	_, html, text, atts, err := BuildReportWithOps(devices, dd, "UTC", 24, "Daily", "0.11.118", false, nil, ThemeByName("dark"))
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) == 0 {
		t.Fatal("email render produced no chart attachments")
	}
	if len(atts) > 7 {
		t.Fatalf("attachment budget exceeded: %d > 7", len(atts))
	}
	seen := map[string]bool{}
	for _, att := range atts {
		if att.MIMEType != "image/png" {
			t.Errorf("attachment %s: MIME %q", att.ContentID, att.MIMEType)
		}
		if len(att.Data) > 80*1024 {
			t.Errorf("attachment %s: %d bytes exceeds 80KB", att.ContentID, len(att.Data))
		}
		if !strings.Contains(html, "cid:"+att.ContentID) {
			t.Errorf("attachment %s has no matching cid: anchor in the HTML", att.ContentID)
		}
		if seen[att.ContentID] {
			t.Errorf("duplicate ContentID %s", att.ContentID)
		}
		seen[att.ContentID] = true
	}
	// Fleet has alerts (device 1) → the timeline chart must ride along.
	if !seen["report_alerts"] {
		t.Error("fleet alert timeline PNG missing")
	}
	// Device chart slots: bounded, and priority-ordered — sections are
	// reordered offline → most alerts → highest CPU, so positions 0 and 1
	// (the offline device and the alert-heavy device) must hold chart slots.
	devCharts := 0
	for cidName := range seen {
		if strings.HasPrefix(cidName, "report_cpumem_") {
			devCharts++
		}
	}
	if devCharts == 0 || devCharts > emailDeviceChartSlots {
		t.Errorf("device chart count %d outside (0, %d]", devCharts, emailDeviceChartSlots)
	}
	if !seen["report_cpumem_0"] || !seen["report_cpumem_1"] {
		t.Errorf("top-priority positions (offline, most-alerts) must win chart slots; got %v", seen)
	}
	// The offline and alert-heavy devices must hold FULL sections (their
	// names render in devheads, not just compact rows) — fw-00 is offline,
	// fw-01 has 5 critical alerts.
	for _, name := range []string{"fw-00", "fw-01"} {
		if !strings.Contains(html, name) {
			t.Errorf("priority device %s missing from email", name)
		}
	}

	// Size-fit cap: overflow devices render as compact rows, and EVERY
	// device still appears in both HTML and plaintext.
	if !strings.Contains(html, "more devices") {
		t.Error("overflow eyebrow missing (15 rich devices can never all fit the budget)")
	}
	for i := 0; i < 15; i++ {
		name := fmt.Sprintf("fw-%02d", i)
		if !strings.Contains(html, name) {
			t.Errorf("device %s missing from email HTML (full section or compact row)", name)
		}
		if !strings.Contains(text, name) {
			t.Errorf("device %s missing from plaintext", name)
		}
	}

	// Gmail clip budget: QP-encoded HTML (exactly as SendHTMLEmail encodes
	// it) must stay under 92KB — the ~102KB clip threshold minus margin.
	// This must hold for ANY fleet because the fit loop shrinks the
	// full-section count until it does.
	var qp bytes.Buffer
	w := quotedprintable.NewWriter(&qp)
	if _, err := w.Write([]byte(html)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if qp.Len() > 92*1024 {
		t.Errorf("QP-encoded email HTML %d bytes exceeds the 92KB Gmail-clip budget", qp.Len())
	}

	// Web render (collapsible=true): SVG world — no attachments, no cid.
	_, webHTML, _, webAtts, err := BuildReportWithOps(devices, dd, "UTC", 24, "Daily", "0.11.118", true, nil, ThemeByName("dark"))
	if err != nil {
		t.Fatal(err)
	}
	if len(webAtts) != 0 {
		t.Errorf("web render produced %d attachments, want 0", len(webAtts))
	}
	if strings.Contains(webHTML, "cid:") || strings.Contains(webHTML, "<img") {
		t.Error("web render must stay image/CID-free")
	}
	if strings.Contains(webHTML, "more devices") {
		t.Error("web render must never cap devices")
	}
	if !strings.Contains(webHTML, "fw-14") {
		t.Error("web render missing device fw-14")
	}
}
