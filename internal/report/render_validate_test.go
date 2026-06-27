package report

import (
	"encoding/xml"
	"regexp"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
	"golang.org/x/net/html"
)

// buildRichModel assembles a report model that exercises every section and
// every SVG generator: fleet KPIs, top talkers, fleet + per-device spike
// groups, the alert timeline, and per-device CPU/Mem + throughput charts.
// One device carries nil data (renders the bare offline card path).
func buildRichModel(t *testing.T, hours int) ReportModel {
	t.Helper()
	now := time.Now()
	mkTimes := func(n int) []time.Time {
		ts := make([]time.Time, n)
		for i := range ts {
			ts[i] = now.Add(-time.Duration(n-i) * 5 * time.Minute)
		}
		return ts
	}
	devices := []models.Device{
		{Name: "fw-edge-01", IPAddress: "10.0.0.1", Status: "online"},
		{Name: "fw-core (b)", IPAddress: "10.0.0.2", Status: "online"}, // name w/ space+paren → exercises safeID
		{Name: "fw-edge-03", IPAddress: "10.0.0.3", Status: "offline"},
	}
	dd := []*DeviceReportData{
		{
			CPUAvg: 12, CPUMax: 97.6, MemAvg: 55, MemMax: 70, DiskUsage: 33,
			SessionCount: 1200, AlertCount: 3,
			Alerts: []models.Alert{
				{Severity: "critical", Timestamp: now.Add(-2 * time.Hour)},
				{Severity: "warning", Timestamp: now.Add(-90 * time.Minute)},
				{Severity: "warning", Timestamp: now.Add(-30 * time.Minute)},
			},
			Talkers: []IfaceTraffic{
				{Name: "wan1", TotalBytes: 412e9, PeakBps: 842e6, AvgBps: 100e6},
				{Name: "lan", TotalBytes: 88e9, PeakBps: 120e6, AvgBps: 20e6},
			},
			Sparkline:      []float64{10e6, 50e6, 30e6, 90e6, 20e6, 75e6},
			SparklineTimes: mkTimes(6),
			CPUHistory:     []float64{10, 50, 90, 30, 97.6, 44},
			MemHistory:     []float64{40, 45, 50, 55, 60, 52},
			SysTimes:       mkTimes(6),
			Spikes: []TrafficSpike{
				{Interface: "wan1", Value: 58e6, Mean: 5e5, Severity: "critical", Timestamp: now.Add(-2 * time.Hour)},
				{Interface: "wan1", Value: 49e6, Mean: 2e6, Severity: "warning", Timestamp: now.Add(-90 * time.Minute)},
			},
			UptimePct: 99.98, UptimeDaysTracked: 30,
		},
		{
			CPUAvg: 5, CPUMax: 20, MemAvg: 30, MemMax: 40, DiskUsage: 10,
			SessionCount: 50, AlertCount: 0,
			Talkers:        []IfaceTraffic{{Name: "port1", TotalBytes: 10e9, PeakBps: 5e6, AvgBps: 1e6}},
			Sparkline:      []float64{1e6, 2e6, 1.5e6},
			SparklineTimes: mkTimes(3),
			CPUHistory:     []float64{4, 6, 5},
			MemHistory:     []float64{28, 31, 30},
			SysTimes:       mkTimes(3),
			UptimePct:      100, UptimeDaysTracked: 30,
		},
		nil, // offline, no data → bare card
	}
	period := "Daily"
	if hours > 48 {
		period = "Weekly"
	}
	m := BuildReportModel(devices, dd, "America/New_York", hours, period)
	m.Version = "0.10.408"
	return m
}

var svgFragmentRe = regexp.MustCompile(`(?s)<svg\b.*?</svg>`)

// TestReportHTMLWellFormed renders the report in both the email (flat) and
// admin-preview (collapsible) layouts and asserts the output is well-formed:
// it parses cleanly as an HTML5 document, every embedded SVG fragment is
// valid XML, structural tag pairs balance, and there are no Go-template
// rendering artifacts or image/CID references.
func TestReportHTMLWellFormed(t *testing.T) {
	t.Parallel()

	for _, hours := range []int{24, 168} { // hourly + daily alert bucketing
		for _, collapsible := range []bool{false, true} {
			m := buildRichModel(t, hours)
			m.Collapsible = collapsible

			out, err := RenderReportHTML(m)
			if err != nil {
				t.Fatalf("render (hours=%d collapsible=%v): %v", hours, collapsible, err)
			}

			label := func(s string) string {
				return s + " [hours=" + itoa(hours) + " collapsible=" + btoa(collapsible) + "]"
			}

			// 1. No Go-template rendering artifacts. Each of these is a distinct
			// failure mode: a nil field, a missing map key, a mis-typed printf,
			// or html/template's "unsafe content" sanitizer sentinel.
			for _, bad := range []string{"<no value>", "ZgotmplZ", "%!", "<nil>"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s: contains template artifact %q", label("render"), bad)
				}
			}

			// 2. Parses cleanly as an HTML5 document.
			if _, err := html.Parse(strings.NewReader(out)); err != nil {
				t.Errorf("%s: html.Parse failed: %v", label("parse"), err)
			}

			// 3. Document skeleton present exactly once.
			for _, want := range []string{"<!DOCTYPE html>", "<html", "<head", "<body", "</html>"} {
				if strings.Count(out, want) < 1 {
					t.Errorf("%s: missing %q", label("skeleton"), want)
				}
			}

			// 4. Structural tag pairs balance.
			assertBalanced(t, out, label, "table")
			assertBalanced(t, out, label, "svg")
			assertBalanced(t, out, label, "defs")
			assertBalanced(t, out, label, "style")
			assertBalanced(t, out, label, "g")
			assertBalanced(t, out, label, "details")

			// 5. Every embedded SVG fragment is well-formed XML (strict) if not IsEmail.
			svgs := svgFragmentRe.FindAllString(out, -1)
			if m.IsEmail {
				if len(svgs) > 0 {
					t.Errorf("%s: expected no <svg> charts in email report, found %d", label("svg"), len(svgs))
				}
			} else {
				if len(svgs) == 0 {
					t.Errorf("%s: expected at least one <svg> chart, found none", label("svg"))
				}
				for i, frag := range svgs {
					if err := xml.Unmarshal([]byte(frag), new(struct {
						XMLName xml.Name
					})); err != nil {
						t.Errorf("%s: SVG fragment #%d is not well-formed XML: %v", label("svg-xml"), i, err)
					}
				}
			}

			// 6. Email-safe: no images, no CID attachment references.
			if strings.Contains(out, "<img") || strings.Contains(out, "cid:") {
				t.Errorf("%s: report must be image/CID-free", label("email-safe"))
			}

			// 7. Collapsible toggles the <details> wrapper exactly.
			hasDetails := strings.Contains(out, "<details")
			if hasDetails != collapsible {
				t.Errorf("%s: <details> present=%v, want %v", label("collapsible"), hasDetails, collapsible)
			}

			// 8. Expected executive sections + data points rendered.
			for _, want := range []string{
				"Firewall Monitor", "Bandwidth &amp; Traffic", "Top Talkers",
				"Traffic Spikes", "Alert Activity", "Device Detail",
				"fw-edge-01", "ONLINE", "OFFLINE", "v0.10.408",
				"CPU &amp; Memory History",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("%s: missing section/datum %q", label("sections"), want)
				}
			}
		}
	}
}

// assertBalanced verifies the count of <tag ...> openers equals </tag> closers.
// Opener match is "<tag" followed by a space or ">" so e.g. "svg" doesn't match
// a hypothetical "<svgother". Self-closing variants are not used in this template.
func assertBalanced(t *testing.T, out string, label func(string) string, tag string) {
	t.Helper()
	openRe := regexp.MustCompile(`(?i)<` + tag + `[\s>]`)
	closeRe := regexp.MustCompile(`(?i)</` + tag + `>`)
	o := len(openRe.FindAllString(out, -1))
	c := len(closeRe.FindAllString(out, -1))
	if o != c {
		t.Errorf("%s: <%s> openers=%d, </%s> closers=%d (unbalanced)", label("balance"), tag, o, tag, c)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

func btoa(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
